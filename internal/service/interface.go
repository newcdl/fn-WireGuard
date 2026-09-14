package service

import (
	"context"
	"fmt"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/store"
	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
)

// ListInterfaces 返回全部接口（默认不回传私钥）。
func (s *Service) ListInterfaces(ctx context.Context) ([]model.Interface, error) {
	list, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	s.Cache.EnrichInterfaces(list)
	for i := range list {
		list[i].PrivateKey = ""
	}
	return list, nil
}

// GetInterface 返回单个接口。
func (s *Service) GetInterface(ctx context.Context, id int64) (*model.Interface, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return nil, err
	}
	list := []model.Interface{*it}
	s.Cache.EnrichInterfaces(list)
	it.PrivateKey = ""
	return it, nil
}

// CreateInterfaceInput 是创建接口的入参。
type CreateInterfaceInput struct {
	Name       string   `json:"name"`
	ListenPort int      `json:"listen_port"`
	MTU        int      `json:"mtu"`
	FWMark     int      `json:"fwmark"`
	Addresses  []string `json:"addresses"`
	DNS        []string `json:"dns"`
	DNSMode    string   `json:"dns_mode"`
	RouteTable string   `json:"route_table"`
	PostUp     string   `json:"post_up"`
	PostDown   string   `json:"post_down"`
	Enabled    bool     `json:"enabled"`
	Autostart  bool     `json:"autostart"`
	// PrivateKey 仅在导入已有配置时使用；为空表示自动生成。
	PrivateKey string `json:"private_key"`
}

// CreateInterface 创建接口并立即下发。
func (s *Service) CreateInterface(ctx context.Context, in CreateInterfaceInput, a Actor) (*model.Interface, error) {
	if strings.TrimSpace(in.Name) == "" {
		name, err := s.nextInterfaceName(ctx)
		if err != nil {
			return nil, err
		}
		in.Name = name
	}
	in.Name = strings.TrimSpace(in.Name)

	priv := strings.TrimSpace(in.PrivateKey)
	var pub string
	var err error
	if priv != "" {
		if !wgkey.Validate(priv) {
			return nil, fmt.Errorf("导入的本机密钥格式不正确，请检查是否完整复制")
		}
		if pub, err = wgkey.PublicKey(priv); err != nil {
			return nil, err
		}
	} else if priv, pub, err = wgkey.Generate(); err != nil {
		return nil, err
	}
	it := &model.Interface{
		Name:       in.Name,
		UUID:       newUUID(),
		PrivateKey: priv,
		ListenPort: in.ListenPort,
		FWMark:     in.FWMark,
		MTU:        in.MTU,
		Addresses:  in.Addresses,
		DNS:        in.DNS,
		DNSMode:    in.DNSMode,
		RouteTable: in.RouteTable,
		PostUp:     in.PostUp,
		PostDown:   in.PostDown,
		Enabled:    in.Enabled,
		Autostart:  in.Autostart,
	}
	s.applyInterfaceDefaults(it)
	if err := s.validateInterface(ctx, it, 0); err != nil {
		return nil, err
	}
	if err := s.Store.CreateInterface(ctx, it); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "iface.create", "interface", fmt.Sprint(it.ID), "", it.Name, "ok", "")
	if err := s.reconcile(ctx); err != nil {
		s.audit(ctx, a, "iface.create", "interface", fmt.Sprint(it.ID), "", it.Name, "error", err.Error())
	}
	it.PublicKey = pub
	it.PrivateKey = priv // 仅创建时回显一次，便于用户留存
	return it, nil
}

// UpdateInterface 更新接口。私钥字段为空时保留原值。
func (s *Service) UpdateInterface(ctx context.Context, id int64, in CreateInterfaceInput, a Actor) (*model.Interface, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return nil, err
	}
	before := it.Name
	if in.Name != "" {
		it.Name = strings.TrimSpace(in.Name)
	}
	it.ListenPort = in.ListenPort
	it.FWMark = in.FWMark
	it.MTU = in.MTU
	it.Addresses = in.Addresses
	it.DNS = in.DNS
	it.DNSMode = in.DNSMode
	it.RouteTable = in.RouteTable
	it.PostUp = in.PostUp
	it.PostDown = in.PostDown
	it.Enabled = in.Enabled
	it.Autostart = in.Autostart
	// 私钥仅在显式传入时覆盖，避免前端表单未携带该字段导致密钥丢失
	if in.PrivateKey != "" {
		if !wgkey.Validate(in.PrivateKey) {
			return nil, fmt.Errorf("本机密钥格式不正确，请检查是否完整复制")
		}
		it.PrivateKey = in.PrivateKey
	}
	s.applyInterfaceDefaults(it)
	if err := s.validateInterface(ctx, it, id); err != nil {
		return nil, err
	}
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "iface.update", "interface", fmt.Sprint(id), before, it.Name, "ok", "")
	_ = s.reconcile(ctx)
	it.PrivateKey = ""
	return it, nil
}

// DeleteInterface 删除接口。
func (s *Service) DeleteInterface(ctx context.Context, id int64, a Actor) error {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Store.DeleteInterface(ctx, id); err != nil {
		return err
	}
	// 先让代理直接删除 link，避免等待下一轮收敛
	if err := s.Core.DeleteInterface(ctx, it.Name); err != nil {
		s.Log.Warn("删除内核接口失败", "name", it.Name, "err", err)
	}
	s.audit(ctx, a, "iface.delete", "interface", fmt.Sprint(id), it.Name, "", "ok", "")
	_ = s.reconcile(ctx)
	return nil
}

// ToggleInterface 启用/停用接口（停用会从内核移除）。
func (s *Service) ToggleInterface(ctx context.Context, id int64, enabled bool, a Actor) error {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return err
	}
	it.Enabled = enabled
	if enabled {
		it.Autostart = true
	}
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return err
	}
	s.audit(ctx, a, "iface.toggle", "interface", fmt.Sprint(id), "", fmt.Sprint(enabled), "ok", "")
	return s.reconcile(ctx)
}

// RevealPrivateKey 在二次鉴权后回显接口私钥，并记录审计。
func (s *Service) RevealPrivateKey(ctx context.Context, id int64, a Actor) (string, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return "", err
	}
	s.audit(ctx, a, "iface.reveal_key", "interface", fmt.Sprint(id), "", "", "ok", "查看接口私钥")
	return it.PrivateKey, nil
}

// RegenerateInterfaceKey 轮换接口密钥对。
func (s *Service) RegenerateInterfaceKey(ctx context.Context, id int64, a Actor) (string, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return "", err
	}
	priv, pub, err := wgkey.Generate()
	if err != nil {
		return "", err
	}
	it.PrivateKey = priv
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return "", err
	}
	s.audit(ctx, a, "iface.rotate_key", "interface", fmt.Sprint(id), "", pub, "ok", "轮换接口密钥")
	_ = s.reconcile(ctx)
	return pub, nil
}

// InterfaceConf 返回服务端 wg-quick 配置文本。
func (s *Service) InterfaceConf(ctx context.Context, id int64) (string, string, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return "", "", err
	}
	peers, err := s.Store.ListPeers(ctx, id)
	if err != nil {
		return "", "", err
	}
	return it.Name, wgconf.RenderServer(it, peers), nil
}

func (s *Service) applyInterfaceDefaults(it *model.Interface) {
	it.Addresses = wgconf.MergeCIDRs(it.Addresses)
	it.DNS = wgconf.MergeCIDRs(it.DNS)
	if it.MTU <= 0 {
		it.MTU = 1420
	}
	if it.ListenPort <= 0 {
		it.ListenPort = 51820
	}
	if it.DNSMode == "" {
		it.DNSMode = "client"
	}
	// 安全底线：默认不管理本机路由。历史值 auto 一并降级为 off。
	if it.RouteTable == "" || it.RouteTable == "auto" {
		it.RouteTable = model.RouteTableOff
	}
	if len(it.Addresses) == 0 {
		it.Addresses = []string{"10.10.0.1/24"}
	}
}

func (s *Service) validateInterface(ctx context.Context, it *model.Interface, selfID int64) error {
	if !ifaceNameRe.MatchString(it.Name) {
		return fmt.Errorf("连接名称「%s」不符合要求：请以字母开头，只使用小写字母、数字、短横线或下划线，长度 2-15 个字符（例如 wg0）", it.Name)
	}
	if err := validatePort(it.ListenPort); err != nil {
		return err
	}
	if it.MTU < 500 || it.MTU > 65535 {
		return fmt.Errorf("数据包大小上限需要在 500 到 65535 之间（推荐 1420）")
	}
	if err := validateCIDRList("内部地址", it.Addresses); err != nil {
		return err
	}
	if err := validateIPList("域名解析服务器", it.DNS); err != nil {
		return err
	}
	switch it.DNSMode {
	case "client", "host", "off":
	default:
		return fmt.Errorf("「域名解析方式」取值不正确，请选择：仅下发给设备 / NAS 也一起使用 / 不参与")
	}
	switch it.RouteTable {
	case model.RouteTableOff, model.RouteTableClient:
	default:
		return fmt.Errorf("「本机访问路线管理」取值不正确，请选择：不管理（推荐）或 客户端模式")
	}
	if other, err := s.Store.GetInterfaceByName(ctx, it.Name); err == nil && other.ID != selfID {
		return fmt.Errorf("连接名称「%s」已经被使用了，请换一个名称", it.Name)
	} else if err != nil && err != store.ErrNotFound {
		return err
	}
	return nil
}

func (s *Service) nextInterfaceName(ctx context.Context) (string, error) {
	used, err := s.Store.InterfaceNames(ctx)
	if err != nil {
		return "", err
	}
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("wg%d", i)
		if !used[name] {
			return name, nil
		}
	}
	return "", fmt.Errorf("连接数量已达上限（最多 100 条），请先删除不再使用的连接")
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}
