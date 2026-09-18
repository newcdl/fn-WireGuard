// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"fnwg/internal/model"
	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
)

// 连接的内部地址网段与监听端口在全部连接内必须唯一：
// 网段重叠会让两条连接上的设备互相抢地址，端口重复会让后创建的连接无法监听。
// 下面这组常量用于按连接序号错开默认值，从源头规避冲突。
const (
	defaultMTU        = 1420
	defaultListenPort = 51820
	defaultAddrOctet  = 10 // 默认内部网段 10.10.0.0/24 的第三个八位组
	autoAllocTries    = 64 // 自动分配时最多顺延尝试的位数
)

// ifaceIndexRe 匹配 wgN 形式的连接名，用于推导默认地址与端口的偏移量。
var ifaceIndexRe = regexp.MustCompile(`^wg(\d+)$`)

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
	// AllowLAN 控制「允许设备访问家里内网」。
	// 新建连接时为 nil 表示采用默认值（开启）；编辑时为 nil 表示保持原值。
	AllowLAN *bool `json:"allow_lan"`
	// IsolatePeers 控制「设备间隔离」。
	// 新建连接时为 nil 表示采用默认值（**关闭**）；编辑时为 nil 表示保持原值。
	//
	// 与 AllowLAN 的默认值取向相反是有意的：隔离是「新增限制」，
	// 默认打开会在用户没做任何操作的情况下切断已有的设备互访。
	IsolatePeers *bool `json:"isolate_peers"`
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
		// 新建连接默认开启内网访问：设备连回家就是为了访问 NAS 与家里其它设备，
		// 不开的话表现是「能连上 NAS，但访问不了家里的机器」。
		AllowLAN: in.AllowLAN == nil || *in.AllowLAN,
		// 设备间隔离默认关闭：它是新增限制，默认打开会静默改变已有设备的可达性。
		IsolatePeers: in.IsolatePeers != nil && *in.IsolatePeers,
	}
	if err := s.applyInterfaceDefaults(ctx, it, 0); err != nil {
		return nil, err
	}
	if err := s.validateInterface(ctx, it, 0); err != nil {
		return nil, err
	}
	s.snapshotBefore(ctx, "iface.create", "新建连接「"+it.Name+"」")
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
	if in.AllowLAN != nil {
		it.AllowLAN = *in.AllowLAN
	}
	if in.IsolatePeers != nil {
		it.IsolatePeers = *in.IsolatePeers
	}
	// 私钥仅在显式传入时覆盖，避免前端表单未携带该字段导致密钥丢失
	if in.PrivateKey != "" {
		if !wgkey.Validate(in.PrivateKey) {
			return nil, fmt.Errorf("本机密钥格式不正确，请检查是否完整复制")
		}
		it.PrivateKey = in.PrivateKey
	}
	if err := s.applyInterfaceDefaults(ctx, it, id); err != nil {
		return nil, err
	}
	if err := s.validateInterface(ctx, it, id); err != nil {
		return nil, err
	}
	s.snapshotBefore(ctx, "iface.update", "修改连接「"+it.Name+"」")
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
	s.snapshotBefore(ctx, "iface.delete", "删除连接「"+it.Name+"」")
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
	note := "停用连接「" + it.Name + "」"
	if enabled {
		note = "启用连接「" + it.Name + "」"
	}
	s.snapshotBefore(ctx, "iface.toggle", note)
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return err
	}
	s.audit(ctx, a, "iface.toggle", "interface", fmt.Sprint(id), "", fmt.Sprint(enabled), "ok", "")
	return s.reconcile(ctx)
}

// SetLanAccess 一键切换「允许设备访问家里内网」。
//
// 单独开一个入口是为了让用户不必进编辑表单就能开启/关闭；
// 打开后本应用会为该连接的隧道网段做源地址改写（NAT），
// 让连进来的设备能够访问 NAS 所在局域网中的其它设备。
func (s *Service) SetLanAccess(ctx context.Context, id int64, enabled bool, a Actor) (*model.Interface, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return nil, err
	}
	if it.AllowLAN == enabled {
		it.PrivateKey = ""
		return it, nil
	}
	it.AllowLAN = enabled
	note := "关闭内网访问「" + it.Name + "」"
	if enabled {
		note = "开启内网访问「" + it.Name + "」"
	}
	s.snapshotBefore(ctx, "iface.lan_access", note)
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return nil, err
	}
	action := "iface.lan_access_off"
	if enabled {
		action = "iface.lan_access_on"
	}
	s.audit(ctx, a, action, "interface", fmt.Sprint(id), "", fmt.Sprint(enabled), "ok", "")
	if err := s.reconcile(ctx); err != nil {
		return nil, err
	}
	it.PrivateKey = ""
	return it, nil
}

// SetPeerIsolation 一键切换「设备间隔离」。
//
// 与 SetLanAccess 同构：不必进编辑表单就能开关。打开后这条连接里的设备
// 互相访问的流量会在 NAS 上被丢弃，但它们访问 NAS 与家里内网不受影响。
func (s *Service) SetPeerIsolation(ctx context.Context, id int64, enabled bool, a Actor) (*model.Interface, error) {
	it, err := s.Store.GetInterface(ctx, id)
	if err != nil {
		return nil, err
	}
	if it.IsolatePeers == enabled {
		it.PrivateKey = ""
		return it, nil
	}
	it.IsolatePeers = enabled
	note := "关闭设备间隔离「" + it.Name + "」"
	if enabled {
		note = "开启设备间隔离「" + it.Name + "」"
	}
	s.snapshotBefore(ctx, "iface.isolate", note)
	if err := s.Store.UpdateInterface(ctx, it); err != nil {
		return nil, err
	}
	action := "iface.isolate_off"
	if enabled {
		action = "iface.isolate_on"
	}
	s.audit(ctx, a, action, "interface", fmt.Sprint(id), "", fmt.Sprint(enabled), "ok", "")
	if err := s.reconcile(ctx); err != nil {
		return nil, err
	}
	it.PrivateKey = ""
	return it, nil
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
	s.snapshotBefore(ctx, "iface.rotate_key", "轮换连接密钥「"+it.Name+"」")
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

// applyInterfaceDefaults 归一化字段并补齐缺省值。
//
// 内部地址与监听端口留空时，按连接序号自动分配一个不与其它连接冲突的取值：
// wg0 → 10.10.0.1/24 + 51820，wg1 → 10.11.0.1/24 + 51821，以此类推；
// 若序号位已被占用则顺延寻找空位，避免「新建第二条连接就必须手工改端口和网段」。
func (s *Service) applyInterfaceDefaults(ctx context.Context, it *model.Interface, selfID int64) error {
	it.Addresses = wgconf.MergeCIDRs(it.Addresses)
	it.DNS = wgconf.MergeCIDRs(it.DNS)
	if it.MTU <= 0 {
		it.MTU = defaultMTU
	}
	if it.DNSMode == "" {
		it.DNSMode = "client"
	}
	// 安全底线：默认不管理本机路由。历史值 auto 一并降级为 off。
	if it.RouteTable == "" || it.RouteTable == "auto" {
		it.RouteTable = model.RouteTableOff
	}
	if it.ListenPort > 0 && len(it.Addresses) > 0 {
		return nil // 两项都由用户指定，无需自动分配
	}
	others, err := s.otherInterfaces(ctx, selfID)
	if err != nil {
		return err
	}
	start := defaultIndexFor(it.Name)
	if it.ListenPort <= 0 {
		it.ListenPort = pickFreePort(others, start)
	}
	if len(it.Addresses) == 0 {
		it.Addresses = []string{pickFreeAddr(others, start)}
	}
	return nil
}

// defaultIndexFor 从连接名推导自动分配序号：wg0 → 0、wg12 → 12。
// 非 wgN 命名的连接从 0 号位开始，由顺延逻辑寻找空位。
func defaultIndexFor(name string) int {
	m := ifaceIndexRe.FindStringSubmatch(name)
	if m == nil {
		return 0
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// defaultInterfaceAddr 按序号给出默认内部地址：wg0 → 10.10.0.1/24、wg1 → 10.11.0.1/24。
func defaultInterfaceAddr(idx int) string {
	if idx < 0 {
		idx = 0
	}
	if idx > 240 { // 10.10.0.0/24 ~ 10.250.0.0/24
		idx = 240
	}
	return fmt.Sprintf("10.%d.0.1/24", defaultAddrOctet+idx)
}

// defaultInterfacePort 按序号给出默认监听端口：wg0 → 51820、wg1 → 51821。
func defaultInterfacePort(idx int) int {
	if idx < 0 {
		idx = 0
	}
	if p := defaultListenPort + idx; p <= 65535 {
		return p
	}
	return 65535
}

// pickFreePort 从序号对应的默认端口开始顺延，返回第一个未被占用的端口。
func pickFreePort(others []model.Interface, start int) int {
	for i := 0; i < autoAllocTries; i++ {
		if p := defaultInterfacePort(start + i); !portUsedBy(others, p) {
			return p
		}
	}
	return defaultInterfacePort(start)
}

// pickFreeAddr 从序号对应的默认网段开始顺延，返回第一个不与已有连接重叠的网段。
func pickFreeAddr(others []model.Interface, start int) string {
	for i := 0; i < autoAllocTries; i++ {
		if a := defaultInterfaceAddr(start + i); !addrOverlapsAny(others, a) {
			return a
		}
	}
	return defaultInterfaceAddr(start)
}

// otherInterfaces 返回除 selfID 之外的全部连接，用于跨连接冲突检查与空位查找。
func (s *Service) otherInterfaces(ctx context.Context, selfID int64) ([]model.Interface, error) {
	list, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	if selfID <= 0 {
		return list, nil
	}
	out := make([]model.Interface, 0, len(list))
	for i := range list {
		if list[i].ID != selfID {
			out = append(out, list[i])
		}
	}
	return out, nil
}

// portUsedBy 判断端口是否已被其它连接占用（0 表示交给内核随机分配，不算冲突）。
func portUsedBy(others []model.Interface, port int) bool {
	if port <= 0 {
		return false
	}
	for i := range others {
		if others[i].ListenPort == port {
			return true
		}
	}
	return false
}

// addrOverlapsAny 判断网段是否与其它连接的内部地址存在重叠。
func addrOverlapsAny(others []model.Interface, cidr string) bool {
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	for i := range others {
		for _, o := range others[i].Addresses {
			if _, on, err := net.ParseCIDR(o); err == nil && cidrOverlap(n, on) {
				return true
			}
		}
	}
	return false
}

// cidrOverlap 判断两个网段是否有交集（不同协议族之间永远不重叠）。
func cidrOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
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
	// 跨连接校验：名称、监听端口与内部地址网段在全部连接内都必须唯一。
	// 提前在这里拦下，避免把冲突留到内核层才以晦涩的错误暴露出来。
	others, err := s.otherInterfaces(ctx, selfID)
	if err != nil {
		return err
	}
	if err := checkInterfaceConflicts(it, others); err != nil {
		return err
	}

	// 内核侧冲突：系统上已存在、但本应用不认的 WireGuard 网卡
	// （典型是早期版本卸载残留）会占住同名网卡与 UDP 端口。
	// 同样提前拦下并给出可操作的提示；取不到自检报告（如代理未运行）时跳过这段检查，
	// 不因为读不到信息就阻断创建。
	if rep, err := s.Core.InspectNetwork(ctx); err == nil {
		for _, fi := range rep.ForeignInterfaces {
			switch {
			case fi.Name == it.Name:
				return fmt.Errorf("系统上已存在名为 %s 的 WireGuard 网卡，但它不是本应用创建的"+
					"（可能是历史残留，也可能是其它工具在用）。请改用其他名称，"+
					"或先到「系统维护 → 疑似残留网卡」中确认并清理它", fi.Name)
			case it.ListenPort > 0 && fi.ListenPort == it.ListenPort:
				return fmt.Errorf("服务端口 %d 已被系统上不是本应用创建的网卡 %s 占用，请更换端口"+
					"（该网卡可能是历史残留，可在「系统维护 → 疑似残留网卡」中清理）",
					it.ListenPort, fi.Name)
			}
		}
	}
	return nil
}

// checkInterfaceConflicts 校验名称、监听端口与内部地址网段是否与其它连接冲突。
func checkInterfaceConflicts(it *model.Interface, others []model.Interface) error {
	for i := range others {
		if others[i].Name == it.Name {
			return fmt.Errorf("连接名称「%s」已经被使用了，请换一个名称", it.Name)
		}
	}
	for i := range others {
		if it.ListenPort > 0 && others[i].ListenPort == it.ListenPort {
			return fmt.Errorf("端口 %d 已被连接 %s 使用，请更换", it.ListenPort, others[i].Name)
		}
	}
	for _, a := range it.Addresses {
		_, an, err := net.ParseCIDR(a)
		if err != nil {
			continue // 格式问题已在字段校验中报出
		}
		for i := range others {
			for _, o := range others[i].Addresses {
				_, on, err := net.ParseCIDR(o)
				if err != nil {
					continue // 历史脏数据不阻断本次校验
				}
				if cidrOverlap(an, on) {
					return fmt.Errorf("内部地址网段 %s 与连接 %s 的 %s 重叠，请更换（例如 %s）",
						a, others[i].Name, o, pickFreeAddr(others, defaultIndexFor(it.Name)))
				}
			}
		}
	}
	return nil
}

func (s *Service) nextInterfaceName(ctx context.Context) (string, error) {
	used, err := s.Store.InterfaceNames(ctx)
	if err != nil {
		return "", err
	}
	// 内核里存在、但本应用不认的网卡名（历史残留等）也要避开：
	// 否则自动命名给出的名字会因为「拒绝接管他人网卡」而无法下发，
	// 表现为「自动创建失败，但手工换个名字就好了」。
	if rep, err := s.Core.InspectNetwork(ctx); err == nil {
		for _, fi := range rep.ForeignInterfaces {
			used[fi.Name] = true
		}
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
