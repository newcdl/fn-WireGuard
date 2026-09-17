package service

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/wgback"
	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
)

// ListPeers 返回节点列表（interfaceID<=0 表示全部）。敏感字段默认不下发。
func (s *Service) ListPeers(ctx context.Context, interfaceID int64) ([]model.Peer, error) {
	peers, err := s.Store.ListPeers(ctx, interfaceID)
	if err != nil {
		return nil, err
	}
	s.Cache.EnrichPeers(peers)
	s.markConfigStale(ctx, peers)
	for i := range peers {
		peers[i].PresharedKey = ""
		peers[i].ClientPrivateKey = ""
	}
	return peers, nil
}

// GetPeer 返回单个节点。
func (s *Service) GetPeer(ctx context.Context, id int64) (*model.Peer, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	list := []model.Peer{*p}
	s.Cache.EnrichPeers(list)
	s.markConfigStale(ctx, list)
	*p = list[0]
	p.PresharedKey = ""
	p.ClientPrivateKey = ""
	return p, nil
}

// PeerInput 是节点新增/编辑入参。
type PeerInput struct {
	InterfaceID      int64      `json:"interface_id"`
	Name             string     `json:"name"`
	PublicKey        string     `json:"public_key"`
	PresharedKey     string     `json:"preshared_key"`
	ClientPrivateKey string     `json:"client_private_key"`
	RouteMode        string     `json:"route_mode"`
	ClientAllowedIPs []string   `json:"client_allowed_ips"`
	EndpointHost     string     `json:"endpoint_host"`
	EndpointPort     int        `json:"endpoint_port"`
	AllowedIPs       []string   `json:"allowed_ips"`
	Keepalive        int        `json:"persistent_keepalive"`
	GroupTag         string     `json:"group_tag"`
	Remark           string     `json:"remark"`
	QuotaRx          int64      `json:"quota_rx"`
	QuotaTx          int64      `json:"quota_tx"`
	ExpireAt         *time.Time `json:"expire_at"`
	Enabled          bool       `json:"enabled"`
	// GenerateKeys 为 true 时自动生成密钥对并托管私钥。
	GenerateKeys bool `json:"generate_keys"`
	// GeneratePSK 为 true 时生成预共享密钥。
	GeneratePSK bool `json:"generate_psk"`
	// AutoAddress 为 true 时自动分配隧道地址。
	AutoAddress bool `json:"auto_address"`
}

// CreatePeer 新增节点。
func (s *Service) CreatePeer(ctx context.Context, in PeerInput, a Actor) (*model.Peer, error) {
	p, err := s.createPeer(ctx, in, a)
	if err != nil {
		return nil, err
	}
	_ = s.reconcile(ctx)
	return p, nil
}

// createPeer 落库一台设备，但**不触发收敛**。
//
// 单台创建走 CreatePeer（落库后立即收敛）。批量导入则逐条调用本函数、
// 最后统一收敛一次：否则 100 台设备会触发 100 次全量收敛，既慢又会把
// 收敛循环搅乱（这正是 V6「导入 100 台 ≤ 10 秒」能否达成的关键）。
func (s *Service) createPeer(ctx context.Context, in PeerInput, a Actor) (*model.Peer, error) {
	it, err := s.Store.GetInterface(ctx, in.InterfaceID)
	if err != nil {
		return nil, fmt.Errorf("所选连接不存在，请刷新页面后重试")
	}
	if in.RouteMode == "" {
		in.RouteMode = model.RouteModeLAN
	}
	p := &model.Peer{
		InterfaceID:      in.InterfaceID,
		Name:             strings.TrimSpace(in.Name),
		PublicKey:        strings.TrimSpace(in.PublicKey),
		PresharedKey:     strings.TrimSpace(in.PresharedKey),
		RouteMode:        in.RouteMode,
		ClientAllowedIPs: in.ClientAllowedIPs,
		EndpointHost:     strings.TrimSpace(in.EndpointHost),
		EndpointPort:     in.EndpointPort,
		AllowedIPs:       in.AllowedIPs,
		Keepalive:        in.Keepalive,
		GroupTag:         in.GroupTag,
		Remark:           in.Remark,
		QuotaRx:          in.QuotaRx,
		QuotaTx:          in.QuotaTx,
		ExpireAt:         in.ExpireAt,
		Enabled:          in.Enabled,
	}

	if in.GenerateKeys || p.PublicKey == "" {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return nil, err
		}
		p.ClientPrivateKey, p.PublicKey = priv, pub
	} else if !wgkey.Validate(p.PublicKey) {
		return nil, fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码，请确认完整复制")
	}
	if in.GeneratePSK || (p.PresharedKey == "" && in.GenerateKeys) {
		psk, err := wgkey.GeneratePSK()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk
	} else if p.PresharedKey != "" && !wgkey.Validate(p.PresharedKey) {
		return nil, fmt.Errorf("二次加密口令格式不正确，请重新生成或清空该项")
	}

	if p.Name == "" {
		p.Name = "设备-" + shortKey(p.PublicKey)
	}
	if in.AutoAddress || len(p.AllowedIPs) == 0 {
		existing, err := s.Store.ListPeers(ctx, it.ID)
		if err != nil {
			return nil, err
		}
		if ip := nextFreeIP(it, existing); ip != "" {
			p.AllowedIPs = append(p.AllowedIPs, ip)
		}
	}
	if p.Keepalive == 0 && p.EndpointHost == "" {
		p.Keepalive = 25
	}
	if err := s.validatePeer(ctx, p, 0); err != nil {
		return nil, err
	}
	if err := s.Store.CreatePeer(ctx, p); err != nil {
		return nil, err
	}
	p.InterfaceName = it.Name
	s.audit(ctx, a, "peer.create", "peer", fmt.Sprint(p.ID), "", p.Name, "ok", "")
	return p, nil
}

// PeerImportRow 是批量导入里的一台设备。
type PeerImportRow struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Remark    string `json:"remark"`
	GroupTag  string `json:"group_tag"`
}

// PeerImportItem 是单台设备的导入结果（逐条回传成功或失败原因）。
type PeerImportItem struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Error  string `json:"error,omitempty"`
	PeerID int64  `json:"peer_id,omitempty"`
}

// PeerImportResult 是批量导入汇总。
type PeerImportResult struct {
	Created int              `json:"created"`
	Failed  int              `json:"failed"`
	Items   []PeerImportItem `json:"items"`
}

// ImportPeers 批量创建设备：逐条创建并汇总结果，最后统一收敛一次。
//
// 与「一次导入整份 wg-quick 配置」不同：这里导入的是**已有的连接下的多台设备**，
// 且必须逐条给出成功/失败明细 —— 重复识别码、格式非法等问题要能定位到具体哪一行，
// 否则用户面对一堆设备根本不知道该改哪一台。
func (s *Service) ImportPeers(ctx context.Context, ifaceID int64, rows []PeerImportRow, a Actor) (*PeerImportResult, error) {
	if len(rows) == 0 {
		return nil, fmt.Errorf("没有可导入的设备")
	}
	if len(rows) > 500 {
		return nil, fmt.Errorf("单次最多导入 500 台设备，当前 %d 台，请分批导入", len(rows))
	}
	if _, err := s.Store.GetInterface(ctx, ifaceID); err != nil {
		return nil, fmt.Errorf("所选连接不存在，请刷新页面后重试")
	}
	res := &PeerImportResult{Items: make([]PeerImportItem, 0, len(rows))}
	for i, r := range rows {
		name := strings.TrimSpace(r.Name)
		item := PeerImportItem{Index: i, Name: name}
		if name == "" {
			item.Error = "缺少设备名称"
			res.Failed++
			res.Items = append(res.Items, item)
			continue
		}
		pub := strings.TrimSpace(r.PublicKey)
		p, err := s.createPeer(ctx, PeerInput{
			InterfaceID: ifaceID,
			Name:        name,
			PublicKey:   pub,
			Remark:      strings.TrimSpace(r.Remark),
			GroupTag:    strings.TrimSpace(r.GroupTag),
			Keepalive:   25,
			Enabled:     true,
			AutoAddress: true,
			// 没给识别码的就自动生成密钥对（等同于在界面点「自动生成」）
			GenerateKeys: pub == "",
			GeneratePSK:  true,
		}, a)
		if err != nil {
			item.Error = err.Error()
			res.Failed++
		} else {
			item.OK = true
			item.PeerID = p.ID
			item.Name = p.Name
			res.Created++
		}
		res.Items = append(res.Items, item)
	}
	if res.Created > 0 {
		_ = s.reconcile(ctx)
	}
	s.audit(ctx, a, "peer.import", "peer", fmt.Sprint(ifaceID), "",
		fmt.Sprintf("成功 %d / 失败 %d", res.Created, res.Failed), "ok", "")
	return res, nil
}

// UpdatePeer 更新节点。
func (s *Service) UpdatePeer(ctx context.Context, id int64, in PeerInput, a Actor) (*model.Peer, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	if in.InterfaceID > 0 {
		p.InterfaceID = in.InterfaceID
	}
	p.Name = strings.TrimSpace(in.Name)
	if in.PublicKey != "" {
		if !wgkey.Validate(in.PublicKey) {
			return nil, fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码")
		}
		p.PublicKey = in.PublicKey
	}
	p.PresharedKey = strings.TrimSpace(in.PresharedKey)
	p.RouteMode = in.RouteMode
	p.ClientAllowedIPs = in.ClientAllowedIPs
	p.EndpointHost = strings.TrimSpace(in.EndpointHost)
	p.EndpointPort = in.EndpointPort
	p.AllowedIPs = in.AllowedIPs
	p.Keepalive = in.Keepalive
	p.GroupTag = in.GroupTag
	p.Remark = in.Remark
	p.QuotaRx, p.QuotaTx = in.QuotaRx, in.QuotaTx
	p.ExpireAt = in.ExpireAt
	p.Enabled = in.Enabled
	if in.GenerateKeys {
		priv, pub, err := wgkey.Generate()
		if err != nil {
			return nil, err
		}
		p.ClientPrivateKey, p.PublicKey = priv, pub
	} else if in.ClientPrivateKey != "" {
		p.ClientPrivateKey = in.ClientPrivateKey
	}
	if in.GeneratePSK {
		psk, err := wgkey.GeneratePSK()
		if err != nil {
			return nil, err
		}
		p.PresharedKey = psk
	}
	if err := s.validatePeer(ctx, p, id); err != nil {
		return nil, err
	}
	if err := s.Store.UpdatePeer(ctx, p); err != nil {
		return nil, err
	}
	s.audit(ctx, a, "peer.update", "peer", fmt.Sprint(id), "", p.Name, "ok", "")
	_ = s.reconcile(ctx)
	p.PresharedKey = ""
	p.ClientPrivateKey = ""
	return p, nil
}

// DeletePeer 删除节点。
func (s *Service) DeletePeer(ctx context.Context, id int64, a Actor) error {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return err
	}
	if err := s.Store.DeletePeer(ctx, id); err != nil {
		return err
	}
	s.audit(ctx, a, "peer.delete", "peer", fmt.Sprint(id), p.Name, "", "ok", "")
	return s.reconcile(ctx)
}

// BatchPeerRequest 是批量操作请求。
type BatchPeerRequest struct {
	IDs        []int64  `json:"ids"`
	Action     string   `json:"action"`
	Keepalive  int      `json:"persistent_keepalive"`
	AllowedIPs []string `json:"allowed_ips"`
	GroupTag   string   `json:"group_tag"`
	ExtendDays int      `json:"extend_days"`
	QuotaRx    int64    `json:"quota_rx"`
	QuotaTx    int64    `json:"quota_tx"`
}

// BatchPeers 执行批量操作。
func (s *Service) BatchPeers(ctx context.Context, req BatchPeerRequest, a Actor) (string, error) {
	if len(req.IDs) == 0 {
		return "", fmt.Errorf("请先勾选要操作的设备")
	}
	switch req.Action {
	case "enable", "disable":
		n, err := s.Store.BatchSetPeerEnabled(ctx, req.IDs, req.Action == "enable")
		if err != nil {
			return "", err
		}
		s.audit(ctx, a, "peer.batch_"+req.Action, "peer", idsString(req.IDs), "", fmt.Sprint(n), "ok", "")
		_ = s.reconcile(ctx)
		return fmt.Sprintf("已%s %d 个节点", map[bool]string{true: "启用", false: "禁用"}[req.Action == "enable"], n), nil

	case "delete":
		n, err := s.Store.BatchDeletePeers(ctx, req.IDs)
		if err != nil {
			return "", err
		}
		s.audit(ctx, a, "peer.batch_delete", "peer", idsString(req.IDs), "", fmt.Sprint(n), "ok", "")
		_ = s.reconcile(ctx)
		return fmt.Sprintf("已删除 %d 个节点", n), nil
	}

	// 其余动作逐条更新
	changed := 0
	for _, id := range req.IDs {
		p, err := s.Store.GetPeer(ctx, id)
		if err != nil {
			continue
		}
		switch req.Action {
		case "keepalive":
			p.Keepalive = req.Keepalive
		case "group":
			p.GroupTag = req.GroupTag
		case "allowed_ips":
			if err := validateCIDRList("允许通行的地址", req.AllowedIPs); err != nil {
				return "", err
			}
			p.AllowedIPs = wgconf.MergeCIDRs(append(p.AllowedIPs, req.AllowedIPs...))
		case "extend":
			base := time.Now()
			if p.ExpireAt != nil && p.ExpireAt.After(base) {
				base = *p.ExpireAt
			}
			t := base.AddDate(0, 0, req.ExtendDays)
			p.ExpireAt = &t
		case "quota":
			p.QuotaRx, p.QuotaTx = req.QuotaRx, req.QuotaTx
		default:
			return "", fmt.Errorf("不支持的操作类型：%s", req.Action)
		}
		if err := s.Store.UpdatePeer(ctx, p); err != nil {
			continue
		}
		changed++
	}
	s.audit(ctx, a, "peer.batch_"+req.Action, "peer", idsString(req.IDs), "", fmt.Sprint(changed), "ok", "")
	_ = s.reconcile(ctx)
	return fmt.Sprintf("已更新 %d 个节点", changed), nil
}

// PeerConfigResult 是客户端配置下发结果。
type PeerConfigResult struct {
	Conf            string   `json:"conf"`
	Filename        string   `json:"filename"`
	Endpoint        string   `json:"endpoint"`
	ServerPublicKey string   `json:"server_public_key"`
	ClientAddress   []string `json:"client_address"`
	AllowedIPs      []string `json:"allowed_ips"`
	QRPayload       string   `json:"qr_payload"`
	Warning         string   `json:"warning,omitempty"`
}

// PeerConfig 生成客户端可直接导入的配置（同时用于二维码内容）。
func (s *Service) PeerConfig(ctx context.Context, id int64) (*PeerConfigResult, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	it, err := s.Store.GetInterface(ctx, p.InterfaceID)
	if err != nil {
		return nil, err
	}
	if p.ClientPrivateKey == "" {
		return nil, fmt.Errorf("这台设备没有保存密钥（当初是以外部识别码添加的），因此无法生成二维码。请在「编辑」中勾选「保存时生成新的密钥对」后重试")
	}
	serverPub, err := wgkey.PublicKey(it.PrivateKey)
	if err != nil {
		return nil, err
	}
	endpoint, warn := s.serverEndpoint(ctx, it)
	clientAddrs, extraRoutes := wgconf.SplitClientAndServerIPs(it, p)
	clientAllowed := s.clientAllowedIPs(ctx, it, p, extraRoutes)
	conf := wgconf.RenderClient(serverPub, it, p, wgconf.RenderClientOptions{
		Endpoint:         endpoint,
		ClientPrivateKey: p.ClientPrivateKey,
		ClientAddress:    clientAddrs,
		AllowedIPs:       clientAllowed,
		DNS:              s.clientDNS(ctx, it),
		MTU:              it.MTU,
		Keepalive:        p.Keepalive,
	})
	// 记下「这台设备刚拿到的配置」：之后改动对外地址、DNS、通行范围时，
	// 界面就能据此标出「配置已过期，需要重新扫码」，而不是让用户自己猜。
	s.rememberPeerConfig(ctx, p, wgconf.ClientFingerprint(wgconf.ClientConfigInputs{
		Endpoint:    endpoint,
		ClientAddrs: clientAddrs,
		AllowedIPs:  clientAllowed,
		DNS:         s.clientDNS(ctx, it),
		MTU:         it.MTU,
		Keepalive:   p.Keepalive,
		ServerPub:   serverPub,
	}))
	name := p.Name
	if name == "" {
		name = fmt.Sprintf("peer-%d", p.ID)
	}
	return &PeerConfigResult{
		Conf:            conf,
		Filename:        name + ".conf",
		Endpoint:        endpoint,
		ServerPublicKey: serverPub,
		ClientAddress:   clientAddrs,
		AllowedIPs:      clientAllowed,
		QRPayload:       conf,
		Warning:         warn,
	}, nil
}

// clientDNS 返回下发给设备的 DNS 服务器地址。
//
// 打开了「内网域名解析」时，设备必须把 NAS 当作解析器，否则它解析不了家里设备名：
// 此时下发的是**本连接的隧道地址**，而连接里配置的 DNS 变成本应用解析器的上游。
// 关闭时保持原样（下发连接里配置的 DNS），行为与升级前完全一致。
func (s *Service) clientDNS(ctx context.Context, it *model.Interface) []string {
	if s.Store.GetSetting(ctx, model.SettingDNSResolve, "") != "1" {
		return it.DNS
	}
	for _, a := range it.Addresses {
		if ip, _, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil && ip.To4() != nil {
			return []string{ip.String()}
		}
	}
	// 没有可用的 IPv4 隧道地址时退回原值：宁可不生效，也不要下发一个设备连不上的地址
	return it.DNS
}

// clientAllowedIPs 生成客户端侧的通行范围（决定设备上哪些流量走隧道）。
//
// 这是「设备上网方式」的落地：只影响设备自身的配置，绝不改动 NAS 的路由。
func (s *Service) clientAllowedIPs(ctx context.Context, it *model.Interface, p *model.Peer, extra []string) []string {
	switch p.RouteMode {
	case model.RouteModeFull:
		return []string{"0.0.0.0/0", "::/0"}
	case model.RouteModeCustom:
		if len(p.ClientAllowedIPs) > 0 {
			return wgconf.MergeCIDRs(p.ClientAllowedIPs)
		}
	}
	// lan（默认）：仅让设备能访问本端内网与额外放行的网段
	out := append([]string{}, s.homeLANSubnets(ctx)...)
	out = append(out, extra...)
	if len(out) == 0 {
		// 探测失败时退化为"只能访问隧道内地址"，仍然可用且安全
		out = append(out, it.Addresses...)
	}
	return wgconf.MergeCIDRs(out)
}

// homeLANSubnets 本端局域网网段：优先使用设置中的值，否则自动探测。
func (s *Service) homeLANSubnets(ctx context.Context) []string {
	if v := s.Store.GetSetting(ctx, "home_lan_cidrs", ""); v != "" {
		return wgconf.MergeCIDRs(strings.Split(v, ","))
	}
	return detectLocalSubnets()
}

// RevealPeerSecrets 回显节点密钥（需 key.reveal 权限）。
func (s *Service) RevealPeerSecrets(ctx context.Context, id int64, a Actor) (map[string]string, error) {
	p, err := s.Store.GetPeer(ctx, id)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, a, "peer.reveal_key", "peer", fmt.Sprint(id), "", "", "ok", "查看节点密钥")
	out := map[string]string{"public_key": p.PublicKey}
	if p.ClientPrivateKey != "" {
		out["client_private_key"] = p.ClientPrivateKey
	}
	if p.PresharedKey != "" {
		out["preshared_key"] = p.PresharedKey
	}
	return out, nil
}

// serverEndpoint 解析服务端对外地址。
func (s *Service) serverEndpoint(ctx context.Context, it *model.Interface) (string, string) {
	if v := s.Store.GetSetting(ctx, "server_endpoint", ""); v != "" {
		return v, ""
	}
	ip := detectLocalIPv4()
	if ip == "" {
		return "", "尚未配置「服务端对外地址」，二维码中的 Endpoint 为空，请到系统设置中填写公网域名或 IP"
	}
	port := it.ListenPort
	if port == 0 {
		port = defaultListenPort
	}
	return net.JoinHostPort(ip, strconv.Itoa(port)),
		"当前 Endpoint 使用自动探测的本机地址，公网访问请到系统设置中配置 DDNS 域名或公网 IP"
}

func (s *Service) validatePeer(ctx context.Context, p *model.Peer, selfID int64) error {
	if !wgkey.Validate(p.PublicKey) {
		return fmt.Errorf("对方设备的识别码格式不正确：应为一串 44 个字符的编码")
	}
	if p.EndpointHost != "" && (p.EndpointPort <= 0 || p.EndpointPort > 65535) {
		return fmt.Errorf("「对方端口」填写不正确，请填写 1 到 65535 之间的数字")
	}
	if err := validateCIDRList("分配给这台设备的内部地址", p.AllowedIPs); err != nil {
		return err
	}
	// 安全红线：服务端准入地址中出现默认路由写法，会改写 NAS 自身网络。
	if err := wgback.ValidatePeerAllowedIPs(p.AllowedIPs); err != nil {
		return err
	}
	switch p.RouteMode {
	case model.RouteModeFull, model.RouteModeLAN:
	case model.RouteModeCustom:
		if len(p.ClientAllowedIPs) == 0 {
			return fmt.Errorf("选择了「自定义可访问范围」但没有填写网段，请补充后再保存")
		}
		if err := validateCIDRList("自定义可访问范围", p.ClientAllowedIPs); err != nil {
			return err
		}
		if err := s.checkScopeConflicts(ctx, p); err != nil {
			return err
		}
	default:
		return fmt.Errorf("「设备上网方式」取值不正确，请选择：只访问家里设备 / 在外上网也走家里 / 自定义可访问范围")
	}
	if p.Keepalive < 0 || p.Keepalive > 3600 {
		return fmt.Errorf("心跳间隔需要在 0 到 3600 秒之间（推荐 25 秒）")
	}
	peers, err := s.Store.ListPeers(ctx, p.InterfaceID)
	if err != nil {
		return err
	}
	for _, other := range peers {
		if other.ID == selfID {
			continue
		}
		if other.PublicKey == p.PublicKey {
			return fmt.Errorf("这台设备已经在当前连接中了（识别码重复），请勿重复添加")
		}
		if sameStringSet(other.AllowedIPs, p.AllowedIPs) && len(p.AllowedIPs) > 0 {
			return fmt.Errorf("「允许通行的地址」与设备「%s」完全相同，两台设备会冲突，请修改后重试", other.Name)
		}
	}
	return nil
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	m := map[string]bool{}
	for _, s := range a {
		m[s] = true
	}
	for _, s := range b {
		if !m[s] {
			return false
		}
	}
	return true
}

func idsString(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// nextFreeIP 在接口隧道网段内寻找空闲地址（从 .2 开始）。
func nextFreeIP(it *model.Interface, peers []model.Peer) string {
	used := map[string]bool{}
	for _, p := range peers {
		for _, a := range p.AllowedIPs {
			if ip, _, err := net.ParseCIDR(a); err == nil {
				used[ip.String()] = true
			}
		}
	}
	for _, a := range it.Addresses {
		ip, ipnet, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		used[ip.String()] = true
		base := ipnet.IP.To4()
		if base == nil {
			continue
		}
		for i := 2; i < 255; i++ {
			cand := net.IPv4(base[0], base[1], base[2], byte(i))
			if !used[cand.String()] {
				return cand.String() + "/32"
			}
		}
	}
	return ""
}
