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
	autoAllocTries    = 64 // 自动分配时最多顺延尝试的位数

	// addrBaseMin / addrBaseMax 是自动分配时「第三个八位组」的可取范围：10.10.0.0/24 ~ 10.250.0.0/24。
	//
	// 起点**不固定为 10**：真实环境里两台 NAS 的第 N 条连接会拿到同一个网段（见
	// defaultInterfaceAddr），于是两端的设备地址成对重复。这里留出 241 个网段，
	// 由每台机器自己的基准偏移（见 defaultAddrOffset）挑起点。
	addrBaseMin = 10
	addrBaseMax = 250
	// addrSpan 是可选网段个数。
	addrSpan = addrBaseMax - addrBaseMin + 1
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
	s.markSiteInterfaces(ctx, list)
	for i := range list {
		list[i].PrivateKey = ""
		list[i].PortNote = s.portNoteFor(ctx, list[i])
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
	s.markSiteInterfaces(ctx, list)
	it.PrivateKey = ""
	it.PortNote = s.portNoteFor(ctx, *it)
	return it, nil
}

// portNoteFor 推导「这条连接能不能从外网连回来」的提示（派生，不落库）。
//
// 放在列表与详情两条读路径上：这条提示必须在**平时**就能看见，
// 否则用户只有在「设备/对端连不上」时才会去猜端口。
func (s *Service) portNoteFor(ctx context.Context, it model.Interface) string {
	endpoint, _ := s.serverEndpoint(ctx, &it)
	note := portNoteIfMismatch(&it, endpoint)
	if note == "" {
		return ""
	}
	// 端口不一致有两种情形，处置完全不同，混成一句话会让一半的人查错方向：
	//   a) 另一条连接正好监听这个外部端口 —— 外部的包已经转给它了，本连接在外网不可能被连上，
	//      要改的是「系统设置里的端口」；
	//   b) 没有连接监听这个端口 —— 用户是把外部端口交给路由器换算到本机端口，
	//      可以工作，但必须真的转得通（真机踩过：以为转好了，其实没有），要查的是路由器。
	_, ext := splitHostPort(endpoint)
	if ext <= 0 {
		return note
	}
	others, err := s.otherInterfaces(ctx, it.ID)
	if err != nil {
		// 读不到其它连接时退回软提示：这是解释性文案，不值得让它挡住列表。
		return note
	}
	for _, o := range others {
		if o.Enabled && o.ListenPort == ext {
			return fmt.Sprintf("对外访问地址用的是 %d 端口，而这个端口正由连接「%s」监听："+
				"一个外部端口同一时刻只能转给一条连接，所以这条连接从外网连不回来。"+
				"到「系统设置 → 接入设置」把对外访问地址里的端口去掉（只留域名或 IP），"+
				"每条连接就会各自用自己的端口；若确实只能用一个外部端口，就只让「%s」对外接客，"+
				"其余连接只用于站点互联", ext, o.Name, o.Name)
		}
	}
	return note
}

// markSiteInterfaces 填「这条连接是异地组网还是普通连接」的派生标记（不落库）。
//
// 判定沿用备注前缀（isSitePeer），与拓扑图、互联向导共用一套口径 ——
// 换个判据就会出现「拓扑说是站点、列表说是普通」这种自相矛盾。
func (s *Service) markSiteInterfaces(ctx context.Context, list []model.Interface) {
	if len(list) == 0 {
		return
	}
	peers, err := s.Store.ListPeers(ctx, 0)
	if err != nil {
		return // 读不到就不标：宁可少个标签，也不要靠猜打标
	}
	site := map[int64]bool{}
	for i := range peers {
		if isSitePeer(&peers[i]) {
			site[peers[i].InterfaceID] = true
		}
	}
	for i := range list {
		if site[list[i].ID] {
			list[i].Kind = model.IfaceKindSite
		}
	}
}

// markSitePeers 填「这条条目是另一台 NAS」的派生标记（不落库）。
func markSitePeers(peers []model.Peer) {
	for i := range peers {
		if isSitePeer(&peers[i]) {
			peers[i].SiteLink = true
		}
	}
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
	// Enabled / Autostart 用指针表达「有没有指定」：新建时为 nil 表示按默认（不启用、不随系统启动，
	// 与这两个字段用非指针时的行为一致），编辑时为 nil 表示保持原值。
	//
	// 它们原先是非指针布尔，于是「部分更新」在语义上根本不成立 —— 只传 {"allow_lan": true}
	// 会把 enabled 与 autostart 一并置为 false，一条正在运行的连接就这么被顺手停用了。
	// 界面编辑抽屉总是提交完整对象，所以用户碰不到；但脚本与自动化一定会踩，而且故障现象
	// （连接被停用）与那一步操作（改了个无关开关）完全对不上，排查代价很高。
	Enabled   *bool `json:"enabled"`
	Autostart *bool `json:"autostart"`
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
		Enabled:    in.Enabled != nil && *in.Enabled,
		Autostart:  in.Autostart != nil && *in.Autostart,
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
	// 只有显式给出才改动这两个开关（理由见 CreateInterfaceInput 里它们的说明）。
	if in.Enabled != nil {
		it.Enabled = *in.Enabled
	}
	if in.Autostart != nil {
		it.Autostart = *in.Autostart
	}
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
// 内部地址与监听端口留空时自动分配一个不与其它连接冲突的取值：网段按「本机偏移 + 连接
// 序号」顺延（见 defaultInterfaceAddr / pickFreeAddr），端口从 51820 起按序号顺延；
// 序号位已被占用则继续顺延，避免「新建第二条连接就必须手工改端口和网段」。
func (s *Service) applyInterfaceDefaults(ctx context.Context, it *model.Interface, selfID int64) error {
	it.Addresses = wgconf.MergeCIDRs(it.Addresses)
	it.DNS = wgconf.MergeCIDRs(it.DNS)
	if it.MTU <= 0 {
		it.MTU = defaultMTU
	}
	it.DNSMode = normalizeDNSMode(it.DNSMode)
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
		it.Addresses = []string{pickFreeAddr(others, start, s.defaultAddrOffset(ctx), s.reservedSubnets(ctx))}
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

// defaultInterfaceAddr 按「本机偏移 + 连接序号」给出默认内部地址：
// 偏移 0 时 wg0 → 10.10.0.1/24、wg1 → 10.11.0.1/24。
//
// 为什么要加一个按机器随机的基准偏移（真机踩到过）：两台 NAS 的第 1 条连接都是各自
// 「序号 0」，纯按序号分配必然都得到 10.10.0.0/24，第 2 条都是 10.11.0.0/24……于是
// 两端设备地址成对重复（都是 .2、.3…）。两端各自独立时看不出问题，但：
//   - 同一个客户端同时导入两台 NAS 的配置时，两份配置的 Address 直接冲突（其中一条不通）；
//   - 两台 NAS 互联后，从一端访问对端同网段里的设备会被本机直连路由截住，永远不通，
//     而隧道本身是通的（能访问对端 NAS 与对端其它网段），用户完全推不出是地址撞车。
//
// 加上这台机器自己的基准后，两端默认网段撞车的概率从「必然」降到约 1/241；
// 本机内部仍按序号顺延、仍会避开已占用的网段（见 pickFreeAddr）。
func defaultInterfaceAddr(offset, idx int) string {
	return fmt.Sprintf("10.%d.0.1/24", addrBase(offset, idx))
}

// addrBase 把「基准偏移 + 连接序号」折算到 addrBaseMin..addrBaseMax 区间内。
func addrBase(offset, idx int) int {
	if idx < 0 {
		idx = 0
	}
	v := (offset%addrSpan + addrSpan) % addrSpan
	return addrBaseMin + (v+idx)%addrSpan
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

// pickFreeAddr 从「本机偏移 + 序号」对应的默认网段开始顺延，返回第一个可用的网段。
//
// avoid 是「本机已知、由另一台 NAS 占用」的网段（见 reservedSubnets）：本机内部唯一并不能
// 保证两端不撞车 —— 两端各自算出的第 N 条连接会落在同一个网段，于是两端的设备地址成对重复
// （都是 .2、.3…）。自动分配时一并避开，是唯一能在用户还没察觉之前就避免这个坑的时机。
//
// 只作用于自动分配：用户手工填的地址仍由用户决定。那份清单是「导入那一刻」的快照，
// 可能已经过期，硬拦会让人连想改都改不掉（重叠时由体检持续报出来，见 inspect.go）。
func pickFreeAddr(others []model.Interface, start, offset int, avoid []string) string {
	for i := 0; i < autoAllocTries; i++ {
		a := defaultInterfaceAddr(offset, start+i)
		if !addrOverlapsAny(others, a) && !addrOverlapsAnyCIDR(avoid, a) {
			return a
		}
	}
	return defaultInterfaceAddr(offset, start)
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

// addrOverlapsAnyCIDR 判断网段是否与一份网段清单中的任意一项重叠。
func addrOverlapsAnyCIDR(avoid []string, cidr string) bool {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return false
	}
	for _, c := range avoid {
		if _, cn, err := net.ParseCIDR(strings.TrimSpace(c)); err == nil && cidrOverlap(n, cn) {
			return true
		}
	}
	return false
}

// cidrOverlap 判断两个网段是否有交集（不同协议族之间永远不重叠）。
func cidrOverlap(a, b *net.IPNet) bool {
	return a.Contains(b.IP) || b.Contains(a.IP)
}

// normalizeDNSMode 归一化「下发 DNS」的取值。
//
// 空值取默认（下发给设备）；历史值 host 一律按 client 处理 —— 它对应界面上的
// 「NAS 也一起使用」，而这个行为**从未实现过**：本应用绝不修改 NAS 自身的系统解析
// （见 internal/dnsserver 的安全边界）。对这类存量值报错只会让用户连「改个别的地方」
// 都保存不了，所以静默归一；其它取值原样返回，交给校验去拒绝，不静默接受拼错的写法。
func normalizeDNSMode(v string) string {
	v = strings.TrimSpace(v)
	switch v {
	case "", model.DNSModeLegacyHost:
		return model.DNSModeClient
	default:
		return v
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
	if it.DNSMode != model.DNSModeClient && it.DNSMode != model.DNSModeOff {
		return fmt.Errorf("「下发 DNS」取值不正确，请选择：下发给设备 / 不下发")
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
	if err := checkInterfaceConflicts(it, others, s.defaultAddrOffset(ctx)); err != nil {
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
//
// offset 是本机的网段基准偏移，只用于给出「建议换成哪个网段」——它必须与自动分配
// 用的是同一个偏移，否则建议出来的地址可能又把别的连接撞上。
func checkInterfaceConflicts(it *model.Interface, others []model.Interface, offset int) error {
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
						a, others[i].Name, o, pickFreeAddr(others, defaultIndexFor(it.Name), offset, nil))
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
