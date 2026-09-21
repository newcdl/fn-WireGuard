// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"fnwg/internal/model"
)

// 网络拓扑图：以本机 NAS 为中心，画出它所在的内网、内网里的设备，
// 以及经隧道连到的另一台 NAS 及其内网。
//
// 组装与判定都做成纯函数（buildTopology），只有取数在 Service 上 ——
// 图上的每个节点与连线都直接对应一条事实，判错会让人对网络产生错误印象，
// 因此规则要能在单元测试里逐条核对，而不是靠肉眼看页面。
//
// 数据来源与各自的边界（都会写进图的说明里）：
//
//	内网网段：本机探测到的家里网段（设置里可覆盖）；
//	内网设备：**内核邻居表**，只读、不扫描 —— 只有最近和 NAS 通信过的机器会出现；
//	隧道设备：本应用的设备清单（在线状态、最近通信、流量都来自运行期状态）；
//	对端 NAS：互联时写入的那条「站点设备」（备注以「站点互联」开头）；
//	对端内网：该对端设备的准入网段（隧道之外的那些）。
//
// 对端内网里的设备明细这边看不到：对端 NAS 会把它的设备源地址改写成隧道地址，
// 因此在我们这侧只能看到「对端 NAS 一个地址」。这一点在图上是明说的，不装作有数据。

// TopologyKV 是悬停卡片里的一行。
type TopologyKV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// TopologyNode 是拓扑图上的一个节点。
type TopologyNode struct {
	ID       string `json:"id"`
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Sublabel string `json:"sublabel,omitempty"`
	Status   string `json:"status"`
	// Note 是「内网域名」里登记的备注（没登记为空）。
	Note string `json:"note,omitempty"`
	// DeviceKind 是用户明确配置的设备类型（空 = 按名称自动判断）。
	DeviceKind string       `json:"device_kind,omitempty"`
	Details    []TopologyKV `json:"details"`
}

// TopologyLink 是两个节点之间的连线。
type TopologyLink struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Kind   string `json:"kind"`
	Label  string `json:"label,omitempty"`
	Status string `json:"status"`
	// Rate 是这条线上的当前速率（字节/秒），界面据此决定流动动画的快慢。
	Rate float64 `json:"rate,omitempty"`
}

// TopologyGraph 是画一张拓扑图所需的全部数据（一次只读快照）。
type TopologyGraph struct {
	At       time.Time      `json:"at"`
	HostName string         `json:"host_name"`
	Nodes    []TopologyNode `json:"nodes"`
	Links    []TopologyLink `json:"links"`
	Notes    []string       `json:"notes"`
}

// 节点与连线的种类（界面按它决定图标、颜色与形状）。
const (
	TopoNodeNAS     = "nas"
	TopoNodeLAN     = "lan"
	TopoNodeHost    = "host"
	TopoNodeDevice  = "device"
	TopoNodeSite    = "site"
	TopoNodeSiteLAN = "site-lan"
	TopoNodeForeign = "foreign"

	TopoLinkLAN     = "lan"
	TopoLinkHost    = "host"
	TopoLinkTunnel  = "tunnel"
	TopoLinkSite    = "site"
	TopoLinkSiteLAN = "site-lan"
	TopoLinkForeign = "foreign"
)

// topologyFacts 是画一张图所需的全部事实。
type topologyFacts struct {
	HostName    string
	HomeSubnets []string
	WANs        []string
	Interfaces  []model.Interface
	Peers       []model.Peer
	LAN         *model.LANReport
	Foreign     []model.ForeignInterface
	// DNSNames 是「内网域名」里登记过的 IP → 名字；图上优先显示它，
	// 否则显示内核邻居表里没有名字的地址（并提示可以自己去登记一个）。
	DNSNames map[string]string
	// DNSNotes 是同一批记录的备注：用户登记时写的说明（例如「客厅的电视」）。
	DNSNotes map[string]string
	// Kinds 是用户明确配置的「IP → 设备类型」（见 SetDeviceKind）。
	Kinds map[string]string
}

func topoID(kind string, parts ...string) string {
	return kind + ":" + strings.Join(parts, ":")
}

// buildTopology 把事实拼成一张图。
func buildTopology(f topologyFacts) TopologyGraph {
	g := TopologyGraph{At: time.Now(), HostName: f.HostName}
	add := func(n TopologyNode) { g.Nodes = append(g.Nodes, n) }
	link := func(l TopologyLink) { g.Links = append(g.Links, l) }

	hostName := f.HostName
	if strings.TrimSpace(hostName) == "" {
		hostName = "本机 NAS"
	}
	// ① 中心节点：本机 NAS
	enabledIfaces := 0
	for _, it := range f.Interfaces {
		if it.Enabled {
			enabledIfaces++
		}
	}
	add(TopologyNode{
		ID: topoID(TopoNodeNAS), Kind: TopoNodeNAS, Label: hostName, Sublabel: "本机",
		Status: "ok",
		Details: []TopologyKV{
			{Key: "主机名", Value: hostName},
			{Key: "内网网段", Value: topoJoin(f.HomeSubnets, "未探测到")},
			{Key: "出口网卡", Value: topoJoin(f.WANs, "未探测到")},
			{Key: "隧道连接", Value: fmt.Sprintf("%d 条（%d 条已启用）", len(f.Interfaces), enabledIfaces)},
		},
	})

	// ② 内网网段 + 网段里的设备
	lanIDs := map[string]string{}
	for _, cidr := range f.HomeSubnets {
		id := topoID(TopoNodeLAN, cidr)
		lanIDs[cidr] = id
		add(TopologyNode{
			ID: id, Kind: TopoNodeLAN, Label: cidr, Sublabel: "内网", Status: "ok",
			Details: []TopologyKV{
				{Key: "网段", Value: cidr},
				{Key: "说明", Value: "NAS 所在的局域网；设备来自内核邻居表（只显示最近通信过的机器）"},
			},
		})
		link(TopologyLink{From: topoID(TopoNodeNAS), To: id, Kind: TopoLinkLAN, Status: "ok"})
	}

	devices := []model.LANDevice{}
	if f.LAN != nil {
		devices = f.LAN.Devices
	}
	known := 0
	demo := f.LAN != nil && f.LAN.Demo
	fallbackLAN := ""
	for _, cidr := range f.HomeSubnets {
		fallbackLAN = lanIDs[cidr]
		break
	}
	for _, d := range devices {
		parent := topoLANFor(lanIDs, f.HomeSubnets, d.IP)
		if parent == "" {
			// 不在任何内网网段里：不画（画出来会让人以为家里真有这个地址）。
			// 演示数据例外：样板地址不可能刚好落在本机探测到的网段里，
			// 而演示环境正是要让人看见「图上会长什么样」（说明里已明说这是样板数据）。
			if demo && fallbackLAN != "" {
				parent = fallbackLAN
			} else {
				continue
			}
		}
		name := strings.TrimSpace(f.DNSNames[d.IP])
		if name == "" {
			name = strings.TrimSpace(d.Name)
		}
		label, sub := d.IP, "内网设备"
		named := name != ""
		if named {
			label, sub = name, d.IP
			known++
		}
		add(TopologyNode{
			ID: topoID(TopoNodeHost, d.IP), Kind: TopoNodeHost, Label: label, Sublabel: sub,
			Status:     topoHostStatus(d.State),
			Note:       f.DNSNotes[d.IP],
			DeviceKind: f.Kinds[d.IP],
			Details: []TopologyKV{
				{Key: "IP 地址", Value: d.IP},
				{Key: "名称", Value: topoOr(name, "未登记（可在「系统设置 → 内网域名」里给它起个名字）")},
				{Key: "MAC", Value: topoOr(d.MAC, "未知")},
				{Key: "状态", Value: topoHostStateLabel(d.State)},
				{Key: "所在网卡", Value: topoOr(d.Interface, "未知")},
			},
		})
		link(TopologyLink{From: parent, To: topoID(TopoNodeHost, d.IP), Kind: TopoLinkHost, Status: "ok"})
	}

	// ③ 隧道设备与对端 NAS
	tunnels := 0
	sites := 0
	for i := range f.Peers {
		p := &f.Peers[i]
		iface := topoInterfaceOf(f.Interfaces, p.InterfaceID)
		ifaceName := ifaceNameOf(iface)
		if isSitePeer(p) {
			sites++
			siteID := topoID(TopoNodeSite, fmt.Sprint(p.ID))
			st := "off"
			if p.Online {
				st = "ok"
			} else if p.Enabled {
				st = "warn"
			}
			add(TopologyNode{
				ID: siteID, Kind: TopoNodeSite, Label: topoOr(p.Name, "对端 NAS"), Sublabel: "另一台 NAS",
				Status: st,
				Details: []TopologyKV{
					{Key: "名称", Value: topoOr(p.Name, "对端 NAS")},
					{Key: "隧道地址", Value: topoJoin(tunnelAddrsOf(iface, p), "未知")},
					{Key: "对外地址", Value: topoOr(p.EndpointString(), "未填写（由本机发起时才有）")},
					{Key: "状态", Value: topoPeerStateLabel(p)},
					{Key: "最近通信", Value: topoHandshakeLabel(p)},
					{Key: "连接", Value: ifaceName},
					{Key: "对端内网", Value: topoJoin(siteSubnetsOf(iface, p), "未配置")},
					{
						Key: "说明",
						Value: "对端内网里的设备明细看不到：对端 NAS 会把它们的源地址改写成隧道地址，" +
							"要看明细得到对端 NAS 的拓扑页",
					},
				},
			})
			link(TopologyLink{
				From: topoID(TopoNodeNAS), To: siteID, Kind: TopoLinkSite,
				Label: ifaceName, Status: st, Rate: p.RxRate + p.TxRate,
			})
			for _, cidr := range siteSubnetsOf(iface, p) {
				id := topoID(TopoNodeSiteLAN, fmt.Sprint(p.ID), cidr)
				add(TopologyNode{
					ID: id, Kind: TopoNodeSiteLAN, Label: cidr, Sublabel: "对端内网", Status: st,
					Details: []TopologyKV{
						{Key: "网段", Value: cidr},
						{Key: "归属", Value: "另一台 NAS（" + topoOr(p.Name, "对端") + "）所在的内网"},
						{Key: "说明", Value: "这里的设备明细在对端 NAS 上，本机只能看到整段网段"},
					},
				})
				link(TopologyLink{From: siteID, To: id, Kind: TopoLinkSiteLAN, Status: st})
			}
			continue
		}

		tunnels++
		devID := topoID(TopoNodeDevice, fmt.Sprint(p.ID))
		st := "ok"
		switch {
		case !p.Enabled:
			st = "off"
		case p.Online:
			st = "ok"
		default:
			st = "warn"
		}
		add(TopologyNode{
			ID: devID, Kind: TopoNodeDevice, Label: topoOr(p.Name, "未命名设备"), Sublabel: topoJoin(tunnelAddrsOf(iface, p), ""),
			Status: st,
			Details: []TopologyKV{
				{Key: "名称", Value: topoOr(p.Name, "未命名设备")},
				{Key: "隧道地址", Value: topoJoin(tunnelAddrsOf(iface, p), "未知")},
				{Key: "连接", Value: ifaceName},
				{Key: "状态", Value: topoPeerStateLabel(p)},
				{Key: "最近通信", Value: topoHandshakeLabel(p)},
				{Key: "累计流量", Value: fmt.Sprintf("↓ %s　↑ %s", humanBytes(p.RxBytes), humanBytes(p.TxBytes))},
				{Key: "上网方式", Value: topoRouteModeLabel(p.RouteMode)},
				{Key: "内网访问", Value: topoLanPolicyLabel(p)},
				{Key: "备注", Value: topoOr(p.Remark, p.GroupTag)},
			},
		})
		link(TopologyLink{
			From: topoID(TopoNodeNAS), To: devID, Kind: TopoLinkTunnel,
			Label: ifaceName, Status: st, Rate: p.RxRate + p.TxRate,
		})
	}

	// ④ 疑似残留网卡（不属于本应用的 WireGuard 网卡）
	for _, fi := range f.Foreign {
		id := topoID(TopoNodeForeign, fi.Name)
		add(TopologyNode{
			ID: id, Kind: TopoNodeForeign, Label: fi.Name, Sublabel: "疑似残留", Status: "warn",
			Details: []TopologyKV{
				{Key: "名称", Value: fi.Name},
				{Key: "监听端口", Value: topoOr(fmt.Sprint(fi.ListenPort), "未监听")},
				{Key: "节点数", Value: fmt.Sprint(fi.PeerCount)},
				{Key: "地址", Value: topoJoin(fi.Addresses, "无")},
				{Key: "说明", Value: "不是本应用创建的 WireGuard 网卡；它占用的端口会让新连接用不了，确认无用后可到「系统维护」清理"},
			},
		})
		link(TopologyLink{From: topoID(TopoNodeNAS), To: id, Kind: TopoLinkForeign, Status: "warn"})
	}

	// ⑤ 说明：图上画了什么、哪些看不到
	g.Notes = append(g.Notes, "内网设备来自 NAS 的内核邻居表：只显示「最近和 NAS 通信过」的机器，不是全网扫描的结果。")
	if known < len(devices) {
		g.Notes = append(g.Notes, "想让设备显示名字：到「系统设置 → 内网域名」给它登记一条记录即可。")
	}
	if f.LAN != nil && !f.LAN.Readable {
		g.Notes = append(g.Notes, "这次没能读到内网设备："+topoOr(f.LAN.Reason, "原因未知"))
	}
	if f.LAN != nil && f.LAN.Demo {
		g.Notes = append(g.Notes, "当前是演示模式：内网设备是样板数据，不是真实网络里的机器。")
	}
	if sites > 0 {
		g.Notes = append(g.Notes, "对端内网的设备明细在对面那台 NAS 上（对端会改写源地址，这边看不到细节）。")
	}
	if len(f.HomeSubnets) == 0 {
		g.Notes = append(g.Notes, "没有探测到内网网段：可在「系统设置 → 接入设置」里手工填写「家里网段」。")
	}
	_ = tunnels
	return g
}

// topoLANFor 找出某个地址落在哪个内网网段上（返回该网段节点的 ID）。
func topoLANFor(lanIDs map[string]string, subnets []string, ip string) string {
	for _, cidr := range subnets {
		if cidrOverlaps(cidr, ip+"/32") {
			return lanIDs[cidr]
		}
	}
	return ""
}

// topoInterfaceOf 按 ID 找连接。
func topoInterfaceOf(ifaces []model.Interface, id int64) *model.Interface {
	for i := range ifaces {
		if ifaces[i].ID == id {
			return &ifaces[i]
		}
	}
	return nil
}

func ifaceNameOf(it *model.Interface) string {
	if it == nil {
		return "未知连接"
	}
	name := it.Name
	if !it.Enabled {
		name += "（已停用）"
	}
	return name
}

// tunnelAddrsOf 取设备在隧道里的地址：准入地址里落在本连接隧道网段内的那些（通常是 /32）。
func tunnelAddrsOf(iface *model.Interface, p *model.Peer) []string {
	if iface == nil {
		return nil
	}
	tunnel := subnetListOf(iface)
	out := []string{}
	for _, a := range p.AllowedIPs {
		if subnetInAny(tunnel, a) {
			out = append(out, a)
		}
	}
	return out
}

// siteSubnetsOf 取对端内网网段：准入地址里落在隧道之外的那些。
func siteSubnetsOf(iface *model.Interface, p *model.Peer) []string {
	tunnel := subnetListOf(iface)
	out := []string{}
	for _, a := range p.AllowedIPs {
		if subnetInAny(tunnel, a) {
			continue
		}
		if cidr := subnetOf(a); cidr != "" {
			out = append(out, cidr)
		}
	}
	sort.Strings(out)
	return out
}

func subnetListOf(it *model.Interface) []string {
	out := []string{}
	for _, a := range it.Addresses {
		if cidr := subnetOf(a); cidr != "" {
			out = append(out, cidr)
		}
	}
	return out
}

func subnetInAny(subnets []string, cidr string) bool {
	for _, s := range subnets {
		if cidrOverlaps(s, cidr) {
			return true
		}
	}
	return false
}

// isSitePeer 判断这条设备是不是「另一台 NAS」（互联向导写入的站点设备）。
//
// 判据用备注前缀：互联时写的就是它（见 InterconnectRemark），
// 与「重复导入同一份邀请」的识别共用同一个标记。
func isSitePeer(p *model.Peer) bool {
	return strings.HasPrefix(strings.TrimSpace(p.Remark), InterconnectRemark)
}

func topoHostStatus(state string) string {
	switch strings.ToLower(state) {
	case "reachable":
		return "ok"
	case "stale", "delay", "probe":
		return "warn"
	default:
		return "off"
	}
}

func topoHostStateLabel(state string) string {
	switch strings.ToLower(state) {
	case "reachable":
		return "可达（最近有过通信）"
	case "stale", "delay", "probe":
		return "待确认（邻居表里的记录已过期）"
	case "":
		return "未知"
	default:
		return state
	}
}

func topoPeerStateLabel(p *model.Peer) string {
	switch {
	case !p.Enabled && p.DisabledReason == "quota":
		return "已停用（流量用尽）"
	case !p.Enabled && p.DisabledReason == "expire":
		return "已停用（已到期）"
	case !p.Enabled:
		return "已停用"
	case p.Online:
		return "在线"
	default:
		return "离线"
	}
}

func topoHandshakeLabel(p *model.Peer) string {
	if p.LastHandshake.IsZero() {
		return "从未"
	}
	return timeAgo(p.LastHandshake)
}

func topoRouteModeLabel(mode string) string {
	switch mode {
	case model.RouteModeFull:
		return "全部流量走连接"
	case model.RouteModeCustom:
		return "自定义范围"
	default:
		return "只访问家里设备"
	}
}

// topoLanPolicyLabel 说明这台设备实际能访问内网的哪些目标。
func topoLanPolicyLabel(p *model.Peer) string {
	switch p.LANPolicy {
	case model.LANPolicyDeny:
		return "不允许访问内网"
	case model.LANPolicyRestrict:
		return "只允许：" + topoJoin(p.LANTargets, "未填写")
	default:
		return "随连接（可访问整个内网）"
	}
}

func topoJoin(list []string, empty string) string {
	if len(list) == 0 {
		return empty
	}
	return strings.Join(list, "、")
}

func topoOr(v, fallback string) string {
	if strings.TrimSpace(v) == "" {
		return fallback
	}
	return v
}

// Topology 组装一张当前网络拓扑的快照（只读）。
//
// 任何一路取数失败都不该让整张图消失：能画多少画多少，并在说明里写清哪一部分没读到 ——
// 一张空白的拓扑图比一张「缺一块但有说明」的更没用。
func (s *Service) Topology(ctx context.Context) *TopologyGraph {
	f := topologyFacts{DNSNames: map[string]string{}, DNSNotes: map[string]string{}, Kinds: map[string]string{}}

	if name, err := os.Hostname(); err == nil {
		f.HostName = strings.TrimSpace(name)
	}
	f.HomeSubnets = s.homeLANSubnets(ctx)

	if ov, err := s.GetOverview(ctx); err == nil {
		f.Interfaces = ov.Interfaces
		if s.Cache != nil {
			peers, err := s.Store.ListPeers(ctx, 0)
			if err == nil {
				s.Cache.EnrichPeers(peers)
				f.Peers = peers
			}
		}
	}
	if net, err := s.CheckNetwork(ctx); err == nil && net != nil {
		if len(net.HomeSubnets) > 0 {
			f.HomeSubnets = net.HomeSubnets
		}
		f.WANs = net.NAT.WANs
		f.Foreign = net.ForeignInterfaces
	}
	if rep, err := s.Core.LANDevices(ctx); err == nil {
		f.LAN = rep
	} else {
		f.LAN = &model.LANReport{Reason: err.Error()}
	}
	// 内网域名的登记记录：把 IP 换成用户认得的名字（没登记就显示地址）
	if recs, err := s.Store.ListDNSRecords(ctx); err == nil {
		for _, r := range recs {
			if ip := strings.TrimSpace(r.IP); ip != "" {
				f.DNSNames[ip] = strings.TrimSpace(r.Name)
				f.DNSNotes[ip] = strings.TrimSpace(r.Note)
			}
		}
	}
	f.Kinds = s.DeviceKinds(ctx)
	g := buildTopology(f)
	return &g
}

// timeAgo 用「多久以前」描述时间（拓扑卡的悬停信息里比绝对时间好读）。
func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "从未"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "刚刚"
	case d < time.Hour:
		return fmt.Sprintf("%d 分钟前", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d 小时前", int(d.Hours()))
	default:
		return fmt.Sprintf("%d 天前", int(d.Hours()/24))
	}
}

// humanBytes 把字节数写成便于阅读的形式（与前端 formatBytes 同一口径的简化版）。
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n)
	idx := -1
	for v >= unit && idx < len(units)-1 {
		v /= unit
		idx++
	}
	return fmt.Sprintf("%.1f %s", v, units[idx])
}
