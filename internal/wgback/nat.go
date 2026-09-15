//go:build linux

package wgback

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"

	"fnwg/internal/model"
)

// 本文件用 nftables 落地「允许设备访问家里内网」。
//
// 规则只写在**本应用专用的表**里：
//
//	table inet fn-wireguard {
//	    chain fnwg_forward      { type filter hook forward      priority filter; }
//	    chain fnwg_postrouting  { type nat    hook postrouting  priority srcnat; }
//	}
//
// 表内只有两类规则，全部限定「源地址属于本应用的隧道网段」：
//
//	ip saddr <隧道网段> accept                          # 转发放行
//	ip saddr <隧道网段> oifname "<出口网卡>" masquerade  # 源地址改写
//
// 因为匹配条件里带了源网段，NAS 自身流量的源地址是局域网地址，永远匹配不到，
// 所以 FN Connect / 应用市场 / Docker 等系统功能完全不受影响。
//
// 关闭开关时整表删除（表是我们的，删除它即可完全撤销），不需要逐条跟踪。
const (
	// natTableName 是本应用专用的 nftables 表名。
	natTableName = "fn-wireguard"
	// natForwardChain / natPostChain 是表内两个链的名字。
	natForwardChain = "fnwg_forward"
	natPostChain    = "fnwg_postrouting"
	// ifNameSize 与内核 IFNAMSIZ 一致，匹配 oifname 时需要补齐到该长度。
	ifNameSize = 16
)

// natMarker 打在本应用创建的规则上（UserData），用于精确识别与删除。
// 绝不依赖「位置」或「内容猜测」去删系统的规则。
var natMarker = []byte("fnwg-nat")

func nftConn() (*nftables.Conn, error) {
	c, err := nftables.New()
	if err != nil {
		return nil, fmt.Errorf("连接 nftables 失败（请确认内核支持 nf_tables 且拥有 CAP_NET_ADMIN）: %w", err)
	}
	return c, nil
}

// findNATTable 查找本应用专用表；不存在返回 nil。
func findNATTable(c *nftables.Conn) (*nftables.Table, error) {
	tables, err := c.ListTables()
	if err != nil {
		return nil, err
	}
	for _, t := range tables {
		if t.Name == natTableName && t.Family == nftables.TableFamilyINet {
			return t, nil
		}
	}
	return nil, nil
}

// matchSrcIPv4 生成「ip saddr <cidr>」的匹配表达式；IPv6 返回 nil（暂不支持）。
func matchSrcIPv4(n *net.IPNet) []expr.Any { return matchIPv4(n, true) }

// matchDstIPv4 生成「ip daddr <cidr>」的匹配表达式（回程方向使用）。
func matchDstIPv4(n *net.IPNet) []expr.Any { return matchIPv4(n, false) }

func matchIPv4(n *net.IPNet, src bool) []expr.Any {
	if n == nil || n.IP.To4() == nil {
		return nil
	}
	mask := n.Mask
	if len(mask) == 16 {
		mask = mask[12:]
	}
	if len(mask) != 4 {
		return nil
	}
	network := n.IP.Mask(n.Mask).To4()
	if network == nil {
		return nil
	}
	offset := uint32(16) // ip daddr
	if src {
		offset = 12 // ip saddr
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: 4},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: network},
	}
}

// matchOifName 生成「oifname "<name>"」的匹配表达式。
func matchOifName(name string) []expr.Any {
	return matchIfName(expr.MetaKeyOIFNAME, name)
}

// matchIIfName 生成「iifname "<name>"」的匹配表达式。
func matchIIfName(name string) []expr.Any {
	return matchIfName(expr.MetaKeyIIFNAME, name)
}

func matchIfName(key expr.MetaKey, name string) []expr.Any {
	buf := make([]byte, ifNameSize)
	copy(buf, name)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: buf},
	}
}

// parseIPNet 解析 CIDR 并返回网段（保留主机位，由调用方按需 mask）。
func parseIPNet(cidr string) (*net.IPNet, error) {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return nil, fmt.Errorf("网段 %q 非法: %w", cidr, err)
	}
	return n, nil
}

// syncNATLocked 让专用表里的规则（内网访问 + 设备间隔离）与全部连接的期望态一致。
func (b *kernelBackend) syncNATLocked(specs []model.InterfaceSpec, opts ApplyOptions, diff *Diff) {
	plan, requested, isolateRequested := b.planNATLocked(specs)

	if opts.DryRun {
		if plan.Enable {
			diff.Append("（预演）将启用内网访问：%s", DescribeNAT(plan))
		}
		if plan.Isolate {
			diff.Append("（预演）将启用设备间隔离：%s", DescribeIsolation(plan))
		}
		return
	}

	// 记录两组「开关是否打开」与「未能生效的原因」，供界面逐层诊断：
	// 用户看到的现象只是「连上了但访问不了家里其它设备」或「设备之间还能互访」，
	// 卡在哪一层必须能一句话说清，否则用户只会反复检查那些其实已经打开的开关。
	// 内容不变时 Save 不会产生磁盘写入，稳态下不会带来额外 IO。
	b.state.SetNATState(requested, plan.SkipReason)
	if isolateRequested {
		b.state.SetIsolateState(true, plan.IsolateSources, plan.IsolateReason)
	} else {
		b.state.SetIsolateState(false, nil, "")
	}
	_ = b.state.Save()

	fingerprint := plan.Fingerprint()

	// 转发开关必须**每轮**确认，不能只在重建规则时检查：
	// 从旧版本升级上来时规则内容没有变化，会走「无需重建」分支，
	// 若不在这里确认，之前没开过的内核转发就永远不会被打开，修复等于没生效。
	//
	// 只在真的要做内网转发时才开：设备间隔离不需要转发开关，
	// 不应该因为一个隔离开关就去改内核的全局设置。
	if plan.Enable {
		turned, err := b.ensureIPForward()
		if err != nil {
			diff.Append("启用内网访问失败：%v", err)
			return
		}
		if turned {
			b.state.SetIPForwardByUs(true)
			diff.Append("已开启内核转发（net.ipv4.ip_forward=1）：否则数据包在转发前就会被内核丢弃")
		}
	}

	// 规则内容与内核现状都一致时才跳过；否则重建。
	// 顺带也修复了「规则被其它工具清理掉」的情况。
	if fingerprint != "" && fingerprint == b.state.NATFingerprint() && b.rulesPresent(plan) {
		return
	}

	// 内容有变化（或需要关闭）：先把上一次留下的痕迹全部撤掉，再按当前决策重建
	removed := b.clearNATLocked()

	if plan.Empty() {
		b.state.SetNAT("", nil, nil)
		_ = b.state.Save()
		if removed {
			diff.Append("已关闭内网访问与设备间隔离，相关规则已移除")
		}
		if plan.SkipReason != "" {
			diff.Append("内网访问未启用：%s", plan.SkipReason)
		}
		if plan.IsolateReason != "" {
			diff.Append("设备间隔离未生效：%s", plan.IsolateReason)
		}
		return
	}

	if err := b.ensureNATTableLocked(plan); err != nil {
		diff.Append("下发转发规则失败：%v", err)
		return
	}
	b.state.SetNAT(fingerprint, plan.Sources, plan.WANs)
	_ = b.state.Save()
	if plan.Enable {
		diff.Append("已启用内网访问：%s", DescribeNAT(plan))
	}
	if plan.Isolate {
		diff.Append("%s", DescribeIsolation(plan))
	}
}

// planNATLocked 依据全部连接计算内网访问与设备隔离决策。
//
// 后两个返回值分别表示「是否有连接打开了内网访问开关」与「是否有连接打开了
// 设备间隔离开关」。开关是用户意图，规则是否真的生效取决于环境条件，
// 两者分开表达，界面才能说清卡在哪一层。
func (b *kernelBackend) planNATLocked(specs []model.InterfaceSpec) (NATPlan, bool, bool) {
	sources := []string{}
	isoSources := []string{}
	tunnels := []string{}
	anyLAN := false
	anyIsolate := false
	for _, s := range specs {
		if !s.Up {
			// 没启用的连接里不可能有设备，它的网段既不需要放行也不需要隔离。
			continue
		}
		subnets := specSubnets(s)
		tunnels = append(tunnels, subnets...)
		if s.IsolatePeers {
			anyIsolate = true
			isoSources = append(isoSources, subnets...)
		}
		if s.AllowLAN {
			anyLAN = true
			sources = append(sources, subnets...)
		}
	}

	input := NATPlanInput{
		Enabled:          anyLAN,
		SourceSubnets:    sources,
		TunnelInterfaces: b.state.ManagedCopy(),
		IsolateRequested: anyIsolate,
		IsolateSubnets:   isoSources,
		TunnelSubnets:    tunnels,
	}
	// 出口网卡与主机网段只在真的要做内网访问时才去探测：
	// 它们都要读内核路由表，没必要每 10 秒为一个没打开的开关付这份代价。
	if anyLAN {
		input.WANInterfaces, input.WANReason = b.wanInterfacesLocked()
		input.HostNetworks = b.hostNetworksLocked()
	}
	return PlanNAT(input), anyLAN, anyIsolate
}

// specSubnets 返回一条连接的全部隧道网段（已做掩码归一化）。
func specSubnets(s model.InterfaceSpec) []string {
	out := []string{}
	for _, a := range s.Addresses {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(a)); err == nil {
			out = append(out, maskedCIDR(n))
		}
	}
	return out
}

// wanInterfacesLocked 返回可用作转发出口的网卡（排除隧道网卡），
// 并给出探测不到时的**具体**原因，供界面直接展示。
//
// 探测分两步，第二步只在第一步无解时执行：
//
//	① 扫描内核路由表里的默认路由（含全部路由表）；
//	② 让内核自己做一次路由查询（UDP socket 不发送任何数据包），再把结果
//	   源地址映射回网卡。有些环境里「默认路由」并不是一条 dst_len 为 0 的
//	   条目（nexthop 对象、ip rule 策略路由），只有这步才问得出来真正的出口。
func (b *kernelBackend) wanInterfacesLocked() ([]string, string) {
	cands := b.routeWANCandidatesLocked()
	wans, reason := PickWANs(cands)
	if len(wans) > 0 {
		return wans, ""
	}
	if dev := probeEgressDevLocked(); dev != "" {
		cands = append(cands, b.classifyWANLocked(dev, true))
		if viaProbe, _ := PickWANs(cands); len(viaProbe) > 0 {
			return viaProbe, ""
		}
	}
	return nil, reason
}

// routeWANCandidatesLocked 把路由表里的默认路由转成候选事实。
func (b *kernelBackend) routeWANCandidatesLocked() []WANCandidate {
	cands := []WANCandidate{}
	for _, r := range defaultRoutesLocked() {
		dev := routeDevName(r)
		if dev == "" {
			cands = append(cands, WANCandidate{})
			continue
		}
		cands = append(cands, b.classifyWANLocked(dev, false))
	}
	if !hasResolvedWAN(cands) {
		// netlink 一条默认路由都没能定位到网卡时的兜底：/proc/net/route 是内核的直接快照
		for _, dev := range defaultDevsFromProc() {
			cands = append(cands, b.classifyWANLocked(dev, false))
		}
	}
	return cands
}

// hasResolvedWAN 判断候选里是否至少有一条能定位到具体网卡。
func hasResolvedWAN(cands []WANCandidate) bool {
	for _, c := range cands {
		if c.Dev != "" {
			return true
		}
	}
	return false
}

// classifyWANLocked 把网卡名转成候选事实：是否是隧道、是否处于启用状态。
func (b *kernelBackend) classifyWANLocked(name string, fromProbe bool) WANCandidate {
	c := WANCandidate{Dev: name, Up: true, FromProbe: fromProbe}
	if l, err := netlink.LinkByName(name); err == nil {
		c.Up = l.Attrs().Flags&net.FlagUp != 0
		if l.Type() == "wireguard" {
			// 内核里类型为 wireguard 的网卡（包括不是本应用创建的历史残留）
			// 一律不能作为转发出口，否则设备流量会被再塞回隧道。
			c.Tunnel = true
		}
	}
	if b.state.IsManaged(name) {
		c.Tunnel = true
	}
	return c
}

// defaultRoutesLocked 读取系统**全部路由表**中的默认路由。
//
// 两个关键点，缺一个就会出现「明明有默认网关却探测不到出口网卡」：
//  1. 必须显式走 eachRoute（带表过滤的通配值）：netlink 库默认会跳过非 main 表，
//     而默认路由并不一定放在 main 表 —— 策略路由、多出口分流都会放到自定义表里。
//  2. 用 Iter 版本：内核在 dump 途中被打断（NLM_F_DUMP_INTR，例如 Docker 正在
//     增删路由）时，已读到的部分仍会逐条交给我们，而不是整批丢弃。
func defaultRoutesLocked() []netlink.Route {
	out := []netlink.Route{}
	_ = eachRoute(netlink.FAMILY_V4, func(r netlink.Route) {
		if isDefaultRoute(r) {
			out = append(out, r)
		}
	})
	return out
}

// isDefaultRoute 判断一条路由是否为默认路由。
//
// 大多数内核在 dump 时会省略 RTA_DST（Dst 为 nil），但并非所有内核都如此，
// 因此这里同时接受「Dst 为 nil」与「前缀长度为 0」两种形态。
func isDefaultRoute(r netlink.Route) bool {
	if r.Dst == nil {
		return true
	}
	ones, _ := r.Dst.Mask.Size()
	return ones == 0
}

// routeDevName 解析一条路由对应的网卡名，兼容普通路由与多路径（ECMP）路由。
func routeDevName(r netlink.Route) string {
	if r.LinkIndex != 0 {
		if l, err := netlink.LinkByIndex(r.LinkIndex); err == nil {
			return l.Attrs().Name
		}
	}
	for _, nh := range r.MultiPath {
		if nh == nil || nh.LinkIndex == 0 {
			continue
		}
		if l, err := netlink.LinkByIndex(nh.LinkIndex); err == nil {
			return l.Attrs().Name
		}
	}
	return ""
}

// defaultDevsFromProc 读取 /proc/net/route 里默认路由的网卡名。
// 作为最后一道兜底：极少数环境下 netlink 读不到，但这里一定能读到。
func defaultDevsFromProc() []string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return nil
	}
	out := []string{}
	for i, line := range strings.Split(string(raw), "\n") {
		if i == 0 { // 表头
			continue
		}
		// 字段：Iface Destination Gateway Flags RefCnt Use Metric Mask MTU ...
		// 默认路由的 Destination 与 Mask 都是全 0。
		fields := strings.Fields(line)
		if len(fields) < 8 || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		if !contains(out, fields[0]) {
			out = append(out, fields[0])
		}
	}
	return out
}

// probeEgressDevLocked 让内核自己回答「出口网卡是谁」。
//
// 连一个 UDP socket 到公网地址并不会发出任何数据包，只是让内核查一次路由表；
// 读回它选定的源地址，再按地址找到所属网卡。相比自己扫描路由表，
// 这种方式天然覆盖 ip rule 策略路由与 nexthop 对象等复杂配置。
func probeEgressDevLocked() string {
	links, err := netlink.LinkList()
	if err != nil {
		return ""
	}
	for _, dst := range []string{"223.5.5.5:53", "1.1.1.1:53", "8.8.8.8:53"} {
		conn, err := net.Dial("udp4", dst)
		if err != nil {
			continue
		}
		local, _ := conn.LocalAddr().(*net.UDPAddr)
		_ = conn.Close()
		if local == nil || local.IP == nil {
			continue
		}
		for _, l := range links {
			addrs, err := netlink.AddrList(l, netlink.FAMILY_V4)
			if err != nil {
				continue
			}
			for _, a := range addrs {
				if a.IPNet != nil && a.IPNet.IP.Equal(local.IP) {
					return l.Attrs().Name
				}
			}
		}
	}
	return ""
}

// hostNetworksLocked 返回主机上除本应用隧道之外的全部网段，用于冲突检测。
func (b *kernelBackend) hostNetworksLocked() []string {
	out := []string{}
	links, err := netlink.LinkList()
	if err != nil {
		return out
	}
	for _, l := range links {
		if b.state.IsManaged(l.Attrs().Name) {
			continue
		}
		addrs, err := netlink.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if a.IPNet == nil || a.IPNet.IP.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, maskedCIDR(a.IPNet))
		}
	}
	return out
}

// ensureNATTableLocked 按决策重建专用表。
// 表完全属于本应用，因此用「整表重建」保证结果确定，无需逐条跟踪。
func (b *kernelBackend) ensureNATTableLocked(plan NATPlan) error {
	c, err := nftConn()
	if err != nil {
		return err
	}

	// 旧表已在 clearNATLocked 中删除，这里直接重建
	tbl := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: natTableName})

	// 转发放行链。注意：本链的 accept 不会覆盖系统链里的 drop
	//（nftables 中 accept 只对当前基链生效，之后的基链仍会继续判定），
	// 因此它的作用是把本应用的意图写在明处；真正决定成败的是系统链的策略，
	// 由 ensureSystemForwardLocked 处理。
	fwd := c.AddChain(&nftables.Chain{
		Table:    tbl,
		Name:     natForwardChain,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
	})
	post := c.AddChain(&nftables.Chain{
		Table:    tbl,
		Name:     natPostChain,
		Type:     nftables.ChainTypeNAT,
		Hooknum:  nftables.ChainHookPostrouting,
		Priority: nftables.ChainPriorityNATSource,
	})

	// 隔离规则必须排在最前面：nftables 以「第一条匹配的规则」作为终局判定，
	// 若把它们放在后面的放行规则之后，丢弃永远轮不到生效，
	// 用户看到的就是「隔离开关打开了但设备还能互访」。
	isoApplied := addIsolationRules(c, tbl, fwd, plan)

	applied := 0
	for _, src := range plan.Sources {
		n, err := parseIPNet(src)
		if err != nil {
			continue
		}
		out := matchSrcIPv4(n)
		if len(out) == 0 {
			continue
		}
		applied++
		// 出方向：设备 → 家里内网
		c.AddRule(&nftables.Rule{
			Table:    tbl,
			Chain:    fwd,
			Exprs:    append(append([]expr.Any{}, out...), &expr.Verdict{Kind: expr.VerdictAccept}),
			UserData: natMarker,
		})
		for _, wan := range plan.WANs {
			// 回程：家里内网 → 设备。
			// 少了这条，回包会被转发链丢掉，表现为「有去无回、ping 不通」。
			back := matchIIfName(wan)
			back = append(back, matchDstIPv4(n)...)
			c.AddRule(&nftables.Rule{
				Table:    tbl,
				Chain:    fwd,
				Exprs:    append(back, &expr.Verdict{Kind: expr.VerdictAccept}),
				UserData: natMarker,
			})
			// 源地址改写
			ex := append([]expr.Any{}, out...)
			ex = append(ex, matchOifName(wan)...)
			ex = append(ex, &expr.Masq{})
			c.AddRule(&nftables.Rule{
				Table:    tbl,
				Chain:    post,
				Exprs:    ex,
				UserData: natMarker,
			})
		}
	}
	if applied == 0 && isoApplied == 0 {
		c.DelTable(tbl)
		_ = c.Flush()
		return fmt.Errorf("没有可用的 IPv4 隧道网段")
	}
	if err := c.Flush(); err != nil {
		return fmt.Errorf("下发转发规则失败: %w", err)
	}
	if !plan.Enable {
		// 只下发了隔离规则：系统转发链的兜底放行是为「设备访问内网」准备的，
		// 这里既不需要，往里插放行规则还会削弱隔离的语义。
		return nil
	}
	return b.ensureSystemForwardLocked(c, plan)
}

// addIsolationRules 写入设备间隔离规则，返回实际写入的条数。
//
// 每条规则形如：
//
//	ip saddr <被隔离的隧道网段> ip daddr <隧道网段> drop
//
// 用 drop 而不是 reject：drop 在所有内核版本上行为一致，也不需要内核生成 ICMP
// 差错报文（在转发路径上生成 ICMP 依赖 conntrack 与内核版本，失败时更难排查）。
// 代价是设备侧表现为「超时」而不是「立即拒绝」，这个取舍是有意为之。
func addIsolationRules(c *nftables.Conn, tbl *nftables.Table, chain *nftables.Chain, plan NATPlan) int {
	n := 0
	for _, pair := range plan.IsolationRules() {
		from, err := parseIPNet(pair[0])
		if err != nil {
			continue
		}
		to, err := parseIPNet(pair[1])
		if err != nil {
			continue
		}
		ex := matchSrcIPv4(from)
		ex = append(ex, matchDstIPv4(to)...)
		if len(ex) == 0 {
			continue
		}
		c.AddRule(&nftables.Rule{
			Table:    tbl,
			Chain:    chain,
			Exprs:    append(ex, &expr.Verdict{Kind: expr.VerdictDrop}),
			UserData: natMarker,
		})
		n++
	}
	return n
}

const ipForwardPath = "/proc/sys/net/ipv4/ip_forward"

// ipForwardEnabled 读取内核是否允许转发。
func ipForwardEnabled() bool {
	raw, err := os.ReadFile(ipForwardPath)
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(raw)) == "1"
}

// ensureIPForward 确保内核允许转发，返回是否由本次调用开启。
//
// 这一步不可省略：转发关闭时，数据包在进入 FORWARD 链之前就被内核丢掉了，
// NAT 规则写得再对也没有用（表现为「开关开了但还是不通」）。
//
// 这是内核的全局开关，但 NAS 自身的流量不经过转发路径，所以开启它不会影响
// 系统自身的网络；装过 Docker 的机器上通常本来就是开着的。
// 出于安全考虑，本应用只负责开启、不负责还原（关闭内网访问后仍保持开启），
// 以免影响机器上其它依赖转发的服务。
func (b *kernelBackend) ensureIPForward() (bool, error) {
	if ipForwardEnabled() {
		return false, nil
	}
	if err := os.WriteFile(ipForwardPath, []byte("1\n"), 0o644); err != nil {
		return false, fmt.Errorf("内核未开启转发，且写入 %s 失败: %w", ipForwardPath, err)
	}
	return true, nil
}

// ensureSystemForwardLocked 处理「系统转发链策略为丢弃」的情况。
//
// 装过 Docker 的机器上，FORWARD 链的策略常常被改成 drop。此时本应用独立表里的
// 放行规则**也会被丢弃**（drop 是终局判定），必须往系统链里插一条放行。
//
// 这条规则严格限定源地址为本应用的隧道网段，所以：
//   - NAS 自身流量的源地址是局域网地址，匹配不到；
//   - 不会给任何其它来源的转发流量增加可达性。
//
// 规则带 UserData 标记，关闭开关时按标记精确删除，绝不误删系统自己的规则。
func (b *kernelBackend) ensureSystemForwardLocked(c *nftables.Conn, plan NATPlan) error {
	tables, err := c.ListTables()
	if err != nil {
		return nil // 读不到系统表就不额外处理，也不阻断内网访问本身
	}
	added := false
	for _, t := range tables {
		if t.Family != nftables.TableFamilyIPv4 && t.Family != nftables.TableFamilyINet {
			continue
		}
		ch, err := c.ListChain(t, "FORWARD")
		if err != nil || ch == nil {
			continue
		}
		ch.Table = t
		if ch.Hooknum == nil || *ch.Hooknum != *nftables.ChainHookForward {
			continue
		}
		if ch.Policy == nil || *ch.Policy != nftables.ChainPolicyDrop {
			continue // 策略不是丢弃，无需额外放行
		}
		for _, src := range plan.Sources {
			n, err := parseIPNet(src)
			if err != nil {
				continue
			}
			out := matchSrcIPv4(n)
			if len(out) == 0 {
				continue
			}
			// 出方向：插到链首，确保在系统的丢弃逻辑之前生效
			c.InsertRule(&nftables.Rule{
				Table:    t,
				Chain:    ch,
				Exprs:    append(append([]expr.Any{}, out...), &expr.Verdict{Kind: expr.VerdictAccept}),
				UserData: natMarker,
			})
			// 回程方向：家里内网 → 设备。少了它，回包会被系统链丢掉。
			for _, wan := range plan.WANs {
				back := matchIIfName(wan)
				back = append(back, matchDstIPv4(n)...)
				c.InsertRule(&nftables.Rule{
					Table:    t,
					Chain:    ch,
					Exprs:    append(back, &expr.Verdict{Kind: expr.VerdictAccept}),
					UserData: natMarker,
				})
			}
			added = true
		}
	}
	if !added {
		return nil
	}
	return c.Flush()
}

// clearNATLocked 撤销本应用创建的全部内网访问痕迹：
// 专用表整表删除 + 系统转发链里带标记的放行规则。
// 返回是否真的删除过内容。
func (b *kernelBackend) clearNATLocked() bool {
	removed := false
	if n, err := b.removeSystemForwardRules(); err == nil && n > 0 {
		removed = true
	}
	if ok, err := b.removeNATTable(); err == nil && ok {
		removed = true
	}
	return removed
}

// removeNATTable 删除本应用专用表（连带其中所有链与规则）。
func (b *kernelBackend) removeNATTable() (bool, error) {
	c, err := nftConn()
	if err != nil {
		return false, err
	}
	t, err := findNATTable(c)
	if err != nil {
		return false, err
	}
	if t == nil {
		return false, nil
	}
	c.DelTable(t)
	if err := c.Flush(); err != nil {
		return false, err
	}
	return true, nil
}

// removeSystemForwardRules 删除系统转发链里由本应用插入的放行规则（按 UserData 标记识别）。
func (b *kernelBackend) removeSystemForwardRules() (int, error) {
	c, err := nftConn()
	if err != nil {
		return 0, err
	}
	tables, err := c.ListTables()
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, t := range tables {
		if t.Family != nftables.TableFamilyIPv4 && t.Family != nftables.TableFamilyINet {
			continue
		}
		ch, err := c.ListChain(t, "FORWARD")
		if err != nil || ch == nil {
			continue
		}
		rules, err := c.GetRules(t, ch)
		if err != nil {
			continue
		}
		for _, r := range rules {
			if !bytes.Equal(r.UserData, natMarker) {
				continue
			}
			if err := c.DelRule(r); err != nil {
				continue
			}
			removed++
		}
	}
	if removed > 0 {
		if err := c.Flush(); err != nil {
			return removed, err
		}
	}
	return removed, nil
}

// NATStatus 返回内网访问规则的实际状态。
func (b *kernelBackend) NATStatus() model.NATStatus {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.natStatusLocked()
}

// systemForwardPolicyDropLocked 判断系统的转发链是否会把本应用的转发流量丢掉。
// 装过 Docker 的机器上 FORWARD 策略常常是 drop。
func (b *kernelBackend) systemForwardPolicyDropLocked() bool {
	c, err := nftConn()
	if err != nil {
		return false
	}
	tables, err := c.ListTables()
	if err != nil {
		return false
	}
	for _, t := range tables {
		if t.Family != nftables.TableFamilyIPv4 && t.Family != nftables.TableFamilyINet {
			continue
		}
		ch, err := c.ListChain(t, "FORWARD")
		if err != nil || ch == nil {
			continue
		}
		if ch.Hooknum != nil && *ch.Hooknum == *nftables.ChainHookForward &&
			ch.Policy != nil && *ch.Policy == nftables.ChainPolicyDrop {
			return true
		}
	}
	return false
}

// natStatusLocked 汇总专用表的当前状态与逐项自检结果。
func (b *kernelBackend) natStatusLocked() model.NATStatus {
	st := model.NATStatus{
		Sources:              b.state.NATSources(),
		WANs:                 b.state.NATWANs(),
		IPForward:            ipForwardEnabled(),
		IPForwardEnabledByUs: b.state.IPForwardByUs(),
		IsolateNets:          b.state.IsolateNets(),
	}
	if st.Sources == nil {
		st.Sources = []string{}
	}
	if st.WANs == nil {
		st.WANs = []string{}
	}
	if st.IsolateNets == nil {
		st.IsolateNets = []string{}
	}

	notes := []string{}
	// 两类规则分别核对。「期望有规则」以状态里记录的实际生效内容为准，
	// 而不是只看指纹：只开了隔离时指纹也非空，但此时内核里本来就没有
	// postrouting 规则，用指纹判断会得出「转发规则不存在」的错误结论。
	if len(st.WANs) > 0 {
		rules, err := b.natRuleCount()
		switch {
		case err != nil:
			notes = append(notes, "无法读取转发规则状态："+err.Error())
		case rules == 0:
			notes = append(notes, "转发规则不存在（可能被其它工具清理过），修改任意连接或重新打开开关即可恢复")
		default:
			st.Active = true
		}
	}
	if len(st.IsolateNets) > 0 {
		rules, err := b.isoRuleCount()
		switch {
		case err != nil:
			notes = append(notes, "无法读取设备间隔离规则状态："+err.Error())
		case rules == 0:
			notes = append(notes, "设备间隔离规则不存在（可能被其它工具清理过），修改任意连接或重新打开开关即可恢复")
		default:
			st.IsolateActive = true
			st.IsolateRules = rules
		}
	}
	st.Note = strings.Join(notes, "；")
	st.Checks = b.natChecksLocked(st)
	return st
}

// rulesPresent 判断专用表里的规则是否与决策相符（可能被其它工具清理过）。
//
// 两类规则分别核对：内网访问写在 postrouting 链，设备隔离写在 forward 链。
// 只核对其中一类的话，「隔离开着、内网访问关着」这种组合会被误判成规则丢失，
// 于是每轮收敛都重建一次规则 —— 规则抖动正是之前花力气消除的问题。
func (b *kernelBackend) rulesPresent(plan NATPlan) bool {
	if plan.Enable {
		if n, err := b.natRuleCount(); err != nil || n == 0 {
			return false
		}
	}
	if plan.Isolate {
		if n, err := b.isoRuleCount(); err != nil || n == 0 {
			return false
		}
	}
	return true
}

// isoRuleCount 返回专用表转发链里「丢弃」类规则的条数，
// 用来确认隔离规则确实落到内核里了（而不是只看表存不存在）。
func (b *kernelBackend) isoRuleCount() (int, error) {
	c, err := nftConn()
	if err != nil {
		return 0, err
	}
	t, err := findNATTable(c)
	if err != nil || t == nil {
		return 0, err
	}
	ch, err := c.ListChain(t, natForwardChain)
	if err != nil || ch == nil {
		return 0, err
	}
	rules, err := c.GetRules(t, ch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range rules {
		for _, e := range r.Exprs {
			if v, ok := e.(*expr.Verdict); ok && v.Kind == expr.VerdictDrop {
				n++
				break
			}
		}
	}
	return n, nil
}

// natRuleCount 返回专用表里源地址改写链上的规则条数，用于确认规则确实落到内核里了。
func (b *kernelBackend) natRuleCount() (int, error) {
	c, err := nftConn()
	if err != nil {
		return 0, err
	}
	t, err := findNATTable(c)
	if err != nil || t == nil {
		return 0, err
	}
	ch, err := c.ListChain(t, natPostChain)
	if err != nil || ch == nil {
		return 0, err
	}
	rules, err := c.GetRules(t, ch)
	if err != nil {
		return 0, err
	}
	return len(rules), nil
}

// natChecksLocked 生成内网访问链路与设备间隔离的自检清单。
//
// 用户看到的现象只有两个（设备连上了但访问不了家里其它设备 / 设备之间还能互访），
// 但成因分好几层：规则没下发 / 内核转发关了 / 系统转发链拦了 / 出口网卡没认出来。
// 逐项列出来，用户就不必靠猜，也能直接告诉我们是哪一层出问题。
//
// 入参是已查好的状态（含内网访问与隔离两侧的事实），避免在这里重复读内核。
func (b *kernelBackend) natChecksLocked(st model.NATStatus) []model.NATCheck {
	checks := []model.NATCheck{}

	requested := b.state.NATSwitchOn()
	blocked := b.state.NATBlockedReason()
	wanted := len(st.WANs) > 0 // 内网访问规则此前是否已下发过
	active := st.Active

	// ① 转发规则
	switch {
	case !requested:
		checks = append(checks, model.NATCheck{
			Key: "rules", Label: "转发规则", OK: false,
			Detail: "尚未下发：没有已启用且打开了「内网访问」开关的连接",
			Fix:    "到「我的连接」把连接的「内网访问」开关打开",
		})
	case !wanted:
		// 开关确实开着，但条件不满足。这里必须如实说出原因：
		// 否则用户会以为「开关没打开」，反复去检查一个其实已经打开的开关。
		detail := "开关已打开，但规则未能下发"
		if blocked != "" {
			detail = "开关已打开，但规则未能下发：" + blocked
		}
		checks = append(checks, model.NATCheck{
			Key: "rules", Label: "转发规则", OK: false,
			Detail: detail,
			Fix:    "按上面的原因处理后本应用每 10 秒会自动重试，也可点「立即应用」马上重试一次",
		})
	case active:
		checks = append(checks, model.NATCheck{
			Key: "rules", Label: "转发规则", OK: true,
			Detail: fmt.Sprintf("已下发：%s → 出口 %s（已做源地址改写）",
				strings.Join(st.Sources, "、"), strings.Join(st.WANs, "、")),
		})
	default:
		checks = append(checks, model.NATCheck{
			Key: "rules", Label: "转发规则", OK: false,
			Detail: "规则内容与期望一致但内核里查不到（可能被其它工具清理过）",
			Fix:    "把该连接的开关关掉再打开，或点「立即应用」重建规则",
		})
	}

	// ② 内核转发开关（最容易被忽略的一层）
	if ipForwardEnabled() {
		checks = append(checks, model.NATCheck{
			Key: "ip_forward", Label: "内核转发", OK: true,
			Detail: "已开启（net.ipv4.ip_forward=1）",
		})
	} else {
		checks = append(checks, model.NATCheck{
			Key: "ip_forward", Label: "内核转发", OK: false,
			Detail: "未开启（net.ipv4.ip_forward=0）：数据包在进入转发规则之前就被内核丢弃，规则写得再对也没用",
			Fix:    "打开内网访问开关时本应用会自动开启；若始终失败请查看 agent 日志",
		})
	}

	// ③ 系统转发链策略
	if b.systemForwardPolicyDropLocked() {
		checks = append(checks, model.NATCheck{
			Key: "forward_policy", Label: "系统转发链", OK: true,
			Detail: "策略为「丢弃」（装过 Docker 的机器常见），本应用已为隧道网段单独放行了出入两个方向",
		})
	} else {
		checks = append(checks, model.NATCheck{
			Key: "forward_policy", Label: "系统转发链", OK: true,
			Detail: "策略为「放行」，无需额外处理",
		})
	}

	// ④ 出口网卡：只要开关是打开的就要给个明确结论，
	//    让用户能直接和 `ip route show default` 的输出对上。
	if len(st.WANs) > 0 {
		checks = append(checks, model.NATCheck{
			Key: "wan", Label: "出口网卡", OK: true,
			Detail: fmt.Sprintf("经 %s 转发到局域网", strings.Join(st.WANs, "、")),
		})
	} else if requested {
		live, reason := b.wanInterfacesLocked()
		if len(live) > 0 {
			checks = append(checks, model.NATCheck{
				Key: "wan", Label: "出口网卡", OK: true,
				Detail: fmt.Sprintf("已探测到 %s（转发规则尚未下发）", strings.Join(live, "、")),
			})
		} else {
			checks = append(checks, model.NATCheck{
				Key: "wan", Label: "出口网卡", OK: false,
				Detail: reason,
				Fix: "在 NAS 上执行 ip route show default 查看默认路由；" +
					"若确实没有默认网关，请到系统网络设置里补上后重试",
			})
		}
	}

	// ⑤ 设备间隔离：只在开关打开时展示，避免没用到这项功能的用户
	//    被一条「未启用」的条目干扰。
	if b.state.IsolateSwitchOn() {
		switch {
		case len(st.IsolateNets) == 0:
			reason := b.state.IsolateBlockedReason()
			if reason == "" {
				reason = "规则尚未下发"
			}
			checks = append(checks, model.NATCheck{
				Key: "isolate", Label: "设备间隔离", OK: false,
				Detail: "开关已打开，但隔离规则未生效：" + reason,
				Fix: "确认连接的「本机专用地址」是 IPv4 网段（目前只支持 IPv4）；" +
					"本应用每 10 秒会自动重试，也可点「立即应用」马上重试一次",
			})
		case !st.IsolateActive:
			checks = append(checks, model.NATCheck{
				Key: "isolate", Label: "设备间隔离", OK: false,
				Detail: "隔离规则内容与期望一致但内核里查不到（可能被其它工具清理过）",
				Fix:    "把该连接的「设备间隔离」开关关掉再打开，或点「立即应用」重建规则",
			})
		default:
			checks = append(checks, model.NATCheck{
				Key: "isolate", Label: "设备间隔离", OK: true,
				Detail: fmt.Sprintf("已隔离 %s：这些连接里的设备之间不能互访，但仍可访问 NAS 与内网（共 %d 条阻断规则）",
					strings.Join(st.IsolateNets, "、"), st.IsolateRules),
			})
		}
	}
	return checks
}
