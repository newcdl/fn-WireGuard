// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package wgback

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// 本文件决定两件相关但独立的事要怎么落地到同一张专用 nftables 表里：
//
//	① 「允许设备访问家里内网」——设备要能访问局域网里的其它机器；
//	② 「设备间隔离」——设备之间不能互相访问，但都可以访问 NAS 与内网。
//
// 为什么 ① 需要 NAT 转发：
//
//	设备把发往家里网段（例如 192.168.3.0/24）的包送进隧道后，NAS 要把它转发到局域网。
//	但局域网里的设备只认识自己所在的网段和默认网关（家里的路由器），
//	路由器并不知道隧道网段（10.x）在哪 → 回包被丢弃，表现为「能连上 NAS，
//	却访问不了家里其它设备」。所以必须由 NAS 做 SNAT：把源地址改写成
//	NAS 自己的局域网地址，回包自然回到 NAS，NAS 再转回隧道。
//
// 为什么 ② 用地址匹配就够了：
//
//	设备之间互访的包在 NAS 上是「进隧道、出隧道」，源与目标都落在隧道网段内。
//	而设备访问 NAS 自身走的是 input 路径（目标地址是本机，内核直接本地投递），
//	访问内网由 ① 的放行规则处理 —— 两者都不会被「隧道 → 隧道」的丢弃规则命中。
//	于是「源与目标都在隧道网段」这个条件本身就精确等价于「设备之间互相访问」，
//	既不需要用 iifname/oifname 去猜，也不会误伤 NAS 自身与回程流量。
//
// 安全边界（与 routesafety.go 同级的铁规则）：
//
//  1. 规则只写在**本应用专用的 nftables 表**里，绝不修改系统的任何表和规则；
//  2. 匹配条件限定源地址必须是本连接的隧道网段 —— NAS 自身流量的源地址是
//     局域网地址，永远匹配不到，因此 FN Connect / 应用市场 / Docker 完全不受影响；
//  3. 出口网卡限定为默认路由所在网卡，不使用通配符，也绝不用隧道网卡本身
//     （本应用创建的连接与内核里的其它 WireGuard 网卡一并排除）；
//  4. 关闭开关时整表删除，不留任何残余。

// NATPlanInput 是内网访问与设备隔离决策的全部输入。
type NATPlanInput struct {
	// Enabled 是连接上的「允许设备访问家里内网」开关。
	Enabled bool
	// SourceSubnets 需要被改写的源网段（各连接的隧道网段）。
	SourceSubnets []string
	// WANInterfaces 出口网卡（默认路由所在网卡）。
	WANInterfaces []string
	// WANReason 是数据面探测不到出口网卡时给出的**具体**原因，为空则使用内置通用提示。
	// 分具体原因是为了让用户知道该去查什么：没有默认路由、出口是隧道、网卡没启用，
	// 三种情况的处理方式完全不同。
	WANReason string
	// TunnelInterfaces 本应用创建的隧道网卡，用于排除「把隧道当出口」这种回环配置。
	TunnelInterfaces []string
	// HostNetworks 主机上其它网卡的网段，用于冲突检测。
	HostNetworks []string

	// IsolateRequested 表示是否有连接打开了「设备间隔离」开关。
	IsolateRequested bool
	// IsolateSubnets 是打开了隔离开关的连接各自的隧道网段。
	IsolateSubnets []string
	// TunnelSubnets 是**全部**已启用连接的隧道网段。
	//
	// 隔离范围要覆盖全部隧道，而不是只覆盖开了隔离的那一条：
	// 若只隔离 wg0，wg1 里的设备仍能访问 wg0 的设备，那隔离就是假的。
	TunnelSubnets []string
}

// NATPlan 是内网访问与设备隔离的落地决策。
type NATPlan struct {
	// Enable 是否启用内网访问。
	Enable bool
	// Sources 规范化后的源网段。
	Sources []string
	// WANs 出口网卡。
	WANs []string
	// SkipReason 是无法启用时的原因（面向用户，直接展示）。
	SkipReason string

	// Isolate 是否下发设备间隔离规则。
	//
	// 与 Enable 相互独立：内网访问可能因为探测不到出口网卡而无法启用，
	// 但隔离规则只依赖隧道网段，此时仍然必须照常下发与撤销。
	Isolate bool
	// IsolateSources 被隔离的隧道网段（用户打开了隔离开关的那些连接）。
	IsolateSources []string
	// TunnelSources 全部隧道网段，隔离规则的另一侧。
	TunnelSources []string
	// IsolateReason 是隔离规则无法下发时的原因（面向用户）。
	IsolateReason string
}

// Empty 表示这份决策不需要在内核里留下任何规则。
func (p NATPlan) Empty() bool { return !p.Enable && !p.Isolate }

// Fingerprint 返回该决策的指纹，用于判断规则是否需要重建。
// 内容一致时完全不动内核里的规则，避免无谓的规则抖动。
func (p NATPlan) Fingerprint() string {
	parts := []string{}
	if p.Enable {
		parts = append(parts, "nat:"+strings.Join(p.Sources, ",")+"->"+strings.Join(p.WANs, ","))
	}
	if p.Isolate {
		// 按「实际要下发的规则」而不是按网段列表计算指纹：
		// 否则单连接场景下源与目标相同的重复规则会让指纹无谓抖动。
		for _, r := range p.IsolationRules() {
			parts = append(parts, "iso:"+r[0]+">"+r[1])
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "|")
}

// IsolationRules 返回设备间隔离的「源网段 → 目标网段」丢弃规则对。
//
// 输出是纯数据：到底下发了哪些规则，可以直接在单元测试里穷举核对，
// 而不是靠读回内核规则去间接推断。两个方向都必须下发 ——
// 只堵一个方向的话，未被隔离那一侧的设备仍能主动连上被隔离的设备。
func (p NATPlan) IsolationRules() [][2]string {
	if !p.Isolate {
		return nil
	}
	out := [][2]string{}
	seen := map[string]bool{}
	add := func(from, to string) {
		key := from + ">" + to
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, [2]string{from, to})
	}
	for _, from := range p.IsolateSources {
		for _, to := range p.TunnelSources {
			add(from, to)
			add(to, from)
		}
	}
	return out
}

// PlanNAT 计算内网访问与设备隔离规则。
//
// 任何一条安全条件不满足都只记录原因并放弃启用，绝不返回错误中断收敛，
// 更不会去改动系统的任何规则。
func PlanNAT(in NATPlanInput) NATPlan {
	plan := NATPlan{}
	// 先算隔离：它与内网访问能不能启用无关，不能因为后者提前返回而丢掉。
	plan.applyIsolation(in)
	plan.applyForwarding(in)
	return plan
}

// applyIsolation 计算设备间隔离决策。
func (p *NATPlan) applyIsolation(in NATPlanInput) {
	if !in.IsolateRequested {
		return
	}
	iso := ipv4Subnets(in.IsolateSubnets)
	tunnels := ipv4Subnets(in.TunnelSubnets)
	if len(iso) == 0 {
		p.IsolateReason = "未获取到这条连接的隧道网段，无法确定要隔离哪些设备"
		if len(normalizeCIDRs(in.IsolateSubnets)) > 0 {
			p.IsolateReason = "本连接的隧道地址是 IPv6，目前暂不支持 IPv6 的设备间隔离"
		}
		return
	}
	if len(tunnels) == 0 {
		p.IsolateReason = "未获取到任何隧道网段，无法下发设备间隔离规则"
		if len(normalizeCIDRs(in.TunnelSubnets)) > 0 {
			p.IsolateReason = "全部隧道地址都是 IPv6，目前暂不支持 IPv6 的设备间隔离"
		}
		return
	}
	p.Isolate = true
	p.IsolateSources = iso
	p.TunnelSources = tunnels
}

// applyForwarding 计算内网访问决策（即原 PlanNAT 的判定逻辑）。
func (p *NATPlan) applyForwarding(in NATPlanInput) {
	if !in.Enabled {
		return
	}

	// 目前只对 IPv4 隧道网段做地址改写；IPv6 的转发放行后续版本再支持。
	all := normalizeCIDRs(in.SourceSubnets)
	if len(all) == 0 {
		p.SkipReason = "未获取到这条连接的隧道网段，无法确定要放行哪些设备"
		return
	}
	sources := ipv4Subnets(all)
	if len(sources) == 0 {
		p.SkipReason = "本连接的隧道地址是 IPv6，目前暂不支持 IPv6 的内网访问转发"
		return
	}
	wans := normAddrs(in.WANInterfaces)
	if len(wans) == 0 {
		if in.WANReason != "" {
			p.SkipReason = in.WANReason
		} else {
			p.SkipReason = "未能探测到 NAS 的出口网卡，无法确定从哪张网卡转发到局域网"
		}
		return
	}
	// 出口不能是本应用的隧道网卡，否则会把隧道流量再转发回隧道，形成回环
	for _, w := range wans {
		if contains(in.TunnelInterfaces, w) {
			p.SkipReason = fmt.Sprintf("出口网卡 %s 是本应用的连接本身，不能作为转发出口", w)
			return
		}
	}
	// 源网段不能与主机网段重叠：那说明隧道网段和家里网段撞了，
	// 这时做地址改写没有意义，还会把局域网流量搅乱。
	hostNets := parseCIDRs(in.HostNetworks)
	for _, s := range sources {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			continue
		}
		if overlapsAny(n, hostNets) {
			p.SkipReason = fmt.Sprintf("隧道网段 %s 与 NAS 现有网段重叠，为避免影响系统网络已跳过；"+
				"请到「我的连接」中把「本机专用地址」改成不冲突的网段", s)
			return
		}
	}

	sort.Strings(sources)
	sort.Strings(wans)
	p.Enable = true
	p.Sources = sources
	p.WANs = wans
}

// ipv4Subnets 规范化网段列表并只保留 IPv4（nft 规则目前只写 IPv4 匹配）。
func ipv4Subnets(list []string) []string {
	out := []string{}
	for _, s := range normalizeCIDRs(list) {
		if _, n, err := net.ParseCIDR(s); err == nil && n.IP.To4() != nil {
			out = append(out, s)
		}
	}
	return out
}

// DescribeNAT 汇总内网访问决策，用于日志与界面展示。
func DescribeNAT(p NATPlan) string {
	if !p.Enable {
		return ""
	}
	return fmt.Sprintf("允许 %s 的设备经由 %s 访问家里内网",
		strings.Join(p.Sources, "、"), strings.Join(p.WANs, "、"))
}

// DescribeIsolation 汇总设备隔离决策，用于日志与界面展示。
func DescribeIsolation(p NATPlan) string {
	if !p.Isolate {
		return ""
	}
	return fmt.Sprintf("已禁止 %s 的设备互相访问（仅可访问 NAS 与内网）",
		strings.Join(p.IsolateSources, "、"))
}

// WANCandidate 描述一条「可能作为转发出口」的候选事实。
//
// 之所以把筛选抽成「纯结构 + 纯函数」：出口网卡决定设备流量的源地址被改写成谁，
// 属于与路由安全同级的边界，必须能脱离内核环境穷举测试。
type WANCandidate struct {
	// Dev 是解析出的网卡名；为空表示这条候选无法定位到具体网卡。
	Dev string
	// Up 该网卡是否处于启用状态。
	Up bool
	// Tunnel 该网卡是隧道（本应用创建的连接，或内核里其它 WireGuard 网卡）。
	Tunnel bool
	// FromProbe 该候选来自内核自身的路由查询，而非扫描路由表。
	FromProbe bool
}

// PickWANs 从候选里挑出可用作转发出口的网卡，并给出不可用时的原因。
//
// 排除规则（任何一条不满足都不选，宁可不启用也不猜）：
//  1. 隧道网卡永远不能作为出口 —— 否则会把设备流量再转发回隧道，形成回环；
//  2. 未启用的网卡不能作为出口 —— 默认路由挂在掉线的网卡上转发必然失败；
//  3. 同一张网卡只出现一次，结果排序稳定（保证指纹稳定，不引起规则反复重建）。
func PickWANs(cands []WANCandidate) ([]string, string) {
	wans := []string{}
	tunnels := []string{}
	down := []string{}
	seen := map[string]bool{}
	unresolved := false

	for _, c := range cands {
		if c.Dev == "" {
			unresolved = true
			continue
		}
		if c.Tunnel {
			if !contains(tunnels, c.Dev) {
				tunnels = append(tunnels, c.Dev)
			}
			continue
		}
		if !c.Up {
			if !contains(down, c.Dev) {
				down = append(down, c.Dev)
			}
			continue
		}
		if seen[c.Dev] {
			continue
		}
		seen[c.Dev] = true
		wans = append(wans, c.Dev)
	}
	if len(wans) > 0 {
		sort.Strings(wans)
		return wans, ""
	}

	sort.Strings(tunnels)
	sort.Strings(down)
	switch {
	case len(tunnels) > 0:
		return nil, fmt.Sprintf("未能探测到 NAS 的出口网卡：默认路由指向隧道网卡 %s，"+
			"本应用不会把设备流量转发进隧道", strings.Join(tunnels, "、"))
	case len(down) > 0:
		return nil, fmt.Sprintf("未能探测到 NAS 的出口网卡：默认路由所在的 %s 当前未启用，"+
			"请在系统网络设置中检查该网卡", strings.Join(down, "、"))
	case unresolved:
		return nil, "未能探测到 NAS 的出口网卡：默认路由无法对应到具体网卡，" +
			"请在 NAS 上执行 ip route show default 查看"
	default:
		return nil, "未能探测到 NAS 的出口网卡：系统里没有默认路由，" +
			"请在 NAS 的系统网络设置中确认默认网关正常"
	}
}
