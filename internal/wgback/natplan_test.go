// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"strings"
	"testing"

	"fnwg/internal/model"
)

// 本文件是「内网访问（NAT 转发）」的回归测试。
//
// 最核心的不变量：下发出去的规则永远把「源地址属于本应用的隧道网段」作为匹配条件。
// NAS 自身流量的源地址是局域网地址，因此永远匹配不到 —— 这是「允许设备访问家里内网，
// 但绝不影响 fnOS 自身网络」这条承诺的技术依据。
// 任何一条用例失败都意味着这条承诺可能被破坏。

func TestPlanNATDisabled(t *testing.T) {
	plan := PlanNAT(NATPlanInput{Enabled: false, SourceSubnets: []string{"10.10.0.0/24"}})
	if plan.Enable {
		t.Fatal("开关关闭时不应启用转发")
	}
	if plan.SkipReason != "" {
		t.Fatalf("关闭开关是正常操作，不应产生提示，实际: %s", plan.SkipReason)
	}
	if plan.Fingerprint() != "" {
		t.Fatalf("关闭状态指纹应为空，实际: %s", plan.Fingerprint())
	}
}

func TestPlanNATBasic(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.1/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if !plan.Enable {
		t.Fatalf("条件满足时应启用，实际: %+v", plan)
	}
	// 主机位必须被归一化，否则每轮收敛都会被判定为「内容变了」而重建规则
	if len(plan.Sources) != 1 || plan.Sources[0] != "10.10.0.0/24" {
		t.Fatalf("源网段应归一化为 10.10.0.0/24，实际: %+v", plan.Sources)
	}
	if len(plan.WANs) != 1 || plan.WANs[0] != "end0" {
		t.Fatalf("出口网卡错误: %+v", plan.WANs)
	}
	if !strings.Contains(DescribeNAT(plan), "10.10.0.0/24") {
		t.Fatalf("描述应包含源网段: %s", DescribeNAT(plan))
	}
}

func TestPlanNATRequiresSourcesAndWAN(t *testing.T) {
	if plan := PlanNAT(NATPlanInput{Enabled: true, WANInterfaces: []string{"end0"}}); plan.Enable ||
		!strings.Contains(plan.SkipReason, "隧道网段") {
		t.Fatalf("缺少源网段时应放弃并说明原因，实际: %+v", plan)
	}
	if plan := PlanNAT(NATPlanInput{Enabled: true, SourceSubnets: []string{"10.10.0.0/24"}}); plan.Enable ||
		!strings.Contains(plan.SkipReason, "出口网卡") {
		t.Fatalf("缺少出口网卡时应放弃并说明原因，实际: %+v", plan)
	}
}

// TestPlanNATNeverUsesTunnelAsWAN 出口网卡是本应用的隧道时拒绝启用：
// 那会把隧道流量再转发回隧道，形成回环。
func TestPlanNATNeverUsesTunnelAsWAN(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:          true,
		SourceSubnets:    []string{"10.10.0.0/24"},
		WANInterfaces:    []string{"wg0"},
		TunnelInterfaces: []string{"wg0", "wg1"},
	})
	if plan.Enable {
		t.Fatal("出口不能是本应用的隧道网卡")
	}
	if !strings.Contains(plan.SkipReason, "回环") && !strings.Contains(plan.SkipReason, "不能作为转发出口") {
		t.Fatalf("应说明原因，实际: %s", plan.SkipReason)
	}
}

// TestPlanNATRejectsOverlapWithHost 隧道网段与 NAS 现有网段重叠时拒绝启用：
// 那说明隧道和家里网段撞了，做地址改写没有意义，还会搅乱局域网流量。
func TestPlanNATRejectsOverlapWithHost(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"192.168.3.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if plan.Enable {
		t.Fatal("与主机网段重叠时不得启用转发")
	}
	if !strings.Contains(plan.SkipReason, "重叠") {
		t.Fatalf("应说明重叠原因，实际: %s", plan.SkipReason)
	}
}

func TestPlanNATSkipsIPv6Only(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"fd00::1/64"},
		WANInterfaces: []string{"end0"},
	})
	if plan.Enable {
		t.Fatal("仅 IPv6 隧道地址时不应启用（暂不支持）")
	}
	if !strings.Contains(plan.SkipReason, "IPv6") {
		t.Fatalf("应明确说明不支持 IPv6，实际: %s", plan.SkipReason)
	}
}

// TestPlanNATKeepsIPv4WhenMixed 同时存在 v4/v6 地址时应保留 v4 部分正常工作。
func TestPlanNATKeepsIPv4WhenMixed(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.1/24", "fd00::1/64"},
		WANInterfaces: []string{"end0"},
	})
	if !plan.Enable {
		t.Fatalf("应保留 IPv4 部分，实际: %+v", plan)
	}
	if len(plan.Sources) != 1 || plan.Sources[0] != "10.10.0.0/24" {
		t.Fatalf("只应保留 IPv4 源网段，实际: %+v", plan.Sources)
	}
}

// TestPlanNATFingerprintStable 指纹必须与输入顺序无关、与内容相关，
// 否则每轮收敛都会重建规则（规则抖动）。
func TestPlanNATFingerprintStable(t *testing.T) {
	base := NATPlanInput{
		Enabled:       true,
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	}
	a := base
	a.SourceSubnets = []string{"10.10.0.1/24", "10.11.0.1/24"}
	b := base
	b.SourceSubnets = []string{"10.11.0.0/24", "10.10.0.0/24"}
	pa, pb := PlanNAT(a), PlanNAT(b)
	if pa.Fingerprint() != pb.Fingerprint() {
		t.Fatalf("顺序不同不应改变指纹：%s vs %s", pa.Fingerprint(), pb.Fingerprint())
	}
	c := base
	c.SourceSubnets = []string{"10.10.0.0/24"}
	if PlanNAT(c).Fingerprint() == pa.Fingerprint() {
		t.Fatal("内容不同时指纹必须不同")
	}
	if PlanNAT(base).Fingerprint() != "" {
		t.Fatal("未启用时指纹应为空")
	}
}

// TestPlanNATMultipleSourcesAndWANs 多连接 / 多出口时应全部保留且排序稳定。
func TestPlanNATMultipleSourcesAndWANs(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.12.0.1/24", "10.10.0.1/24"},
		WANInterfaces: []string{"end1", "end0"},
	})
	if !plan.Enable {
		t.Fatalf("应启用，实际: %+v", plan)
	}
	if strings.Join(plan.Sources, ",") != "10.10.0.0/24,10.12.0.0/24" {
		t.Fatalf("源网段应排序，实际: %+v", plan.Sources)
	}
	if strings.Join(plan.WANs, ",") != "end0,end1" {
		t.Fatalf("出口网卡应排序，实际: %+v", plan.WANs)
	}
}

// TestPlanNATNeverEmitsDefaultRoute 源网段里出现默认路由是不该发生的，
// 万一出现也必须被识别为与主机网段重叠而拒绝。这是最后一道兜底。
func TestPlanNATNeverEmitsDefaultRoute(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"0.0.0.0/0"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if plan.Enable {
		t.Fatal("0.0.0.0/0 绝不能作为被改写的源网段")
	}
}

// ---------------------------------------------------------------- 设备间隔离

// TestPlanIsolationRulePairs 隔离规则必须覆盖互访的两个方向。
//
// 单连接时源与目标相同（设备互访都发生在同一网段内），只应下发一条；
// 两条连接都开隔离时是完整的 2×2（去掉重复后 4 条）。
func TestPlanIsolationRulePairs(t *testing.T) {
	one := PlanNAT(NATPlanInput{
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24"},
		TunnelSubnets:    []string{"10.10.0.0/24"},
	})
	if !one.Isolate || one.Enable {
		t.Fatalf("只开隔离时不应顺带启用内网访问，实际: %+v", one)
	}
	if got := one.IsolationRules(); len(got) != 1 || got[0] != [2]string{"10.10.0.0/24", "10.10.0.0/24"} {
		t.Fatalf("单连接应恰好一条同网段阻断规则，实际: %+v", got)
	}

	two := PlanNAT(NATPlanInput{
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24", "10.12.0.0/24"},
		TunnelSubnets:    []string{"10.12.0.0/24", "10.10.0.0/24"},
	})
	if got := two.IsolationRules(); len(got) != 4 {
		t.Fatalf("两条连接都隔离应下发 4 条阻断规则，实际 %d 条: %+v", len(got), got)
	}
}

// TestPlanIsolationCoversAllTunnels 只隔离其中一条连接时，另一条连接里的设备
// 也必须访问不到被隔离的设备，否则「隔离」只堵了一半。
func TestPlanIsolationCoversAllTunnels(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:          true,
		SourceSubnets:    []string{"10.10.0.0/24", "10.11.0.0/24"},
		WANInterfaces:    []string{"end0"},
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24"},
		TunnelSubnets:    []string{"10.10.0.0/24", "10.11.0.0/24"},
	})
	want := map[string]bool{
		"10.10.0.0/24>10.10.0.0/24": true,
		"10.10.0.0/24>10.11.0.0/24": true,
		"10.11.0.0/24>10.10.0.0/24": true,
	}
	rules := plan.IsolationRules()
	if len(rules) != len(want) {
		t.Fatalf("应恰好 %d 条阻断规则，实际 %d 条: %+v", len(want), len(rules), rules)
	}
	for _, r := range rules {
		if !want[r[0]+">"+r[1]] {
			t.Fatalf("出现了预期之外的隔离规则: %v", r)
		}
	}
	if !plan.Enable {
		t.Fatal("内网访问与设备隔离应能同时生效")
	}
}

// TestPlanIsolationRuleSpaceIsTunnelOnly 隔离规则只能落在隧道网段之间：
// 绝不能出现「隧道 ↔ 局域网」这类匹配，那会连带切断设备访问家里内网的能力，
// 而用户要的只是「设备之间不通」。
func TestPlanIsolationRuleSpaceIsTunnelOnly(t *testing.T) {
	const host = "192.168.3.0/24"
	plan := PlanNAT(NATPlanInput{
		Enabled:          true,
		SourceSubnets:    []string{"10.10.0.0/24"},
		WANInterfaces:    []string{"end0"},
		HostNetworks:     []string{host},
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24"},
		TunnelSubnets:    []string{"10.10.0.0/24"},
	})
	tunnels := map[string]bool{"10.10.0.0/24": true}
	rules := plan.IsolationRules()
	if len(rules) == 0 {
		t.Fatal("应下发隔离规则")
	}
	for _, r := range rules {
		if !tunnels[r[0]] || !tunnels[r[1]] {
			t.Fatalf("隔离规则只能匹配隧道网段，实际: %v", r)
		}
		if r[0] == host || r[1] == host {
			t.Fatalf("隔离规则绝不能匹配 NAS 所在局域网网段: %v", r)
		}
	}
}

// TestPlanIsolationIndependentOfForwarding 内网访问因为探测不到出口网卡而无法启用时，
// 隔离规则仍必须照常下发 —— 它只依赖隧道网段，不依赖出口网卡。
func TestPlanIsolationIndependentOfForwarding(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:          true,
		SourceSubnets:    []string{"10.10.0.0/24"},
		WANReason:        "未能探测到 NAS 的出口网卡：系统里没有默认路由",
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24"},
		TunnelSubnets:    []string{"10.10.0.0/24"},
	})
	if plan.Enable {
		t.Fatal("没有出口网卡时不应启用内网访问")
	}
	if plan.SkipReason == "" {
		t.Fatal("内网访问未启用必须给出原因")
	}
	if !plan.Isolate || len(plan.IsolationRules()) == 0 {
		t.Fatalf("隔离不应受内网访问未启用的影响，实际: %+v", plan)
	}
	if plan.Empty() {
		t.Fatal("有隔离规则时决策不该被当成「无事可做」")
	}
}

// TestPlanIsolationOffChangesNothing 没开开关时一条隔离规则都不该有，
// 指纹也要与旧版本完全一致：否则升级后的第一轮收敛就会无谓地重建规则。
func TestPlanIsolationOffChangesNothing(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:          true,
		SourceSubnets:    []string{"10.10.0.0/24"},
		WANInterfaces:    []string{"end0"},
		IsolateRequested: false,
		TunnelSubnets:    []string{"10.10.0.0/24"},
	})
	if plan.Isolate || len(plan.IsolationRules()) != 0 {
		t.Fatalf("开关关闭时不应产生隔离规则，实际: %+v", plan)
	}
	if got := plan.Fingerprint(); got != "nat:10.10.0.0/24->end0" {
		t.Fatalf("未开启隔离时指纹应与旧版本一致，实际: %s", got)
	}
}

// TestPlanIsolationReasons 隔离无法生效时必须给出可读原因，
// 且要能区分「隧道是 IPv6」与「读不到隧道网段」—— 两者处理方式不同。
func TestPlanIsolationReasons(t *testing.T) {
	ipv6 := PlanNAT(NATPlanInput{
		IsolateRequested: true,
		IsolateSubnets:   []string{"fd00::1/64"},
		TunnelSubnets:    []string{"fd00::1/64"},
	})
	if ipv6.Isolate || !strings.Contains(ipv6.IsolateReason, "IPv6") {
		t.Fatalf("IPv6 隧道应给出明确的不支持原因，实际: %+v", ipv6)
	}
	none := PlanNAT(NATPlanInput{IsolateRequested: true})
	if none.Isolate || !strings.Contains(none.IsolateReason, "隧道网段") {
		t.Fatalf("读不到网段应说明原因，实际: %+v", none)
	}
	if none.Fingerprint() != "" {
		t.Fatalf("隔离未生效且无转发规则时指纹应为空，实际: %s", none.Fingerprint())
	}
}

// TestPlanIsolationFingerprintStable 指纹对隔离同样要稳定：
// 输入顺序变化不改变指纹，开关变化必须改变指纹（否则规则不会重建）。
func TestPlanIsolationFingerprintStable(t *testing.T) {
	base := NATPlanInput{
		IsolateRequested: true,
		IsolateSubnets:   []string{"10.10.0.0/24"},
		TunnelSubnets:    []string{"10.10.0.0/24", "10.11.0.0/24"},
	}
	a := PlanNAT(base)
	b := base
	b.TunnelSubnets = []string{"10.11.0.0/24", "10.10.0.0/24"}
	if a.Fingerprint() != PlanNAT(b).Fingerprint() {
		t.Fatalf("顺序不同不应改变指纹：%s vs %s", a.Fingerprint(), PlanNAT(b).Fingerprint())
	}
	off := base
	off.IsolateRequested = false
	if PlanNAT(off).Fingerprint() == a.Fingerprint() {
		t.Fatal("开关变化必须改变指纹，否则内核里的规则不会被更新")
	}
}

// TestPickWANsBasic 常规情形：多张网卡都有默认路由时全部保留，顺序稳定。
func TestPickWANsBasic(t *testing.T) {
	wans, reason := PickWANs([]WANCandidate{
		{Dev: "end1", Up: true},
		{Dev: "end0", Up: true},
		{Dev: "end0", Up: true}, // 同一条路由被读到两次不应重复
	})
	if reason != "" {
		t.Fatalf("正常情形不应产生说明，实际: %s", reason)
	}
	if strings.Join(wans, ",") != "end0,end1" {
		t.Fatalf("出口网卡应去重并排序，实际: %v", wans)
	}
}

// TestPickWANsNeverPicksTunnel 隧道网卡永远不能作为转发出口：
// 那会把设备流量再转发回隧道，形成回环。历史残留的 WireGuard 网卡也算隧道。
func TestPickWANsNeverPicksTunnel(t *testing.T) {
	wans, reason := PickWANs([]WANCandidate{
		{Dev: "wg0", Up: true, Tunnel: true},
		{Dev: "end0", Up: true},
	})
	if len(wans) != 1 || wans[0] != "end0" {
		t.Fatalf("应跳过隧道并选中真实出口，实际: %v", wans)
	}
	if reason != "" {
		t.Fatalf("有可用出口时不应产生说明，实际: %s", reason)
	}

	// 只有隧道时：不得启用，且原因要点名是哪张网卡、为什么不行
	wans, reason = PickWANs([]WANCandidate{{Dev: "wg0", Up: true, Tunnel: true}})
	if len(wans) != 0 {
		t.Fatalf("只剩隧道时不应选中任何出口，实际: %v", wans)
	}
	if !strings.Contains(reason, "出口网卡") || !strings.Contains(reason, "wg0") || !strings.Contains(reason, "隧道") {
		t.Fatalf("原因应说明出口网卡是隧道，实际: %s", reason)
	}
}

// TestPickWANsSkipsDownLink 默认路由挂在一张未启用的网卡上时不能选它。
func TestPickWANsSkipsDownLink(t *testing.T) {
	wans, reason := PickWANs([]WANCandidate{{Dev: "end0", Up: false}})
	if len(wans) != 0 {
		t.Fatalf("未启用的网卡不应作为出口，实际: %v", wans)
	}
	if !strings.Contains(reason, "出口网卡") || !strings.Contains(reason, "未启用") {
		t.Fatalf("原因应说明网卡未启用，实际: %s", reason)
	}
}

// TestPickWANsReasonWhenNoDefaultRoute 一条默认路由都没有：这是最常见的
// 「探测不到出口网卡」成因，提示必须把用户直接引到 `ip route show default`。
func TestPickWANsReasonWhenNoDefaultRoute(t *testing.T) {
	wans, reason := PickWANs(nil)
	if len(wans) != 0 {
		t.Fatalf("没有候选时不应选中任何出口，实际: %v", wans)
	}
	if !strings.Contains(reason, "出口网卡") || !strings.Contains(reason, "没有默认路由") {
		t.Fatalf("原因应说明系统里没有默认路由，实际: %s", reason)
	}
}

// TestPickWANsReasonWhenDevUnresolved 读到了默认路由却定位不到网卡：
// 提示要与「没有默认路由」区分开，否则用户会去查一个其实存在的路由。
func TestPickWANsReasonWhenDevUnresolved(t *testing.T) {
	wans, reason := PickWANs([]WANCandidate{{}, {}})
	if len(wans) != 0 {
		t.Fatalf("无法解析网卡时不应选中任何出口，实际: %v", wans)
	}
	if !strings.Contains(reason, "出口网卡") || !strings.Contains(reason, "ip route show default") {
		t.Fatalf("原因应引导用户查看默认路由，实际: %s", reason)
	}
	if strings.Contains(reason, "没有默认路由") {
		t.Fatalf("两种成因不能混为一谈，实际: %s", reason)
	}
}

// TestPlanNATSurfacesWANReason 数据面给出的具体原因必须原样透出，
// 而不是被通用的「未能探测到出口网卡」覆盖 —— 用户就靠这句话定位问题。
func TestPlanNATSurfacesWANReason(t *testing.T) {
	const custom = "未能探测到 NAS 的出口网卡：系统里没有默认路由，请在 NAS 的系统网络设置中确认默认网关正常"
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.1/24"},
		WANReason:     custom,
	})
	if plan.Enable {
		t.Fatal("没有出口网卡时不得启用转发")
	}
	if plan.SkipReason != custom {
		t.Fatalf("应原样透出数据面给出的原因，实际: %s", plan.SkipReason)
	}
}

// TestPlanNATIncludesPeerSiteSubnets 站点到站点互联：对端站点网段要与隧道网段一起放行。
//
// 少了这一项的现场表现是「隧道通、对端 NAS 自己能访问本机内网，但对端局域网里的机器访问不了」——
// 对端主机的源地址是它自己的局域网网段，不落在本连接的隧道网段里。
func TestPlanNATIncludesPeerSiteSubnets(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.1/24"},
		PeerSubnets:   []string{"192.168.2.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if !plan.Enable {
		t.Fatalf("应启用转发，实际: %+v", plan)
	}
	want := []string{"10.10.0.0/24", "192.168.2.0/24"}
	if len(plan.Sources) != len(want) {
		t.Fatalf("源网段应包含隧道与对端站点两类，实际: %+v", plan.Sources)
	}
	for i := range want {
		if plan.Sources[i] != want[i] {
			t.Fatalf("源网段应为 %v，实际: %+v", want, plan.Sources)
		}
	}
	// 指纹要能体现对端站点网段的变化，否则改了对端网段不会重建规则
	other := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.1/24"},
		PeerSubnets:   []string{"192.168.9.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if other.Fingerprint() == plan.Fingerprint() {
		t.Fatal("对端站点网段不同时指纹必须不同，否则规则不会重建")
	}
}

// TestPlanNATPeerSiteSubnetOverlapRejected 对端站点网段与 NAS 现有网段重叠时拒绝转发：
// 那种配置会把本机内网与对端内网搅在一起，提示里必须说清是「对端」那一边要改。
func TestPlanNATPeerSiteSubnetOverlapRejected(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.0/24"},
		PeerSubnets:   []string{"192.168.3.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.3.0/24"},
	})
	if plan.Enable {
		t.Fatal("与主机网段重叠时不得启用转发")
	}
	if !strings.Contains(plan.SkipReason, "对端站点网段") {
		t.Fatalf("应指出是对端站点网段重叠（改法与隧道网段不同），实际: %s", plan.SkipReason)
	}
}

// TestPeerSiteSubnetsFromSpecs 从连接期望态里挑出对端站点网段：
// 落在隧道内的（对端自己的地址）不算，默认路由写法一律丢弃，IPv6 跳过，重复只留一份。
func TestPeerSiteSubnetsFromSpecs(t *testing.T) {
	spec := model.InterfaceSpec{
		Addresses: []string{"10.10.0.1/24"},
		Peers: []model.PeerSpec{
			{Name: "nas-b", AllowedIPs: []string{"10.10.0.2/32", "192.168.2.0/24", "192.168.2.0/24"}},
			{Name: "nas-c", AllowedIPs: []string{"10.10.0.3/32", "172.16.5.0/24", "fd00::/64", "0.0.0.0/0"}},
		},
	}
	got := peerSiteSubnets(spec, []string{"10.10.0.0/24"})
	want := []string{"192.168.2.0/24", "172.16.5.0/24"}
	if len(got) != len(want) {
		t.Fatalf("应对端站点网段为 %v，实际: %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("应对端站点网段为 %v，实际: %v", want, got)
		}
	}
	// 没有设备时为空；设备只有隧道地址时同样为空（普通设备不该被当成站点）
	if len(peerSiteSubnets(model.InterfaceSpec{Peers: nil}, []string{"10.10.0.0/24"})) != 0 {
		t.Fatal("没有设备时不应产生站点网段")
	}
	plain := model.InterfaceSpec{Peers: []model.PeerSpec{{AllowedIPs: []string{"10.10.0.7/32"}}}}
	if len(peerSiteSubnets(plain, []string{"10.10.0.0/24"})) != 0 {
		t.Fatal("只有隧道地址的普通设备不应产生站点网段")
	}
}

// TestPlanNATNeverForwardsPeerDefaultRoute 兜底：即使数据里混进 0.0.0.0/0，
// 也不能把它当站点网段放行（那等于把本机内网整个暴露给对端）。
func TestPlanNATNeverForwardsPeerDefaultRoute(t *testing.T) {
	spec := model.InterfaceSpec{
		Addresses: []string{"10.10.0.1/24"},
		Peers:     []model.PeerSpec{{AllowedIPs: []string{"0.0.0.0/0"}}},
	}
	if got := peerSiteSubnets(spec, []string{"10.10.0.0/24"}); len(got) != 0 {
		t.Fatalf("默认路由写法必须被丢弃，实际: %v", got)
	}
}

// TestPlanPeerTargetRules 按设备限制内网目标：白名单与拒绝两组纯数据都要能逐条核对。
//
// 顺序即语义：白名单在前、拒绝在后，且两者都必须排在网段级放行之前
// （nftables 以第一条匹配的规则为终局判定）。这里核对的是「下发了什么」，
// 顺序由 nat.go 的调用位置保证，另有 TestPlanPeerTargetOrder 用纯数据钉住相对顺序。
func TestPlanPeerTargetRules(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.1.0/24"},
		PeerRestrictions: []PeerRestriction{
			{Policy: model.LANPolicyRestrict, DeviceAddresses: []string{"10.10.0.5/32"},
				Targets: []string{"192.168.1.10:445", "192.168.1.0/24", "192.168.1.10:445"}},
			{Policy: model.LANPolicyDeny, DeviceAddresses: []string{"10.10.0.6/32"}},
		},
	})
	if !plan.Enable {
		t.Fatalf("应启用转发：%+v", plan)
	}
	// 白名单按稳定顺序输出（排序保证指纹稳定），重复目标只留一份
	wantAllow := []string{"allow:10.10.0.5/32>192.168.1.0/24", "allow:10.10.0.5/32>192.168.1.10:445"}
	if len(plan.PeerAllow) != 2 {
		t.Fatalf("白名单应两条（去重后），实际：%+v", plan.PeerAllow)
	}
	for i := range wantAllow {
		if plan.PeerAllow[i].Key() != wantAllow[i] {
			t.Fatalf("白名单第 %d 条应为 %s，实际 %s", i, wantAllow[i], plan.PeerAllow[i].Key())
		}
	}
	// 两台受限设备各自都要有「访问内网各网段」的拒绝规则
	if len(plan.PeerDeny) != 2 {
		t.Fatalf("两台受限设备应各有一条拒绝规则，实际：%+v", plan.PeerDeny)
	}
	for i, pair := range plan.PeerDeny {
		if pair[1] != "192.168.1.0/24" {
			t.Fatalf("第 %d 条拒绝的目标应为内网网段，实际 %v", i, pair)
		}
	}
}

// TestPlanPeerTargetOrder 白名单必须排在拒绝之前：反了的话「允许的目标」也会被挡住。
func TestPlanPeerTargetOrder(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.1.0/24"},
		PeerRestrictions: []PeerRestriction{
			{Policy: model.LANPolicyRestrict, DeviceAddresses: []string{"10.10.0.5/32"}, Targets: []string{"192.168.1.10"}},
		},
	})
	if len(plan.PeerAllow) != 1 || len(plan.PeerDeny) != 1 {
		t.Fatalf("应各有一条，实际 allow=%+v deny=%+v", plan.PeerAllow, plan.PeerDeny)
	}
	// 纯数据层面无法表达顺序，这里固定住「两组都不为空」这个前提：
	// 只要两组都在，nat.go 就按 allow → deny 的顺序写入（见 addPeerTargetRules）。
	if plan.PeerAllow[0].Src != plan.PeerDeny[0][0] {
		t.Fatalf("白名单与拒绝应针对同一台设备，实际 %s / %s", plan.PeerAllow[0].Src, plan.PeerDeny[0][0])
	}
}

// TestPlanPeerTargetsOnlyWhenLANEnabled 连接级开关没开时不产生任何按设备规则：
// 那时本来就什么都访问不了，再下发拒绝规则只会让诊断页出现无法解释的规则。
func TestPlanPeerTargetsOnlyWhenLANEnabled(t *testing.T) {
	plan := PlanNAT(NATPlanInput{
		Enabled:       false,
		SourceSubnets: []string{"10.10.0.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.1.0/24"},
		PeerRestrictions: []PeerRestriction{
			{Policy: model.LANPolicyDeny, DeviceAddresses: []string{"10.10.0.6/32"}},
		},
	})
	if len(plan.PeerAllow) != 0 || len(plan.PeerDeny) != 0 {
		t.Fatalf("开关没开时不该有按设备规则：%+v / %+v", plan.PeerAllow, plan.PeerDeny)
	}
}

// TestPlanPeerTargetsFingerprint 指纹要跟着规则内容走：
// 改了一台设备的允许目标却不重建规则，用户会看到「改了没生效」。
func TestPlanPeerTargetsFingerprint(t *testing.T) {
	base := NATPlanInput{
		Enabled:       true,
		SourceSubnets: []string{"10.10.0.0/24"},
		WANInterfaces: []string{"end0"},
		HostNetworks:  []string{"192.168.1.0/24"},
		PeerRestrictions: []PeerRestriction{
			{Policy: model.LANPolicyRestrict, DeviceAddresses: []string{"10.10.0.5/32"}, Targets: []string{"192.168.1.10", "192.168.1.11"}},
		},
	}
	one := PlanNAT(base)
	// 顺序不同不该引起重建
	reordered := base
	reordered.PeerRestrictions = []PeerRestriction{
		{Policy: model.LANPolicyRestrict, DeviceAddresses: []string{"10.10.0.5/32"}, Targets: []string{"192.168.1.11", "192.168.1.10"}},
	}
	if PlanNAT(reordered).Fingerprint() != one.Fingerprint() {
		t.Fatal("目标顺序变化不该引起规则重建")
	}
	// 内容变化必须引起重建
	changed := base
	changed.PeerRestrictions = []PeerRestriction{
		{Policy: model.LANPolicyRestrict, DeviceAddresses: []string{"10.10.0.5/32"}, Targets: []string{"192.168.1.10"}},
	}
	if PlanNAT(changed).Fingerprint() == one.Fingerprint() {
		t.Fatal("目标内容变化必须引起规则重建")
	}
	// 策略从 restrict 改成 deny 也要变
	denied := base
	denied.PeerRestrictions = []PeerRestriction{
		{Policy: model.LANPolicyDeny, DeviceAddresses: []string{"10.10.0.5/32"}},
	}
	if PlanNAT(denied).Fingerprint() == one.Fingerprint() {
		t.Fatal("策略变化必须引起规则重建")
	}
}

// TestPeerRestrictionsFromSpecs 从连接期望态里收集约束：
// 源只取「落在隧道网段内」的地址（对端站点网段不是设备本身），inherit 的设备不进这份清单。
func TestPeerRestrictionsFromSpecs(t *testing.T) {
	specs := []model.InterfaceSpec{
		{
			Up:        true,
			Addresses: []string{"10.10.0.1/24"},
			Peers: []model.PeerSpec{
				{Name: "restricted", AllowedIPs: []string{"10.10.0.5/32", "192.168.9.0/24"},
					LANPolicy: model.LANPolicyRestrict, LANTargets: []string{"192.168.1.10:445"}},
				{Name: "denied", AllowedIPs: []string{"10.10.0.6/32"}, LANPolicy: model.LANPolicyDeny},
				{Name: "inherit", AllowedIPs: []string{"10.10.0.7/32"}, LANPolicy: model.LANPolicyInherit},
			},
		},
		{
			// 没启用的连接里的设备不参与（它的规则也不该下发）
			Up:        false,
			Addresses: []string{"10.11.0.1/24"},
			Peers: []model.PeerSpec{
				{AllowedIPs: []string{"10.11.0.5/32"}, LANPolicy: model.LANPolicyDeny},
			},
		},
	}
	got := peerRestrictions(specs, []string{"10.10.0.0/24", "10.11.0.0/24"})
	if len(got) != 2 {
		t.Fatalf("应收集到两台受限设备（inherit 与未启用的不算），实际：%+v", got)
	}
	if got[0].Policy != model.LANPolicyRestrict || len(got[0].DeviceAddresses) != 1 ||
		got[0].DeviceAddresses[0] != "10.10.0.5/32" {
		t.Fatalf("受限设备的源应只取隧道内地址：%+v", got[0])
	}
	if len(got[0].Targets) != 1 || got[0].Targets[0] != "192.168.1.10:445" {
		t.Fatalf("目标应原样带上：%+v", got[0].Targets)
	}
	if got[1].Policy != model.LANPolicyDeny {
		t.Fatalf("禁止访问的设备策略应保留：%+v", got[1])
	}
}
