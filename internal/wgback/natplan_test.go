package wgback

import (
	"strings"
	"testing"
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
