// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"os"
	"strings"
	"testing"
)

// 本文件是「绝不破坏 NAS 系统网络」这条铁规则的回归测试。
// 任何一条用例失败都意味着可能再次把用户的 NAS 网络弄坏，必须修复后才能发布。

func TestPlanRoutesDefaultOff(t *testing.T) {
	// 默认（不管理路由）时不允许产生任何路由动作
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   false,
		InterfaceAddrs: []string{"10.10.0.1/24"},
		PeerAllowedIPs: []string{"10.10.0.2/32", "192.168.3.0/24", "0.0.0.0/0"},
	})
	if len(plan.Add) != 0 {
		t.Fatalf("默认关闭路由管理时不应添加任何路由，实际: %v", plan.Add)
	}
	// 10.10.0.2/32 落在本连接网段内，已被内核直连路由覆盖，不产生提示；
	// 其余两个是用户真正需要知道的，必须汇报。
	if len(plan.Skip) != 2 {
		t.Fatalf("只应汇报真正需要用户知道的网段，实际: %+v", plan.Skip)
	}
}

// TestPlanRoutesOffStaysQuietForOwnSubnet 回归「手机连回家」这类最常见场景：
// 设备地址落在连接自身网段内，内核已通过直连路由覆盖，本应用无需做任何事，
// 因此不应产生任何提示 —— 用户曾把这条提示理解为「出错了」。
func TestPlanRoutesOffStaysQuietForOwnSubnet(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   false,
		InterfaceAddrs: []string{"10.210.0.1/24"},
		PeerAllowedIPs: []string{"10.210.0.2/32"},
	})
	if len(plan.Skip) != 0 {
		t.Fatalf("自身网段内的设备地址不应产生任何提示，实际: %+v", plan.Skip)
	}
	if len(plan.Add) != 0 {
		t.Fatalf("不应添加任何路由，实际: %v", plan.Add)
	}
}

// TestPlanRoutesOffWarnsAboutRemoteSegment 反过来：异地组网的对端网段在自身网段之外，
// 此时若路由管理未开启就必须如实提示，否则用户会以为功能坏了却没线索。
func TestPlanRoutesOffWarnsAboutRemoteSegment(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   false,
		InterfaceAddrs: []string{"10.210.0.1/24"},
		PeerAllowedIPs: []string{"10.210.0.2/32", "192.168.5.0/24"},
	})
	if len(plan.Skip) != 1 || plan.Skip[0].CIDR != "192.168.5.0/24" {
		t.Fatalf("应只提示对端网段，实际: %+v", plan.Skip)
	}
	if !strings.Contains(plan.Skip[0].Reason, "路由管理未开启") {
		t.Fatalf("提示需说明原因，实际: %+v", plan.Skip[0])
	}
}

// TestPlanRoutesOffReportsPartialCoverage 比自身网段更大的目标并未被完整覆盖
// （例如 /16 里还有 /24 之外的地址），必须提示而不是当作「无需添加」。
func TestPlanRoutesOffReportsPartialCoverage(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   false,
		InterfaceAddrs: []string{"10.210.0.1/24"},
		PeerAllowedIPs: []string{"10.210.0.0/16"},
	})
	if len(plan.Skip) != 1 {
		t.Fatalf("未被完整覆盖的目标必须提示，实际: %+v", plan.Skip)
	}
}

func TestPlanRoutesNeverAddsDefaultRoute(t *testing.T) {
	// 即使显式开启，也绝不接管默认路由：这是让 FN Connect 断网的根因
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.10.0.1/24"},
		PeerAllowedIPs: []string{"0.0.0.0/0", "::/0"},
		HostNetworks:   []string{"192.168.3.0/24"},
		ExistingRoutes: []HostRoute{{Dst: "", LinkIndex: 2, HasGw: true}},
	})
	if len(plan.Add) != 0 {
		t.Fatalf("绝不添加默认路由，实际: %v", plan.Add)
	}
	for _, s := range plan.Skip {
		if !strings.Contains(s.Reason, "默认路由") {
			t.Fatalf("默认路由应给出明确原因，实际: %+v", s)
		}
	}
}

func TestPlanRoutesNeverOverridesExisting(t *testing.T) {
	// 主机已有同目标路由时必须跳过，绝不覆盖（早期版本用 RouteReplace 覆盖，导致系统断网）
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.10.0.1/24"},
		PeerAllowedIPs: []string{"192.168.3.0/24"},
		HostNetworks:   []string{"192.168.3.0/24"},
		ExistingRoutes: []HostRoute{{Dst: "192.168.3.0/24", LinkIndex: 2}},
	})
	if len(plan.Add) != 0 {
		t.Fatalf("与主机网段重叠的路由必须跳过，实际: %v", plan.Add)
	}
}

func TestPlanRoutesSkipsHostNetworkOverlap(t *testing.T) {
	// 与主机网段重叠（哪怕主机没有该路由）也必须跳过，否则会抢走局域网可达性
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"192.168.3.0/24", "172.16.0.0/24"},
		HostNetworks:   []string{"192.168.3.0/24"},
	})
	if len(plan.Add) != 1 || plan.Add[0] != "172.16.0.0/24" {
		t.Fatalf("应只保留不与主机重叠的网段，实际: %v（跳过 %+v）", plan.Add, plan.Skip)
	}
	// 顺带确认：包含本接口地址的大网段也必须被拒绝（保守策略）
	strict := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"10.0.0.0/8"},
	})
	if len(strict.Add) != 0 {
		t.Fatalf("包含本连接地址的网段必须跳过，实际: %v", strict.Add)
	}
}

func TestPlanRoutesSkipsOwnInterfaceSubnet(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.10.0.1/24"},
		PeerAllowedIPs: []string{"10.10.0.2/32"},
	})
	if len(plan.Add) != 0 {
		t.Fatalf("本接口自身网段无需添加路由，实际: %v", plan.Add)
	}
}

func TestPlanRoutesAllowsSafeRouteInClientMode(t *testing.T) {
	// 合法的客户端场景：远端网段与主机不冲突、主机也没有该路由 → 允许添加
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"10.20.0.0/24"},
		HostNetworks:   []string{"192.168.3.0/24"},
		ExistingRoutes: []HostRoute{{Dst: "", LinkIndex: 2, HasGw: true}},
	})
	if len(plan.Add) != 1 || plan.Add[0] != "10.20.0.0/24" {
		t.Fatalf("安全的远端网段应被允许，实际: %v", plan.Add)
	}
}

// TestPlanPolicyRoutesNeverUseMainTable 回归：异地组网的下发目标一律是本应用专用表，
// 绝不写进系统主路由表。这是「异地组网能用、但绝不改飞牛系统路由」的关键。
func TestPlanPolicyRoutesNeverUseMainTable(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"192.168.5.0/24"},
		HostNetworks:   []string{"192.168.3.0/24"},
	})
	if len(plan.Add) != 1 {
		t.Fatalf("安全的对端网段应被允许下发，实际: %+v", plan)
	}
	list := PlanPolicyRoutes("wg200", plan)
	if len(list) != 1 {
		t.Fatalf("应生成 1 条策略路由，实际: %+v", list)
	}
	pr := list[0]
	if pr.Table != PolicyTableID {
		t.Fatalf("必须写入本应用专用表 %d，实际: %d", PolicyTableID, pr.Table)
	}
	if pr.Table == 254 || pr.Table == 0 {
		t.Fatalf("绝不能写入系统主路由表（main/254），实际: %d", pr.Table)
	}
	if pr.Dev != "wg200" || pr.CIDR != "192.168.5.0/24" || pr.Family != 4 {
		t.Fatalf("策略路由字段错误: %+v", pr)
	}
}

// TestPlanPolicyRoutesIPv6Family 确认协议族被正确标记（规则与路由都要用对协议族）。
func TestPlanPolicyRoutesIPv6Family(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"fd00:5::/64"},
	})
	list := PlanPolicyRoutes("wg0", plan)
	if len(list) != 1 || list[0].Family != 6 {
		t.Fatalf("IPv6 目标应标记为协议族 6，实际: %+v", list)
	}
}

// TestPlanPolicyRoutesEmptyWhenNotAllowed 被安全红线拦下的网段不得产生任何策略路由。
func TestPlanPolicyRoutesEmptyWhenNotAllowed(t *testing.T) {
	plan := PlanRoutes(RoutePlanInput{
		ManageRoutes:   true,
		InterfaceAddrs: []string{"10.99.0.1/24"},
		PeerAllowedIPs: []string{"0.0.0.0/0", "10.99.0.2/32", "192.168.3.0/24"},
		HostNetworks:   []string{"192.168.3.0/24"},
	})
	if list := PlanPolicyRoutes("wg0", plan); len(list) != 0 {
		t.Fatalf("默认路由/自身网段/主机网段都不得下发，实际: %+v", list)
	}
}

func TestIsDefaultRouteCIDR(t *testing.T) {
	for _, c := range []string{"0.0.0.0/0", "::/0", "0/0", "0::/0"} {
		if !IsDefaultRouteCIDR(c) {
			t.Fatalf("%s 应被判定为默认路由", c)
		}
	}
	for _, c := range []string{"10.0.0.0/8", "192.168.3.0/24", "10.10.0.2/32", "::/64"} {
		if IsDefaultRouteCIDR(c) {
			t.Fatalf("%s 不应被判定为默认路由", c)
		}
	}
}

func TestValidatePeerAllowedIPsRejectsDefault(t *testing.T) {
	for _, c := range []string{"0.0.0.0/0", "::/0"} {
		err := ValidatePeerAllowedIPs([]string{"10.10.0.2/32", c})
		if err == nil {
			t.Fatalf("服务端准入地址 %s 必须被拒绝", c)
		}
		if !strings.Contains(err.Error(), "上网方式") {
			t.Fatalf("错误提示应引导用户使用「设备上网方式」，实际: %v", err)
		}
	}
	if err := ValidatePeerAllowedIPs([]string{"10.10.0.2/32", "192.168.2.0/24"}); err != nil {
		t.Fatalf("正常准入地址不应报错: %v", err)
	}
}

func TestStateManagedTracking(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/netstate.json"
	st := LoadState(path)
	if st.IsManaged("wg0") {
		t.Fatal("初始状态不应包含任何受管接口")
	}
	st.MarkManaged("wg0")
	st.MarkManaged("wg0")
	st.MarkManaged("wg7")
	if !st.IsManaged("wg0") || !st.IsManaged("wg7") {
		t.Fatal("标记后应被识别为受管接口")
	}
	if got := st.ManagedCopy(); len(got) != 2 {
		t.Fatalf("受管接口数量错误: %v", got)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := LoadState(path)
	if !reloaded.IsManaged("wg0") {
		t.Fatal("重新加载后应保留受管记录")
	}
	reloaded.UnmarkManaged("wg0")
	if reloaded.IsManaged("wg0") {
		t.Fatal("取消标记后不应再受管")
	}
}

// TestStatePolicyRouteTracking 确保策略路由记录可跨重启保留，
// 以便停用/卸载时只撤销自己创建的 ip rule 与表内路由。
func TestStatePolicyRouteTracking(t *testing.T) {
	path := t.TempDir() + "/netstate.json"
	st := LoadState(path)

	pr := PolicyRoute{Dev: "wg200", CIDR: "192.168.5.0/24", Table: PolicyTableID, Family: 4}
	if st.HasPolicyRoute("wg200", "192.168.5.0/24") {
		t.Fatal("初始状态不应包含策略路由记录")
	}
	st.MarkPolicyRoute(pr)
	st.MarkPolicyRoute(pr) // 重复标记不应产生重复记录
	st.MarkPolicyRoute(PolicyRoute{Dev: "wg1", CIDR: "192.168.6.0/24", Table: PolicyTableID, Family: 4})
	if got := st.PolicyRoutesCopy(); len(got) != 2 {
		t.Fatalf("策略路由记录数量错误: %+v", got)
	}
	if got := st.PolicyRoutesFor("wg200"); len(got) != 1 || got[0].CIDR != "192.168.5.0/24" {
		t.Fatalf("按连接筛选错误: %+v", got)
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}

	reloaded := LoadState(path)
	if !reloaded.HasPolicyRoute("wg200", "192.168.5.0/24") {
		t.Fatal("重新加载后应保留策略路由记录")
	}
	reloaded.UnmarkPolicyRoute("wg200", "192.168.5.0/24")
	if reloaded.HasPolicyRoute("wg200", "192.168.5.0/24") {
		t.Fatal("取消记录后不应再存在")
	}
	if got := reloaded.PolicyRoutesCopy(); len(got) != 1 || got[0].Dev != "wg1" {
		t.Fatalf("只应移除目标记录，实际: %+v", got)
	}
}

// TestStateNATSwitchAndBlocked 确保「开关是否打开」与「未能启用的原因」可跨重启保留：
// 界面靠这两个字段说清「开关是开着的，卡在了哪一层」，
// 丢掉的话用户会以为开关没打开，去反复检查一个其实已经打开的开关。
func TestStateNATSwitchAndBlocked(t *testing.T) {
	path := t.TempDir() + "/netstate.json"
	st := LoadState(path)

	if st.NATSwitchOn() || st.NATBlockedReason() != "" {
		t.Fatal("初始状态不应有开关与受阻记录")
	}

	st.SetNATState(true, "未能探测到 NAS 的出口网卡：系统里没有默认路由")
	if !st.NATSwitchOn() || !strings.Contains(st.NATBlockedReason(), "出口网卡") {
		t.Fatalf("应记录开关与受阻原因，实际: %v / %s", st.NATSwitchOn(), st.NATBlockedReason())
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := LoadState(path)
	if !reloaded.NATSwitchOn() || !strings.Contains(reloaded.NATBlockedReason(), "默认路由") {
		t.Fatalf("重新加载后应保留开关与受阻原因，实际: %v / %s", reloaded.NATSwitchOn(), reloaded.NATBlockedReason())
	}

	// 启用成功后必须同时清掉受阻原因，否则界面会一直显示一条早已过期的错误
	reloaded.SetNATState(true, "")
	if reloaded.NATBlockedReason() != "" {
		t.Fatalf("启用成功后不应残留受阻原因，实际: %s", reloaded.NATBlockedReason())
	}
	// 关闭开关时开关与受阻原因一并归还初始态
	reloaded.SetNATState(false, "忽略这条：开关没打开时不应记录原因")
	if reloaded.NATSwitchOn() || reloaded.NATBlockedReason() != "" {
		t.Fatalf("关闭开关后应清空两项，实际: %v / %s", reloaded.NATSwitchOn(), reloaded.NATBlockedReason())
	}
}

// TestStateIsolateTracking 设备间隔离开关与「实际生效的网段」必须可跨重启保留：
// 界面靠它回答「隔离开着没有、隔的是谁、没生效是为什么」。
func TestStateIsolateTracking(t *testing.T) {
	path := t.TempDir() + "/netstate.json"
	st := LoadState(path)

	if st.IsolateSwitchOn() || len(st.IsolateNets()) != 0 || st.IsolateBlockedReason() != "" {
		t.Fatal("初始状态不应有隔离记录")
	}

	st.SetIsolateState(true, []string{"10.10.0.0/24"}, "")
	if !st.IsolateSwitchOn() {
		t.Fatal("应记录开关已打开")
	}
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := LoadState(path)
	if !reloaded.IsolateSwitchOn() || len(reloaded.IsolateNets()) != 1 || reloaded.IsolateNets()[0] != "10.10.0.0/24" {
		t.Fatalf("重新加载后应保留开关与生效网段，实际: %v / %v", reloaded.IsolateSwitchOn(), reloaded.IsolateNets())
	}

	// 拿到的必须是副本：调用方改动它不能污染状态文件里的数据
	nets := reloaded.IsolateNets()
	nets[0] = "被改坏了"
	if reloaded.IsolateNets()[0] != "10.10.0.0/24" {
		t.Fatal("返回的网段必须是副本，否则调用方会误改状态")
	}

	// 开关开着但规则没下发：要同时保留原因，界面才能说清卡在哪一层
	reloaded.SetIsolateState(true, nil, "本连接的隧道地址是 IPv6，目前暂不支持 IPv6 的设备间隔离")
	if len(reloaded.IsolateNets()) != 0 || !strings.Contains(reloaded.IsolateBlockedReason(), "IPv6") {
		t.Fatalf("应记录未生效原因，实际: %v / %s", reloaded.IsolateNets(), reloaded.IsolateBlockedReason())
	}

	// 关闭开关时三项一并归还初始态
	reloaded.SetIsolateState(false, nil, "忽略这条：开关没打开时不应记录原因")
	if reloaded.IsolateSwitchOn() || len(reloaded.IsolateNets()) != 0 || reloaded.IsolateBlockedReason() != "" {
		t.Fatalf("关闭开关后应清空三项，实际: %v / %v / %s",
			reloaded.IsolateSwitchOn(), reloaded.IsolateNets(), reloaded.IsolateBlockedReason())
	}
}

// TestStatePskFingerprintTracking 确保口令指纹可跨重启保留：
// 它是「口令变了才下发、没变一次都不碰」的唯一依据。
func TestStatePskFingerprintTracking(t *testing.T) {
	path := t.TempDir() + "/netstate.json"
	st := LoadState(path)
	if got := st.PskFingerprint("wg0", "KEY"); got != "" {
		t.Fatalf("初始不应有指纹，实际 %q", got)
	}
	st.SetPskFingerprint("wg0", "KEY", "fp1")
	st.SetPskFingerprint("wg0", "OTHER", "fp2")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	reloaded := LoadState(path)
	if got := reloaded.PskFingerprint("wg0", "KEY"); got != "fp1" {
		t.Fatalf("重新加载后应保留指纹，实际 %q", got)
	}
	reloaded.DropPskFingerprint("wg0", "OTHER")
	if got := reloaded.PskFingerprint("wg0", "OTHER"); got != "" {
		t.Fatal("移除后不应再有指纹")
	}
	reloaded.DropPskFingerprints("wg0")
	if got := reloaded.PskFingerprint("wg0", "KEY"); got != "" {
		t.Fatal("按接口清理后不应再有指纹")
	}
}

// TestStateSaveSkipsUnchangedWrites 收敛循环每 10 秒调用一次 Save，
// 稳态下不应持续产生磁盘写入。
func TestStateSaveSkipsUnchangedWrites(t *testing.T) {
	path := t.TempDir() + "/netstate.json"
	st := LoadState(path)
	st.MarkManaged("wg0")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// 内容未变化 → 不应重写
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	same, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(same.ModTime()) {
		t.Fatal("内容未变化时不应重写状态文件")
	}
	// 内容变化 → 应写入
	st.MarkManaged("wg1")
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() == same.Size() && after.ModTime().Equal(same.ModTime()) {
		t.Fatal("内容变化后应重写状态文件")
	}
}

func TestStateBaselineOnlyCapturedOnce(t *testing.T) {
	st := LoadState(t.TempDir() + "/s.json")
	st.SetBaseline([]BaselineRoute{{Family: 2, Gw: "192.168.3.1", Dev: "end0", Metric: 100}})
	// 后续调用不应覆盖已采集的基线（避免被污染后的状态污染基线）
	st.SetBaseline([]BaselineRoute{{Family: 2, Gw: "10.10.0.1", Dev: "wg0"}})
	got := st.Baseline()
	if len(got) != 1 || got[0].Dev != "end0" {
		t.Fatalf("基线应只采集一次，实际: %+v", got)
	}
}
