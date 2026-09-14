package wgback

import (
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
	if len(plan.Skip) != 3 {
		t.Fatalf("所有网段都应被记录为跳过，实际: %+v", plan.Skip)
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
