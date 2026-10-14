// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// findAccessIssue 按 key 查找一条矛盾结论。
func findAccessIssue(list []service.AccessIssue, key string) *service.AccessIssue {
	for i := range list {
		if list[i].Key == key {
			return &list[i]
		}
	}
	return nil
}

// TestDiagnoseAccessConflicts 回归「设置各自都对、组合起来互相抵消」的情形。
//
// 这类问题用户几乎不可能自己推出来：现象只是「配了却访问不了」，
// 而真正的矛盾在另一个页面的另一个开关里。
func TestDiagnoseAccessConflicts(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	// 固定家里网段，避免结果随开发机真实网络变化
	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "172.31.0.0/24"}, actor); err != nil {
		t.Fatal(err)
	}

	lanOff := false
	wg0, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true), AllowLAN: &lanOff,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	wg1, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"10.11.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// ① 设备在「只访问家里设备」模式下（范围自动包含家里网段），但连接的内网访问开关是关的
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: wg0.ID, Name: "手机", GenerateKeys: true, AutoAddress: true,
		RouteMode: model.RouteModeLAN, Enabled: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	issue := findAccessIssue(svc.DiagnoseAccess(ctx), "scope_needs_lan_access")
	if issue == nil {
		t.Fatalf("应报出「设备允许访问内网、但连接没打开内网访问」，实际: %+v", svc.DiagnoseAccess(ctx))
	}
	if !strings.Contains(issue.Detail, "wg0") || !strings.Contains(issue.Detail, "手机") {
		t.Fatalf("结论必须点名是哪条连接、哪台设备，实际: %s", issue.Detail)
	}
	if !strings.Contains(issue.Fix, "内网访问") {
		t.Fatalf("处理建议必须指向那个真正的开关，实际: %s", issue.Fix)
	}

	// 打开开关后这条矛盾必须消失，不能留下假警报
	if _, err := svc.SetLanAccess(ctx, wg0.ID, true, actor); err != nil {
		t.Fatal(err)
	}
	if findAccessIssue(svc.DiagnoseAccess(ctx), "scope_needs_lan_access") != nil {
		t.Fatal("打开内网访问后不应再报这条矛盾")
	}

	// ② 设备隔离与通行范围互相抵消：范围里有隧道网段，但隔离会把设备之间的流量丢掉
	if _, err := svc.SetPeerIsolation(ctx, wg0.ID, true, actor); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: wg0.ID, Name: "平板", GenerateKeys: true, AutoAddress: true,
		RouteMode: model.RouteModeCustom, ClientAllowedIPs: []string{"10.10.0.0/24"}, Enabled: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	iso := findAccessIssue(svc.DiagnoseAccess(ctx), "scope_blocked_by_isolation")
	if iso == nil {
		t.Fatal("应报出「设备隔离与通行范围互相抵消」")
	}
	if !strings.Contains(iso.Detail, "平板") || !strings.Contains(iso.Detail, "10.10.0.0/24") {
		t.Fatalf("结论必须点名设备与网段，实际: %s", iso.Detail)
	}
	if !strings.Contains(iso.Fix, "取一") {
		t.Fatalf("建议应给出二选一的出处，实际: %s", iso.Fix)
	}

	// ③④ 历史数据兜底：保存期的校验是后加的，老库里可能已经存在这两种写法。
	//     直接改库模拟升级上来的数据。
	legacy, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: wg1.ID, Name: "旧手机", GenerateKeys: true, AutoAddress: true,
		RouteMode: model.RouteModeCustom, ClientAllowedIPs: []string{"172.30.0.0/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	rewrite := func(scope []string) {
		t.Helper()
		stored, err := st.GetPeer(ctx, legacy.ID)
		if err != nil {
			t.Fatal(err)
		}
		stored.RouteMode = model.RouteModeCustom
		stored.ClientAllowedIPs = scope
		if err := st.UpdatePeer(ctx, stored); err != nil {
			t.Fatal(err)
		}
	}

	rewrite([]string{"0.0.0.0/0"})
	if findAccessIssue(svc.DiagnoseAccess(ctx), "scope_default_route") == nil {
		t.Fatal("范围里写成 0.0.0.0/0 的历史数据必须被诊断出来")
	}

	rewrite([]string{"10.10.0.0/24"})
	cross := findAccessIssue(svc.DiagnoseAccess(ctx), "scope_cross_interface")
	if cross == nil {
		t.Fatal("通行范围指向另一条连接的专用地址时必须被诊断出来")
	}
	if !strings.Contains(cross.Detail, wg0.Name) {
		t.Fatalf("冲突对象必须点名是哪条连接（%s），实际: %s", wg0.Name, cross.Detail)
	}

	// 改回正常范围后不应再有跨连接矛盾
	rewrite([]string{"172.30.0.0/24"})
	if findAccessIssue(svc.DiagnoseAccess(ctx), "scope_cross_interface") != nil {
		t.Fatal("范围正常后不应再报跨连接矛盾")
	}
}

// TestDiagnoseAccessNoFalsePositives 一套自洽的配置不该产生任何矛盾结论 ——
// 假警报会让用户学会忽略这些提示，那就等于没有提示。
// TestDiagnoseAccessAddrOutsideTunnel 设备的登记地址全落在隧道之外必须被报出来。
//
// 这条此前完全静默：配置照常生成、二维码看起来完全正常，设备却怎么都连不上
// （回包无路可走）。最容易踩到的路径是「为了避开两台 NAS 撞车改了连接网段，
// 而旧设备地址没跟着改」—— 那时用户只会以为设备坏了。
func TestDiagnoseAccessAddrOutsideTunnel(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	fixedHomeLAN(t, svc, "172.31.0.0/24")

	wg0, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	// 设备地址留在旧网段（例如连接网段后来从 10.99 改成了 10.10）
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: wg0.ID, Name: "旧手机", GenerateKeys: true,
		AllowedIPs: []string{"10.99.0.2/32"}, Keepalive: 25, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	issue := findAccessIssue(svc.DiagnoseAccess(ctx), "peer_addr_outside_tunnel")
	if issue == nil {
		t.Fatalf("必须报出「设备地址不在隧道网段内」，实际: %+v", svc.DiagnoseAccess(ctx))
	}
	if !strings.Contains(issue.Detail, "10.99.0.2/32") || !strings.Contains(issue.Detail, "10.10.0.0/24") {
		t.Fatalf("要说清是哪个地址、落在哪个网段之外，实际: %s", issue.Detail)
	}
	if !strings.Contains(issue.Detail, "旧手机") || issue.Fix == "" {
		t.Fatalf("要点名设备并给出处置办法，实际: %+v", issue)
	}
	// 处理入口在设备页：改的是那台设备的地址，不是这条连接的设置
	if issue.To != "peers" {
		t.Fatalf("处理入口应指向「我的设备」，实际: %q", issue.To)
	}

	// 生成二维码那一步也必须说 —— 用户就是在那里拿到配置的
	res, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Warning, "不在本连接的隧道网段") {
		t.Fatalf("生成配置时要给出这条提示，实际: %q", res.Warning)
	}
}

// TestDiagnoseAccessSiteAdmitCross 站点条目放行的网段撞上本机另一条连接时必须报出来。
//
// 从本机（或它的设备）访问那个网段会被本地那条连接截住、根本到不了对端，
// 而界面上原先一句话都没有 —— 用户只会以为「对端那台机器有问题」。
func TestDiagnoseAccessSiteAdmitCross(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	fixedHomeLAN(t, svc, "172.31.0.0/24")

	site, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
		RouteTable: model.RouteTableClient,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"10.11.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	// 站点条目：准入 = 对端 NAS 地址 + 一条放行网段；那条网段恰好是 wg1 的专用地址
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: site.ID, Name: "对端 NAS", GenerateKeys: true, GeneratePSK: true,
		AllowedIPs: []string{"10.10.0.2/32", "10.11.0.0/24"}, Keepalive: 25,
		Enabled: boolPtr(true), Remark: service.InterconnectRemark,
	}, actor); err != nil {
		t.Fatal(err)
	}

	issue := findAccessIssue(svc.DiagnoseAccess(ctx), "site_admit_cross_interface")
	if issue == nil {
		t.Fatalf("必须报出「对端条目放行的网段撞本机另一条连接」，实际: %+v", svc.DiagnoseAccess(ctx))
	}
	if !strings.Contains(issue.Detail, "对端 NAS") || !strings.Contains(issue.Detail, "10.11") {
		t.Fatalf("要说清是谁的哪一段放行撞了谁，实际: %s", issue.Detail)
	}
	if issue.Fix == "" {
		t.Fatal("必须给出处置办法")
	}
}

func TestDiagnoseAccessNoFalsePositives(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "172.31.0.0/24"}, actor); err != nil {
		t.Fatal(err)
	}
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	// 内网访问默认开启；设备用默认的「只访问家里设备」；没开隔离
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "手机", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	if got := svc.DiagnoseAccess(ctx); len(got) != 0 {
		t.Fatalf("自洽配置不应产生矛盾结论，实际: %+v", got)
	}

	// 停用的连接不参与诊断：用户已经把它关掉了，不该继续提示
	if err := svc.ToggleInterface(ctx, it.ID, false, actor); err != nil {
		t.Fatal(err)
	}
	if got := svc.DiagnoseAccess(ctx); len(got) != 0 {
		t.Fatalf("停用的连接不应产生结论，实际: %+v", got)
	}
}
