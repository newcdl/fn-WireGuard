// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// 本文件回归「设备里那份配置是否已过期」与「通行范围的冲突校验」。
//
// 这两件事共同决定用户能不能想明白一个现象：
// 「我在界面上改了设备的通行范围，为什么设备上还是老样子」。

func TestPeerConfigStaleLifecycle(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "我的手机", GenerateKeys: true, AutoAddress: true, Enabled: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	reload := func() model.Peer {
		t.Helper()
		peers, err := svc.ListPeers(ctx, 0)
		if err != nil || len(peers) != 1 {
			t.Fatalf("读取设备列表失败: %v / %d 条", err, len(peers))
		}
		return peers[0]
	}

	// 显式指定家里网段：否则 clientAllowedIPs 会去探测开发机真实的局域网，
	// 用例结果就随运行环境变化（本机网段恰好等于用例取值时，会掩盖真实缺陷）。
	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "172.31.0.0/24"}, actor); err != nil {
		t.Fatal(err)
	}

	// 从未生成过配置：不能标过期。
	// 否则升级到本版本后，所有存量设备的列表都会突然飘满提示。
	if reload().ConfigStale {
		t.Fatal("从未生成过配置的设备不应被标为「配置已过期」")
	}

	// 刚生成配置：立即成为「不过期」
	cfg, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Conf == "" || cfg.QRPayload == "" {
		t.Fatal("应生成可用于导入的配置内容")
	}
	if reload().ConfigStale {
		t.Fatal("刚生成的配置不应被标为已过期")
	}

	// 改对外访问地址：设备里那份配置的 Endpoint 已经不对了 → 必须报过期
	if err := svc.SetSettings(ctx, map[string]string{"server_endpoint": "vpn.example.com:51820"}, actor); err != nil {
		t.Fatal(err)
	}
	if !reload().ConfigStale {
		t.Fatal("「对外访问地址」变化后必须标为已过期：设备上的旧地址连不回来")
	}

	// 重新生成 → 标记消除（这就是界面「一键重新生成二维码」要消除的东西）
	if _, err := svc.PeerConfig(ctx, p.ID); err != nil {
		t.Fatal(err)
	}
	if reload().ConfigStale {
		t.Fatal("重新生成配置后不应再标为已过期")
	}

	// 改与设备侧配置无关的字段（名称）：不该误报过期
	base := service.PeerInput{
		InterfaceID: it.ID,
		PublicKey:   p.PublicKey,
		RouteMode:   p.RouteMode,
		AllowedIPs:  p.AllowedIPs,
		Keepalive:   p.Keepalive,
		Enabled:     true,
	}
	rename := base
	rename.Name = "改名后的手机"
	if _, err := svc.UpdatePeer(ctx, p.ID, rename, actor); err != nil {
		t.Fatalf("改名失败: %v", err)
	}
	if reload().ConfigStale {
		t.Fatal("只改设备名称不该被判为配置过期：设备里那份配置没有任何变化")
	}

	// 改通行范围：用户最容易忽略的一种 → 必须报过期
	scoped := base
	scoped.Name = "改名后的手机"
	scoped.RouteMode = model.RouteModeCustom
	scoped.ClientAllowedIPs = []string{"172.30.0.0/24"}
	if _, err := svc.UpdatePeer(ctx, p.ID, scoped, actor); err != nil {
		t.Fatalf("修改通行范围失败: %v", err)
	}
	if !reload().ConfigStale {
		t.Fatal("通行范围变化后必须标为已过期：否则用户会以为改完就生效了")
	}

	// 详情接口（单台设备）也要带上同一个结论，否则列表与详情会自相矛盾
	got, err := svc.GetPeer(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ConfigStale {
		t.Fatal("设备详情应与列表给出一致的「配置已过期」结论")
	}
}

func TestPeerScopeConflictRejected(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	wg0, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	wg1, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"10.11.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	create := func(ifaceID int64, scope []string) error {
		t.Helper()
		_, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID:      ifaceID,
			Name:             "测试设备",
			GenerateKeys:     true,
			AutoAddress:      true,
			RouteMode:        model.RouteModeCustom,
			ClientAllowedIPs: scope,
			Enabled:          true,
		}, actor)
		return err
	}

	// ① 自定义范围里写默认路由：那是「全部流量」的语义，
	//    混进来会让设备的全部上网流量都走隧道，与用户以为的完全不同。
	err = create(wg0.ID, []string{"0.0.0.0/0"})
	if err == nil {
		t.Fatal("自定义范围里写 0.0.0.0/0 必须被拒绝")
	}
	if !strings.Contains(err.Error(), "全部流量") {
		t.Fatalf("提示应告诉用户改用「全部流量」模式，实际: %v", err)
	}

	// ② 与另一条连接的隧道网段重叠：包会被送进那条连接 → 拒绝并点名
	err = create(wg0.ID, []string{"10.11.0.0/24"})
	if err == nil {
		t.Fatal("与其它连接的隧道网段重叠必须被拒绝")
	}
	if !strings.Contains(err.Error(), wg1.Name) {
		t.Fatalf("提示应指出与哪条连接冲突（%s），实际: %v", wg1.Name, err)
	}

	// ③ 与本连接自己的隧道网段重叠是**允许**的：那正是「访问同隧道内的其它设备」
	if err := create(wg0.ID, []string{"10.10.0.0/24"}); err != nil {
		t.Fatalf("与本连接隧道网段重叠应被允许，实际: %v", err)
	}

	// ④ 家里网段当然也允许（这就是这个功能存在的意义）
	if err := create(wg1.ID, []string{"192.168.3.0/24"}); err != nil {
		t.Fatalf("指定家里网段应被允许，实际: %v", err)
	}
}
