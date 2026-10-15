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

// 本文件回归「设备里那份配置是否已过期」与「通行范围的冲突校验」。
//
// 这两件事共同决定用户能不能想明白一个现象：
// 「我在界面上改了设备的通行范围，为什么设备上还是老样子」。

func TestPeerConfigStaleLifecycle(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "我的手机", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
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
		Enabled:     boolPtr(true),
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

// TestDeviceScopeIncludesSiteLAN 站点互联后，新生成的设备配置必须把**对端内网**也并入通行范围。
//
// 不并入的话，设备根本不会把发往对端内网的包送进隧道 —— 现象是「电脑连上了、
// 能访问本机内网，却访问不了另一台 NAS 后面的机器」，而且不报错、无从自查。
// 同时要确认没有把站点连接的隧道网段一并写进去（那是 NAS 之间的链路，不该进设备路由）。
func TestDeviceScopeIncludesSiteLAN(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	// 家里网段显式指定：否则用例结果会随开发机真实的局域网变化。
	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "192.168.1.0/24"}, actor); err != nil {
		t.Fatal(err)
	}
	// 设备所在连接
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.20.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	// 站点互联：会自动新建一条连接（隧道网段自动分配），并把对端内网写进准入地址。
	if _, err := svc.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName:        "nas-b",
		PeerLANSubnets:  []string{"192.168.2.0/24"},
		LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor); err != nil {
		t.Fatal(err)
	}

	ifaces, err := svc.Store.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var devIface int64
	for _, it := range ifaces {
		if it.Name == "wg0" {
			devIface = it.ID
		}
	}
	if devIface == 0 {
		t.Fatal("设备所在连接 wg0 应当存在")
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: devIface, Name: "我的电脑", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	has := func(cidr string) bool {
		for _, a := range cfg.AllowedIPs {
			if a == cidr {
				return true
			}
		}
		return false
	}
	if !has("192.168.1.0/24") {
		t.Fatalf("设备通行范围应包含本机内网，实际: %v", cfg.AllowedIPs)
	}
	if !has("192.168.2.0/24") {
		t.Fatalf("设备通行范围应包含站点对端内网，实际: %v", cfg.AllowedIPs)
	}
	for _, a := range cfg.AllowedIPs {
		if a == "10.10.0.0/24" || a == "10.20.0.0/24" {
			t.Fatalf("隧道网段不应进设备通行范围（那是 NAS 之间的链路），实际: %v", cfg.AllowedIPs)
		}
	}
}

// TestDeviceOnSiteLinkScopeIncludesBothLANs 覆盖最常见的拓扑：只有一条连接，
// 它既是站点互联链路、又挂着你要用的设备（电脑就挂在这条连接下）。
//
// 此时设备的通行范围必须同时含本机内网与对端内网；数据面的源地址改写规则
// 也必须照样下发（见 wgback.TestPlanSiteMasqCoversDeviceOnSiteLink）。
func TestDeviceOnSiteLinkScopeIncludesBothLANs(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "192.168.2.0/24"}, actor); err != nil {
		t.Fatal(err)
	}
	// 直接互联：本机上没有任何连接时，向导会建出唯一的那条连接（wg0）。
	created, err := svc.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName:        "nas2",
		PeerLANSubnets:  []string{"192.168.3.0/24"},
		LocalLANSubnets: []string{"192.168.2.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	// 设备就挂在这条互联连接下
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: created.InterfaceID, Name: "我的电脑", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	has := func(cidr string) bool {
		for _, a := range cfg.AllowedIPs {
			if a == cidr {
				return true
			}
		}
		return false
	}
	if !has("192.168.2.0/24") || !has("192.168.3.0/24") {
		t.Fatalf("设备通行范围应同时含本机内网与对端内网，实际: %v", cfg.AllowedIPs)
	}
	// 设备的隧道地址必须避开站点链路占用的地址，否则会与对端 NAS 撞车。
	for _, a := range cfg.ClientAddress {
		if strings.HasPrefix(a, "10.10.0.2/") {
			t.Fatalf("设备地址占用了对端 NAS 的隧道地址: %v", cfg.ClientAddress)
		}
	}
}

func TestPeerScopeConflictRejected(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	wg0, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true), Autostart: boolPtr(true),
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

	create := func(ifaceID int64, scope []string) error {
		t.Helper()
		_, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID:      ifaceID,
			Name:             "测试设备",
			GenerateKeys:     true,
			AutoAddress:      true,
			RouteMode:        model.RouteModeCustom,
			ClientAllowedIPs: scope,
			Enabled:          boolPtr(true),
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

// TestPeerConfigStaleNotStuckWhenDNSResolveOn 回归「开了内网域名解析后，设备永远显示需重新扫码」。
//
// 成因是同一份指纹用了两套 DNS 推导：「记录设备刚拿到什么」时用的是**下发给设备的值**
// （开启内网域名解析后会被替换成本机隧道地址），而「事后比对应当是什么」时用的是
// 连接里填的 DNS。两者不等 → 每台设备都被判为「配置已过期」，而且**重新扫码也清不掉**
// （重新生成记下的仍是另一套值），用户只能反复扫码、问题却一直挂着。
func TestPeerConfigStaleNotStuckWhenDNSResolveOn(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "172.31.0.0/24"}, actor); err != nil {
		t.Fatal(err)
	}
	// 连接里填的 DNS 与隧道地址不同：这正是暴露「两套推导」的条件。
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, DNS: []string{"223.5.5.5"},
		Enabled: boolPtr(true), Autostart: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	// 打开「内网域名解析」：此后下发给设备的 DNS 变成 10.10.0.1（本连接的隧道地址）
	if err := svc.SetSettings(ctx, map[string]string{model.SettingDNSResolve: "1"}, actor); err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "我的电脑", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Conf, "DNS = 10.10.0.1") {
		t.Fatalf("开启内网域名解析后，设备配置里的 DNS 应是本机隧道地址：\n%s", cfg.Conf)
	}
	// 必须顺带说清「这个地址只在连接期间可用」：断开后客户端若没还原 DNS，
	// 现象是「所有按域名访问的都不通」，用户推不出与这条连接有关（真机反馈过）。
	if !strings.Contains(cfg.Warning, "自动获取") {
		t.Fatalf("应提示断开连接后把设备 DNS 改回自动获取，实际：%q", cfg.Warning)
	}

	// 刚生成完就应当是「不过期」：这一条就是那个永远清不掉的标记
	got, err := svc.GetPeer(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.ConfigStale {
		t.Fatal("刚生成的配置不该被标为「需重新扫码」：用户重新扫码也修不好")
	}
	peers, err := svc.ListPeers(ctx, 0)
	if err != nil || len(peers) != 1 {
		t.Fatalf("读取设备列表失败: %v / %d 条", err, len(peers))
	}
	if peers[0].ConfigStale {
		t.Fatal("设备列表与详情必须给出一致结论：列表也不该标「需重新扫码」")
	}

	// 反过来必须仍然敏感：改掉下发给设备的 DNS 来源（关掉内网域名解析后回落成 223.5.5.5），
	// 设备手里那份就真的过期了 —— 否则修法变成了「永不报过期」。
	if err := svc.SetSettings(ctx, map[string]string{model.SettingDNSResolve: "0"}, actor); err != nil {
		t.Fatal(err)
	}
	if !reloadPeer(t, svc).ConfigStale {
		t.Fatal("下发给设备的 DNS 变了，必须标为「配置已过期」")
	}
}

// reloadPeer 取唯一的设备（用例里都只有一台），顺带覆盖「列表接口会算过期标记」这条路径。
func reloadPeer(t *testing.T, svc *service.Service) model.Peer {
	t.Helper()
	peers, err := svc.ListPeers(context.Background(), 0)
	if err != nil || len(peers) != 1 {
		t.Fatalf("读取设备列表失败: %v / %d 条", err, len(peers))
	}
	return peers[0]
}

// TestDNSModeControlsPushedDNS 覆盖「是否下发 DNS」的真实行为。
//
//   - client（默认）：连接里填的 DNS 被写进设备配置；
//   - off：不写进设备配置（连接里那一栏仍作为「内网域名解析」的上游，与下发与否无关）；
//   - host：历史值「NAS 也一起使用」，**从未生效过**（本应用绝不改 NAS 的系统解析），
//     一律按 client 处理 —— 界面上也已经没有这个选项，报错只会让人连编辑都保存不了；
//   - 其它取值：必须被拒绝，不静默接受拼错的写法；
//   - 打开「内网域名解析」时由它接管（下发隧道地址），off 不能让这个功能静默失效。
func TestDNSModeControlsPushedDNS(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if err := svc.SetSettings(ctx, map[string]string{"home_lan_cidrs": "172.31.0.0/24"}, actor); err != nil {
		t.Fatal(err)
	}
	mk := func(name, addr, mode string) (*model.Interface, *service.PeerConfigResult) {
		t.Helper()
		it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
			Name: name, Addresses: []string{addr}, DNS: []string{"223.5.5.5"}, DNSMode: mode,
			Enabled: boolPtr(true), Autostart: boolPtr(true),
		}, actor)
		if err != nil {
			t.Fatalf("创建连接 %s（dns_mode=%q）失败: %v", name, mode, err)
		}
		p, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID: it.ID, Name: "设备-" + name, GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
		}, actor)
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := svc.PeerConfig(ctx, p.ID)
		if err != nil {
			t.Fatal(err)
		}
		return it, cfg
	}

	// ① 不下发
	_, off := mk("wg0", "10.10.0.1/24", model.DNSModeOff)
	if strings.Contains(off.Conf, "DNS =") {
		t.Fatalf("「不下发」时设备配置里不该有 DNS 行：\n%s", off.Conf)
	}
	// ② 默认与历史值 host：都下发给设备
	_, def := mk("wg1", "10.11.0.1/24", "")
	if !strings.Contains(def.Conf, "DNS = 223.5.5.5") {
		t.Fatalf("默认应当把连接里的 DNS 下发给设备：\n%s", def.Conf)
	}
	host, hist := mk("wg2", "10.12.0.1/24", "host")
	if host.DNSMode != model.DNSModeClient {
		t.Fatalf("历史值 host 应按 client 归一，实际存成 %q", host.DNSMode)
	}
	if !strings.Contains(hist.Conf, "DNS = 223.5.5.5") {
		t.Fatalf("历史值 host 应按「下发给设备」处理：\n%s", hist.Conf)
	}
	// ③ 拼错的取值要当场拒绝
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg3", Addresses: []string{"10.13.0.1/24"}, DNSMode: "clinet", Enabled: boolPtr(true),
	}, actor); err == nil {
		t.Fatal("非法的「是否下发 DNS」取值必须被拒绝，不能静默按默认处理")
	}

	// ④ 打开「内网域名解析」后由它接管：即便是「不下发」的连接，设备也要拿到隧道地址，
	//    否则这个功能会对那条连接静默失效，而界面上看不出原因。
	if err := svc.SetSettings(ctx, map[string]string{model.SettingDNSResolve: "1"}, actor); err != nil {
		t.Fatal(err)
	}
	var offPeer int64
	peers, err := svc.ListPeers(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		if p.Name == "设备-wg0" {
			offPeer = p.ID
		}
	}
	if offPeer == 0 {
		t.Fatal("应当能找到「不下发」那条连接下的设备")
	}
	again, err := svc.PeerConfig(ctx, offPeer)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(again.Conf, "DNS = 10.10.0.1") {
		t.Fatalf("开启内网域名解析后，设备应被指向本机隧道地址：\n%s", again.Conf)
	}
}
