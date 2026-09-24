// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"net"
	"strconv"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
	"fnwg/internal/wgkey"
)

// mustInterface 取一条连接（测试里只有一个时用它）。
func mustInterface(t *testing.T, svc *service.Service) model.Interface {
	t.Helper()
	ctx := context.Background()
	list, err := svc.Store.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) == 0 {
		t.Fatal("应当已经建好一条连接")
	}
	return list[len(list)-1]
}

func mustPeers(t *testing.T, svc *service.Service, ifaceID int64) []model.Peer {
	t.Helper()
	peers, err := svc.Store.ListPeers(context.Background(), ifaceID)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) == 0 {
		t.Fatal("应当已经建好一条对端条目")
	}
	return peers
}

// TestInterconnectRoundTrip 覆盖站点互联的主链路：一端生成邀请、另一端导入，两端要真的配对。
//
// 重点不是「建出来了」，而是四处必须同时对：
//   - 两端在同一个隧道网段里各占一个地址；
//   - 两端都知道对方公钥（本端的对端条目公钥 == 对端连接的公钥）；
//   - 准入地址 = 对端隧道地址 + 对端内网网段；
//   - 通行范围 = 自己暴露给对面的网段。
//
// 这四处错任何一处的现象都只是「不通」：不报错、也没法自查，所以必须逐条钉住。
func TestInterconnectRoundTrip(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}
	svcA, stA := newTestEnv(t)
	svcB, _ := newTestEnv(t)

	// A：生成邀请（对端内网 192.168.2.0/24，本机暴露 192.168.1.0/24）
	created, err := svcA.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName:        "nas-b",
		PeerLANSubnets:  []string{"192.168.2.0/24", "192.168.2.0/24"},
		PeerEndpoint:    "b.example.com:51820",
		LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if created.TunnelSubnet != "10.10.0.0/24" || created.PeerTunnelAddress != "10.10.0.2" {
		t.Fatalf("隧道网段与对端地址不对：%s / %s", created.TunnelSubnet, created.PeerTunnelAddress)
	}
	// 邀请里给对方的地址要带隧道网段掩码（对方直接拿它当连接地址）
	if created.Invite.Peer.TunnelAddress != "10.10.0.2/24" {
		t.Fatalf("邀请里的对端隧道地址应为 10.10.0.2/24，实际 %s", created.Invite.Peer.TunnelAddress)
	}
	if created.Invite.Peer.TunnelSubnet != created.TunnelSubnet {
		t.Fatalf("邀请里的隧道网段要与本机一致：%+v", created.Invite.Peer)
	}
	if created.Invite.Site.PublicKey == "" || created.Invite.Peer.PrivateKey == "" {
		t.Fatalf("邀请里必须有本机公钥与对端私钥：%+v", created.Invite)
	}
	if created.PeerConf == "" {
		t.Fatal("应当同时给出一份 wg-quick 配置（对端没装本应用时用）")
	}
	if !strings.Contains(created.PeerConf, created.Invite.Site.PublicKey) {
		t.Fatalf("wg-quick 配置里应当有本机公钥：\n%s", created.PeerConf)
	}
	// 私钥随文件走这件事必须明确告诉用户
	foundKeyWarn := false
	for _, w := range created.Warnings {
		if strings.Contains(w, "私钥") {
			foundKeyWarn = true
		}
	}
	if !foundKeyWarn {
		t.Fatalf("必须提醒「邀请文件含私钥」：%v", created.Warnings)
	}

	// A 本端：连接与对端条目
	ifaceA := mustInterface(t, svcA)
	if len(ifaceA.Addresses) != 1 || ifaceA.Addresses[0] != "10.10.0.1/24" {
		t.Fatalf("A 的隧道地址应为 10.10.0.1/24：%v", ifaceA.Addresses)
	}
	if !ifaceA.AllowLAN {
		t.Fatal("站点互联必须打开「允许设备访问家里内网」：对端局域网里的主机要靠它转发")
	}
	if ifaceA.RouteTable != model.RouteTableClient {
		t.Fatalf("站点互联要用 client 路由方式（走本应用自己的策略路由表）：%s", ifaceA.RouteTable)
	}
	peersA := mustPeers(t, svcA, ifaceA.ID)
	if got := peersA[0].AllowedIPs; len(got) != 2 || got[0] != "10.10.0.2/32" || got[1] != "192.168.2.0/24" {
		t.Fatalf("A 的对端准入地址应为对端隧道地址+对端内网：%v", got)
	}
	if got := peersA[0].ClientAllowedIPs; len(got) != 1 || got[0] != "192.168.1.0/24" {
		t.Fatalf("A 给对端的通行范围应为本机暴露的网段：%v", got)
	}
	if peersA[0].EndpointHost != "b.example.com" || peersA[0].EndpointPort != 51820 {
		t.Fatalf("A 的对端条目应当带上对端地址：%+v", peersA[0].EndpointHost)
	}

	// B：导入邀请
	inv, err := service.ParseInterconnectInvite([]byte(created.InviteJSON))
	if err != nil {
		t.Fatal(err)
	}
	imported, err := svcB.ImportInterconnect(ctx, inv, actor)
	if err != nil {
		t.Fatal(err)
	}
	ifaceB := mustInterface(t, svcB)
	if len(ifaceB.Addresses) != 1 || ifaceB.Addresses[0] != "10.10.0.2/24" {
		t.Fatalf("B 的隧道地址应当由邀请给定：%v", ifaceB.Addresses)
	}
	if !ifaceB.AllowLAN || ifaceB.RouteTable != model.RouteTableClient {
		t.Fatalf("B 侧同样要打开内网访问并用 client 路由：%+v", ifaceB)
	}
	// 关键一环：A 的对端条目公钥必须等于 B 连接的公钥（两端认识彼此）
	pubB, err := wgkey.PublicKey(ifaceB.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if peersA[0].PublicKey != pubB {
		t.Fatalf("两端的公钥没配上：A 记的是 %s，B 实际的公钥是 %s", peersA[0].PublicKey, pubB)
	}
	peersB := mustPeers(t, svcB, ifaceB.ID)
	if peersB[0].PublicKey != created.Invite.Site.PublicKey {
		t.Fatal("B 的对端条目应当记 A 的公钥")
	}
	if got := peersB[0].AllowedIPs; len(got) != 2 || got[0] != "10.10.0.1/32" || got[1] != "192.168.1.0/24" {
		t.Fatalf("B 的对端准入地址应为 A 的隧道地址+A 内网：%v", got)
	}
	// B 的对端条目要带上「邀请里写的那个对外地址」——地址本身是 A 探测/配置出来的，
	// 测试不假设它的取值，只钉住它被原样带过去了。
	wantHost, wantPortStr, err := net.SplitHostPort(created.Invite.Site.Endpoint)
	if err != nil {
		t.Fatalf("本机对外地址应当是 host:port：%q", created.Invite.Site.Endpoint)
	}
	wantPort, _ := strconv.Atoi(wantPortStr)
	if peersB[0].EndpointHost != wantHost || peersB[0].EndpointPort != wantPort {
		t.Fatalf("B 的对端条目应当带上 A 的对外地址 %s：%+v", created.Invite.Site.Endpoint, peersB[0])
	}
	if peersB[0].Keepalive != service.InterconnectKeepalive {
		t.Fatalf("站点互联要开保活：%d", peersB[0].Keepalive)
	}
	if imported.TunnelSubnet != created.TunnelSubnet {
		t.Fatalf("两端隧道网段必须一致：%s / %s", imported.TunnelSubnet, created.TunnelSubnet)
	}

	// 审计：生成与导入都要留痕
	entries, _, err := stA.ListAudit(ctx, model.AuditFilter{Username: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	sawCreate := false
	for _, e := range entries {
		if e.Action == "interconnect.create" {
			sawCreate = true
		}
	}
	if !sawCreate {
		t.Fatal("生成邀请应当写审计")
	}
}

// TestInterconnectRejectsBadInput 把「生成」这一侧的输入校验钉住。
func TestInterconnectRejectsBadInput(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestEnv(t)
	actor := service.Actor{Username: "tester"}

	cases := []struct {
		name  string
		in    service.InterconnectInput
		words string
	}{
		{
			name:  "没有对端网段",
			in:    service.InterconnectInput{PeerLANSubnets: nil},
			words: "至少要填一个网段",
		},
		{
			name:  "对端网段写成全网",
			in:    service.InterconnectInput{PeerLANSubnets: []string{"0.0.0.0/0"}},
			words: "0.0.0.0/0",
		},
		{
			name:  "对端网段不是合法 CIDR",
			in:    service.InterconnectInput{PeerLANSubnets: []string{"192.168.2.0"}},
			words: "不是合法的 IPv4 网段",
		},
		{
			name: "本机暴露网段写成全网",
			in: service.InterconnectInput{
				PeerLANSubnets:  []string{"192.168.2.0/24"},
				LocalLANSubnets: []string{"0.0.0.0/0"},
			},
			words: "0.0.0.0/0",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := svc.CreateInterconnect(ctx, c.in, actor); err == nil ||
				!strings.Contains(err.Error(), c.words) {
				t.Fatalf("应当被拒绝并说明原因（含 %q），实际：%v", c.words, err)
			}
		})
	}
}

// TestInterconnectImportRejectsConflicts 导入侧的冲突必须在建任何东西之前挡住。
//
// 这些冲突的共同点是「不报错、只是不通」：隧道网段撞车、两端内网网段相同、公钥已被占用。
// 建完再发现就只能删连接重来，所以这里逐个钉住。
func TestInterconnectImportRejectsConflicts(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svc, _ := newTestEnv(t)

	// 本机的家里网段固定下来，测试才不受运行环境影响
	if err := svc.Store.SetSetting(ctx, "home_lan_cidrs", "192.168.1.0/24"); err != nil {
		t.Fatal(err)
	}
	// 先在本机放一条占着「邀请隧道网段」的连接：隧道网段冲突与公钥占用两个用例都靠它，
	// 且不依赖子用例的执行顺序（地址显式指定，不靠自动分配推算）。
	enabled := true
	existing, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg9", Addresses: []string{"10.10.0.1/24"}, Enabled: &enabled,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	good := service.InterconnectInvite{
		Kind:    service.InterconnectKind,
		Version: service.InterconnectVersion,
		Site: service.InterconnectSite{
			Name: "nas-a", TunnelAddress: "10.10.0.1/24", LANSubnets: []string{"192.168.9.0/24"},
		},
		Peer: service.InterconnectPeerParams{
			PrivateKey: mustKey(t), TunnelAddress: "10.10.0.2/24", TunnelSubnet: "10.10.0.0/24", MTU: 1380,
		},
	}
	good.Site.PublicKey = mustPublicKey(t)

	t.Run("标识不对", func(t *testing.T) {
		inv := good
		inv.Kind = "something-else"
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "不是本应用的互联邀请") {
			t.Fatalf("应拒绝无关内容：%v", err)
		}
	})
	t.Run("版本过新", func(t *testing.T) {
		inv := good
		inv.Version = service.InterconnectVersion + 1
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "更新版本") {
			t.Fatalf("应提示升级：%v", err)
		}
	})
	t.Run("声明的隧道网段与地址对不上", func(t *testing.T) {
		inv := good
		inv.Peer.TunnelSubnet = "10.99.0.0/24"
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "不在隧道网段") {
			t.Fatalf("应拒绝损坏的邀请：%v", err)
		}
	})
	t.Run("隧道地址不在网段内", func(t *testing.T) {
		inv := good
		inv.Peer.TunnelAddress = "10.11.0.2/24"
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "不在隧道网段") {
			t.Fatalf("应拒绝损坏的邀请：%v", err)
		}
	})
	t.Run("两端内网网段撞车", func(t *testing.T) {
		inv := good
		inv.Site.LANSubnets = []string{"192.168.1.0/24"} // 与本机家里网段相同
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "重叠") {
			t.Fatalf("两端内网网段相同时应拒绝：%v", err)
		}
	})
	t.Run("公钥已被占用", func(t *testing.T) {
		pub, err := wgkey.PublicKey(existing.PrivateKey)
		if err != nil {
			t.Fatal(err)
		}
		inv := good
		inv.Peer.TunnelAddress = "10.12.0.2/24"
		inv.Peer.TunnelSubnet = "10.12.0.0/24"
		inv.Site.PublicKey = pub
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "公钥") {
			t.Fatalf("公钥重复时应拒绝：%v", err)
		}
	})
	t.Run("隧道网段与已有连接冲突", func(t *testing.T) {
		inv := good
		if _, err := svc.ImportInterconnect(ctx, inv, actor); err == nil ||
			!strings.Contains(err.Error(), "隧道网段") {
			t.Fatalf("隧道网段与已有连接重叠时应拒绝：%v", err)
		}
	})
}

// TestInterconnectSecondLinkGetsOwnTunnel 再建一条互联要用到不同的隧道网段：
// 两条站点互联落在同一个隧道网段里会互相干扰。
func TestInterconnectSecondLinkGetsOwnTunnel(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestEnv(t)
	actor := service.Actor{Username: "tester"}

	first, err := svc.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName: "nas-b", PeerLANSubnets: []string{"192.168.2.0/24"}, LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName: "nas-c", PeerLANSubnets: []string{"192.168.3.0/24"}, LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if second.TunnelSubnet == first.TunnelSubnet {
		t.Fatalf("第二条互联应当自动换一个隧道网段：都是 %s", first.TunnelSubnet)
	}
	if second.PeerTunnelAddress != "10.11.0.2" {
		t.Fatalf("第二条互联的对端地址应为新网段里的 .2：%s", second.PeerTunnelAddress)
	}
}

func mustKey(t *testing.T) string {
	t.Helper()
	priv, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustPublicKey(t *testing.T) string {
	t.Helper()
	_, pub, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	return pub
}
