// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// subnetHost 取网段里指定末位的主机地址（10.109.0.0/24 + 2 → 10.109.0.2）。
//
// 用它是为了断言**相对关系**而不是写死某个网段：默认网段带一个按本机随机的基准偏移，
// 写死等于把「两台机器必然撞车」当成契约，而那正是要修掉的行为。
func subnetHost(t *testing.T, cidr string, last int) string {
	t.Helper()
	ip, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		t.Fatalf("网段不合法：%s", cidr)
	}
	base := ip.Mask(n.Mask).To4()
	if base == nil {
		t.Fatalf("用例只处理 IPv4 网段：%s", cidr)
	}
	return fmt.Sprintf("%d.%d.%d.%d", base[0], base[1], base[2], last)
}

// thirdOctet 取 10.x.0.1/24 里的 x，顺带断言它是预期的形状。
func thirdOctet(t *testing.T, addr string) int {
	t.Helper()
	ip, _, err := net.ParseCIDR(strings.TrimSpace(addr))
	if err != nil {
		t.Fatalf("地址不合法：%s", addr)
	}
	v4 := ip.To4()
	if v4 == nil || v4[0] != 10 || v4[2] != 0 || v4[3] != 1 {
		t.Fatalf("自动分配的地址应形如 10.x.0.1/24，实际 %s", addr)
	}
	return int(v4[1])
}

// octetDelta 返回 addr 的第三个八位组相对基准 base **前移**了多少位
// （按 241 个可选网段的环回计算：10.10.0.0/24 ~ 10.250.0.0/24）。
func octetDelta(t *testing.T, base int, addr string) int {
	t.Helper()
	return (thirdOctet(t, addr) - base + 241) % 241
}

// containsCIDR 判断列表里是否含某个地址（顺序无关）。
func containsCIDR(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// countIPv4 数一份地址清单里有几个 IPv4 项。
func countIPv4(t *testing.T, list []string) int {
	t.Helper()
	n := 0
	for _, a := range list {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(a))
		if err != nil {
			t.Fatalf("地址 %q 不合法：%v", a, err)
		}
		if ip.To4() != nil {
			n++
		}
	}
	return n
}

// fixedHomeLAN 把「本机内网网段」固定下来：不固定的话它走自动探测，
// 用例就会随运行环境变化（探测到的网段与邀请里写的撞车会让导入直接失败）。
//
// 两端要传**不同**的网段：相同会被导入侧正确拒绝（「两端的内网网段不能相同」）。
func fixedHomeLAN(t *testing.T, svc *service.Service, cidr string) {
	t.Helper()
	if err := svc.Store.SetSetting(context.Background(), "home_lan_cidrs", cidr); err != nil {
		t.Fatal(err)
	}
}

// TestUpdatePeerKeepsPresharedKey 回归一处会静默损坏数据的缺陷。
//
// 设备编辑抽屉（frontend/src/views/Peers.vue）**不提交 preshared_key 字段**，
// 而 UpdatePeer 原先无条件用请求里的值覆盖它 —— 于是「编辑设备改个名字或换个地址」
// 就会把该设备的二次加密口令清空。设备手上那份配置还带着旧口令，对端直接拒绝握手，
// 现象只是「一直离线」，成因在界面上完全看不出来（真机日志里能读出
// 「更新节点 X（…）（清除二次加密口令）」）。
func TestUpdatePeerKeepsPresharedKey(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svc, _ := newTestEnv(t)

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "我的手机", GenerateKeys: true, GeneratePSK: true,
		AutoAddress: true, Keepalive: 25, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if p.PresharedKey == "" {
		t.Fatal("开启二次加密口令时应生成口令")
	}
	before := p.PresharedKey

	// 模拟界面上的「编辑设备」：不带 preshared_key，也不要求生成新口令
	if _, err := svc.UpdatePeer(ctx, p.ID, service.PeerInput{
		InterfaceID: it.ID, Name: "我的手机（改名）", RouteMode: model.RouteModeLAN,
		AllowedIPs: p.AllowedIPs, Keepalive: 25, Enabled: boolPtr(true),
	}, actor); err != nil {
		t.Fatal(err)
	}
	row, err := svc.Store.GetPeer(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if row.Name != "我的手机（改名）" {
		t.Fatalf("这次编辑本身应当生效：%q", row.Name)
	}
	if row.PresharedKey != before {
		t.Fatalf("编辑设备不该改动二次加密口令（口令被清空会让这台设备再也连不上）：%q → %q",
			before, row.PresharedKey)
	}

	// 明确点了「生成新口令」时才换：这是用户表达「轮换」意图的唯一方式
	if _, err := svc.UpdatePeer(ctx, p.ID, service.PeerInput{
		InterfaceID: it.ID, Name: row.Name, RouteMode: model.RouteModeLAN,
		AllowedIPs: row.AllowedIPs, Keepalive: 25, Enabled: boolPtr(true), GeneratePSK: true,
	}, actor); err != nil {
		t.Fatal(err)
	}
	rotated, err := svc.Store.GetPeer(ctx, p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.PresharedKey == before {
		t.Fatal("点了「生成新口令」应当真的换一个口令")
	}
}

// TestCreatePeerManualAddressNotDoubled 手填了地址之后，不该再自动追加一个地址。
//
// 界面恒传 auto_address=true（含义是「允许自动分配」），而原先的实现是只要这个标志为真就
// 追加一个地址 —— 于是用户手填的地址之外，设备还多挂一个自动挑的同网段地址。用户明明
// "改成了不重复的地址"（真机上就是这么说的），它身上那个自动地址仍然会和别人撞车，
// 而界面上完全看不出来（日志里一台设备的准入地址里有两个 IPv4）。
func TestCreatePeerManualAddressNotDoubled(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svc, _ := newTestEnv(t)

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// 手填 IPv4（界面照旧传 auto_address=true）
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "MAC", GenerateKeys: true, GeneratePSK: true,
		AutoAddress: true, AllowedIPs: []string{"10.10.0.9/32"},
		Keepalive: 25, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if !containsCIDR(p.AllowedIPs, "10.10.0.9/32") {
		t.Fatalf("手填的地址必须保留：%v", p.AllowedIPs)
	}
	if n := countIPv4(t, p.AllowedIPs); n != 1 {
		t.Fatalf("手填了地址之后不该再追加一个（这就是「改了地址却还是撞车」的来源），实际有 %d 个：%v",
			n, p.AllowedIPs)
	}

	// 完全留空：照旧自动分配（原有行为不变）
	q, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "手机", GenerateKeys: true,
		AutoAddress: true, Keepalive: 25, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if countIPv4(t, q.AllowedIPs) != 1 {
		t.Fatalf("留空时应自动分配一个地址：%v", q.AllowedIPs)
	}
	if containsCIDR(q.AllowedIPs, "10.10.0.9/32") {
		t.Fatalf("自动分配应当避开已被占用的地址：%v", q.AllowedIPs)
	}
}

// TestPeerAddressOverlapRejected 同一连接里的地址**重叠**必须被拒绝，而不只是「完全相同」。
//
// WireGuard 的准入地址是一张按前缀索引的表：两个节点声明同一个地址时，只有一个能收到流量，
// 另一个永远不通。而"集合完全相同"这种比对放过了
// {10.20.0.3/32} 与 {10.20.0.3/32, 192.168.2.0/24} 这种最要命的情形 ——
// 那正是「设备与对端 NAS 抢地址」：对端 NAS 在界面上看着在线，实际永远不通。
func TestPeerAddressOverlapRejected(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svcA, _ := newTestEnv(t)
	svcB, _ := newTestEnv(t)
	fixedHomeLAN(t, svcA, "192.168.1.0/24")
	fixedHomeLAN(t, svcB, "192.168.2.0/24")

	// 用真实的互联流程建出站点条目：A 生成邀请、B 导入
	created, err := svcA.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName: "nas-b", PeerLANSubnets: []string{"192.168.9.0/24"},
		LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	inv, err := service.ParseInterconnectInvite([]byte(created.InviteJSON))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svcB.ImportInterconnect(ctx, inv, 0, actor); err != nil {
		t.Fatal(err)
	}

	ifs, err := svcB.ListInterfaces(ctx)
	if err != nil || len(ifs) != 1 {
		t.Fatalf("B 上应当有一条互联连接：%v / %v", ifs, err)
	}
	ifaceID := ifs[0].ID
	peers, err := svcB.ListPeers(ctx, 0)
	if err != nil || len(peers) != 1 || !peers[0].SiteLink {
		t.Fatalf("B 上应当只有一条站点条目：%+v / %v", peers, err)
	}
	// 对端 NAS 自己的隧道地址（落在本连接网段内的那一项）；本机的地址就是邀请里给的那一个
	peerAddr := tunnelAddrIn(t, peers[0].AllowedIPs, created.TunnelSubnet)
	myAddr := created.PeerTunnelAddress + "/32"

	// 1) 与「对端 NAS 条目」抢地址：必须拒绝，并说清是与谁冲突
	_, err = svcB.CreatePeer(ctx, service.PeerInput{
		InterfaceID: ifaceID, Name: "我的手机", GenerateKeys: true,
		AllowedIPs: []string{peerAddr}, Enabled: boolPtr(true),
	}, actor)
	if err == nil {
		t.Fatal("设备地址与对端 NAS 条目重叠时必须拒绝")
	}
	if !strings.Contains(err.Error(), "对端 NAS") {
		t.Fatalf("要说清是与「对端 NAS」冲突（否则用户不知道该改哪一边），实际：%v", err)
	}

	// 2) 与本机这条连接的专用地址重叠：等于把设备配成了 NAS 自己
	_, err = svcB.CreatePeer(ctx, service.PeerInput{
		InterfaceID: ifaceID, Name: "我的手机", GenerateKeys: true,
		AllowedIPs: []string{myAddr}, Enabled: boolPtr(true),
	}, actor)
	if err == nil || !strings.Contains(err.Error(), "本机") {
		t.Fatalf("设备地址与本机专用地址重叠时必须拒绝，实际：%v", err)
	}

	// 3) 不重叠的地址照常可建，且不会被追加第二个地址
	ok, err := svcB.CreatePeer(ctx, service.PeerInput{
		InterfaceID: ifaceID, Name: "我的手机", GenerateKeys: true, AutoAddress: true,
		AllowedIPs: []string{hostLastOctet(t, created.TunnelSubnet, 100)}, Keepalive: 25,
		Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatalf("不冲突的地址应当能建：%v", err)
	}
	if countIPv4(t, ok.AllowedIPs) != 1 {
		t.Fatalf("手填地址后不该再追加自动地址：%v", ok.AllowedIPs)
	}

	// 4) 编辑时同样要拦：把已有设备的地址改成与对端 NAS 重叠
	if _, err := svcB.UpdatePeer(ctx, ok.ID, service.PeerInput{
		InterfaceID: ifaceID, Name: ok.Name, RouteMode: model.RouteModeLAN,
		AllowedIPs: []string{peerAddr}, Keepalive: 25, Enabled: boolPtr(true),
	}, actor); err == nil {
		t.Fatal("编辑成与对端 NAS 重叠的地址时必须拒绝")
	}
}

// handInvite 手搓一份邀请：网段与地址全部写死，用例才不依赖本机随机的基准偏移。
//
// occupied 是对端随邀请带来的「已占用隧道网段」清单（老邀请没有这一项，传 nil 即可）。
func handInvite(t *testing.T, occupied []string) service.InterconnectInvite {
	t.Helper()
	return service.InterconnectInvite{
		Kind:    service.InterconnectKind,
		Version: service.InterconnectVersion,
		Site: service.InterconnectSite{
			Name: "nas-a", PublicKey: mustPublicKey(t),
			Endpoint:        "b.example.com:51820",
			TunnelAddress:   "10.20.0.1/24",
			LANSubnets:      []string{"192.168.9.0/24"},
			OccupiedSubnets: occupied,
		},
		Peer: service.InterconnectPeerParams{
			PrivateKey:    mustKey(t),
			PresharedKey:  mustKey(t),
			TunnelAddress: "10.20.0.2/24",
			TunnelSubnet:  "10.20.0.0/24",
			MTU:           1380,
		},
	}
}

// inspectItem 取体检里某一项的结论；取不到直接失败（缺项会让报告显示「全部通过」）。
func inspectItem(t *testing.T, svc *service.Service, key string) service.InspectItem {
	t.Helper()
	items := svc.InspectChecks(context.Background())
	for _, it := range items {
		if it.Key == key {
			return it
		}
	}
	t.Fatalf("体检里应当有 %q 这一项，实际只有 %d 项", key, len(items))
	return service.InspectItem{}
}

// TestInterconnectPreviewDoesNotPersist 预检必须是只读的。
//
// 它只是把「将要做什么」算出来给用户确认：若顺手把连接与条目建出来，
// 用户点一次「检查一下」就等于导入了 —— 而他还以为自己只是在看。
// 同时钉住「预检说的端口/连接名就是执行后实际用的」：不一致的话，
// 确认框里的话就成了另一件事，用户按着它核对端口映射必然核错。
func TestInterconnectPreviewDoesNotPersist(t *testing.T) {
	ctx := context.Background()
	svc, _ := newTestEnv(t)
	fixedHomeLAN(t, svc, "192.168.1.0/24")

	inv := handInvite(t, []string{"10.20.0.0/24", "10.30.0.0/24"})
	pv, err := svc.PreviewInterconnect(ctx, inv, 0)
	if err != nil {
		t.Fatal(err)
	}
	// 只读：连接与条目都还不该存在
	if ifs, err := svc.Store.ListInterfaces(ctx); err != nil || len(ifs) != 0 {
		t.Fatalf("预检不该建出连接：%v / %v", ifs, err)
	}
	if ps, err := svc.Store.ListPeers(ctx, 0); err != nil || len(ps) != 0 {
		t.Fatalf("预检不该建出对端条目：%v / %v", ps, err)
	}
	if pv.InterfaceName == "" || pv.ListenPort <= 0 {
		t.Fatalf("预检必须给出具体的连接名与监听端口：%+v", pv)
	}
	if pv.TunnelSubnet != "10.20.0.0/24" || pv.TunnelAddress != "10.20.0.2/24" {
		t.Fatalf("预检应说清隧道地址与网段：%+v", pv)
	}
	if !containsCIDR(pv.AllowedIPs, "10.20.0.1/32") || !containsCIDR(pv.AllowedIPs, "192.168.9.0/24") {
		t.Fatalf("准入地址应对端 NAS 地址 + 对端内网网段：%v", pv.AllowedIPs)
	}
	if !containsCIDR(pv.ClientAllowed, "192.168.1.0/24") {
		t.Fatalf("应说清本机暴露给对端的网段：%v", pv.ClientAllowed)
	}
	// 会写进策略路由表的只有「隧道网段之外」的那些：对端 NAS 的 /32 落在本连接的
	// 隧道网段里，由内核为该网卡自动建立的直连路由覆盖，本应用不会为它加路由。
	if !containsCIDR(pv.RouteSubnets, "192.168.9.0/24") {
		t.Fatalf("对端内网网段应进路由表：%v", pv.RouteSubnets)
	}
	if containsCIDR(pv.RouteSubnets, "10.20.0.1/32") {
		t.Fatalf("落在隧道网段内的地址不该进路由表：%v", pv.RouteSubnets)
	}
	// 两端共用的互联网段不进「已占用」清单：本机这条互联连接自己就占着它，
	// 列进去只会让「本机网段与对端占用重叠」的体检项永远成立。
	if len(pv.OccupiedByPeer) != 1 || pv.OccupiedByPeer[0] != "10.30.0.0/24" {
		t.Fatalf("对端已占用清单应只留下值得避开的那些，实际：%v", pv.OccupiedByPeer)
	}
	if pv.PeerEndpoint != "b.example.com:51820" {
		t.Fatalf("应回报对端地址：%q", pv.PeerEndpoint)
	}
	found := false
	for _, w := range pv.Warnings {
		if strings.Contains(w, "10.30.0.0/24") {
			found = true
		}
	}
	if !found {
		t.Fatalf("预检必须把「对端已占用哪些网段」说给用户：%v", pv.Warnings)
	}
}

// TestInterconnectPreviewPortMatchesImport 预检给出的端口与连接名，就是执行后实际用的。
func TestInterconnectPreviewPortMatchesImport(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svc, _ := newTestEnv(t)
	fixedHomeLAN(t, svc, "192.168.1.0/24")

	inv := handInvite(t, nil)
	pv, err := svc.PreviewInterconnect(ctx, inv, 0)
	if err != nil {
		t.Fatal(err)
	}
	// 前端会把预检选定的端口回填进输入框再执行；这里按同样的方式走一遍。
	got, err := svc.ImportInterconnect(ctx, inv, pv.ListenPort, actor)
	if err != nil {
		t.Fatal(err)
	}
	if got.ListenPort != pv.ListenPort {
		t.Fatalf("预检说的端口（%d）与实际建的（%d）不一致", pv.ListenPort, got.ListenPort)
	}
	if got.InterfaceName != pv.InterfaceName {
		t.Fatalf("预检说的连接名（%q）与实际建的（%q）不一致", pv.InterfaceName, got.InterfaceName)
	}
}

// TestInterconnectReservedSubnetVisible 覆盖「两端设备地址撞车」里**事后无从自查**的那一类：
// 对端占用网段落库 + 本机连接网段与它重叠时体检报出来。
//
// 撞车的现象只是「能访问对端 NAS、访问不了对端的某几台设备」，成因与现象之间
// 从界面上完全推不出关系，因此必须长期可见，而不是只在导入那一刻提示一次。
func TestInterconnectReservedSubnetVisible(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svc, _ := newTestEnv(t)
	fixedHomeLAN(t, svc, "192.168.1.0/24")

	inv := handInvite(t, []string{"10.20.0.0/24", "10.30.0.0/24"})
	if _, err := svc.ImportInterconnect(ctx, inv, 0, actor); err != nil {
		t.Fatal(err)
	}

	// 1) 台账落库：只留「值得避开」的（对端的另一条连接网段）
	// 用服务层的 ListPeers：它才会填「这条是站点条目」的派生标记（SiteLink 不落库）。
	peers, err := svc.ListPeers(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 || !peers[0].SiteLink {
		t.Fatalf("导入后应当有一条站点条目：%+v", peers)
	}
	if len(peers[0].SiteOccupied) != 1 || peers[0].SiteOccupied[0] != "10.30.0.0/24" {
		t.Fatalf("对端已占用网段应落库且不含两端共用的互联网段，实际：%v", peers[0].SiteOccupied)
	}

	// 2) 体检：有台账、没重叠 → 报「没重复」
	if it := inspectItem(t, svc, "site-subnet-overlap"); it.Level != "ok" {
		t.Fatalf("没有重叠时应当是 ok，实际 %s：%s", it.Level, it.Detail)
	}

	// 3) 手工把新连接的网段设成与对端占用相同：只警告、不阻断。
	//    硬拦会让人改不掉 —— 那份清单是「导入那一刻」的快照，可能早就过期了。
	enabled := true
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg7", Addresses: []string{"10.30.0.1/24"}, Enabled: &enabled,
	}, actor); err != nil {
		t.Fatalf("手工填一个与对端占用重叠的网段不该被阻断（清单可能过期）：%v", err)
	}
	it := inspectItem(t, svc, "site-subnet-overlap")
	if it.Level != "warning" {
		t.Fatalf("重叠时必须报出来，实际 %s：%s", it.Level, it.Detail)
	}
	if !strings.Contains(it.Detail, "wg7") || it.Fix == "" {
		t.Fatalf("要说清是哪条连接、并给出处置办法：%+v", it)
	}
}

// TestInstallIDPerMachine 安装标识：每台机器各不相同。
//
// 它是「默认网段跨机去相关」的种子：两台机器的标识不同，各自第 N 条连接才会挑到不同网段。
// 标识**不随备份还原一起走**（见 applyBackupPayload），因此「同源」只可能来自手工拷贝整机数据。
func TestInstallIDPerMachine(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svcA, _ := newTestEnv(t)
	svcB, _ := newTestEnv(t)

	// 新建连接会顺带生成安装标识（默认网段的基准由它派生）
	idOf := func(svc *service.Service) string {
		if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{Enabled: boolPtr(true)}, actor); err != nil {
			t.Fatal(err)
		}
		return svc.Store.GetSetting(ctx, service.SettingInstallID, "")
	}
	idA, idB := idOf(svcA), idOf(svcB)
	if idA == "" || idB == "" {
		t.Fatal("新建连接后应当已经生成安装标识")
	}
	if idA == idB {
		t.Fatalf("两台机器的安装标识不应相同：%q", idA)
	}
}

// TestInterconnectWarnsOnSameInstallID 两台机器「同源」（安装标识相同）必须在导入时点破。
//
// 同源意味着以后各自新建的连接还会挑到同一个网段 —— 那正是「两端设备地址成对重复」的根源，
// 而用户不可能从界面上推出来。不阻断导入（站点隧道本身能通），但必须当场说清。
func TestInterconnectWarnsOnSameInstallID(t *testing.T) {
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	svcA, _ := newTestEnv(t)
	svcB, _ := newTestEnv(t)
	fixedHomeLAN(t, svcA, "192.168.1.0/24")
	fixedHomeLAN(t, svcB, "192.168.2.0/24")

	created, err := svcA.CreateInterconnect(ctx, service.InterconnectInput{
		PeerName: "nas-b", PeerLANSubnets: []string{"192.168.9.0/24"},
		LocalLANSubnets: []string{"192.168.1.0/24"},
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if created.Invite.Site.InstallID == "" {
		t.Fatal("邀请里应当带上本机的安装标识（对方据此判断是否同源）")
	}

	// 让 B 与 A 变成「同一份数据装出来的」
	if err := svcB.Store.SetSetting(ctx, service.SettingInstallID, created.Invite.Site.InstallID); err != nil {
		t.Fatal(err)
	}
	inv, err := service.ParseInterconnectInvite([]byte(created.InviteJSON))
	if err != nil {
		t.Fatal(err)
	}
	got, err := svcB.ImportInterconnect(ctx, inv, 0, actor)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "安装标识") {
			found = true
		}
	}
	if !found {
		t.Fatalf("两台机器同源时必须点破，实际提醒：%v", got.Warnings)
	}
}

// tunnelAddrIn 取准入地址里落在给定网段内的那一项（对端 NAS 的隧道地址，形如 10.20.0.1/32）。
func tunnelAddrIn(t *testing.T, list []string, subnet string) string {
	t.Helper()
	_, sn, err := net.ParseCIDR(subnet)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range list {
		ip, _, err := net.ParseCIDR(strings.TrimSpace(a))
		if err == nil && sn.Contains(ip) {
			return a
		}
	}
	t.Fatalf("准入地址里找不到落在 %s 内的项：%v", subnet, list)
	return ""
}

// hostLastOctet 按隧道网段造一个末位为 last 的 /32 地址（10.20.0.0/24 + 100 → 10.20.0.100/32）。
func hostLastOctet(t *testing.T, subnet string, last int) string {
	t.Helper()
	ip, n, err := net.ParseCIDR(subnet)
	if err != nil {
		t.Fatal(err)
	}
	base := ip.Mask(n.Mask).To4()
	if base == nil {
		t.Fatalf("用例只处理 IPv4 网段：%s", subnet)
	}
	return (&net.IPNet{IP: net.IPv4(base[0], base[1], base[2], byte(last)), Mask: net.CIDRMask(32, 32)}).String()
}
