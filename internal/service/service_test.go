// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fnwg/internal/core"
	"fnwg/internal/model"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/service"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
)

// newTestEnv 搭建一套完整的服务环境：临时数据库 + 内存数据面后端 + 收敛引擎。
//
// 这里必须显式用 NewMock，不能用 New：New 在 Linux 上返回的是**真实内核后端**，
// 而业务层测试会走到 Reconcile / DeleteInterface，真实的 netlink 调用需要
// CAP_NET_ADMIN —— CI 的 runner 以非 root 运行，结果必然是
// 「创建接口失败: operation not permitted」。
func newTestEnv(t *testing.T) (*service.Service, *store.Store) {
	t.Helper()
	svc, st, _ := newTestEnvWithDir(t)
	return svc, st
}

// newTestEnvWithDir 与 newTestEnv 相同，但额外返回共享目录。
// 配置快照要落盘到共享目录，测试需要显式 svc.SetSnapshotDir(dir) 才会启用自动留档。
func newTestEnvWithDir(t *testing.T) (*service.Service, *store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := wgback.NewMock(filepath.Join(dir, "netstate.json"))
	engine := reconcile.New(st, backend, logger)
	svc := service.New(st, core.NewLocal(engine), logger, "test")
	return svc, st, dir
}

func TestInterfaceAndPeerLifecycle(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name:      "wg0",
		Addresses: []string{"10.10.0.1/24"},
		DNS:       []string{"223.5.5.5"},
		Enabled:   true,
		Autostart: true,
	}, actor)
	if err != nil {
		t.Fatalf("创建接口失败: %v", err)
	}
	if it.ListenPort != 51820 {
		t.Fatalf("未应用默认监听端口: %d", it.ListenPort)
	}
	if it.MTU != 1420 {
		t.Fatalf("未应用默认 MTU: %d", it.MTU)
	}
	if it.PrivateKey == "" || it.PublicKey == "" {
		t.Fatal("创建接口时应生成密钥对并回显一次")
	}

	// 列表接口不应回传私钥
	list, err := svc.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].PrivateKey != "" {
		t.Fatal("列表接口不应包含私钥")
	}

	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID:  it.ID,
		Name:         "我的手机",
		GenerateKeys: true,
		GeneratePSK:  true,
		AutoAddress:  true,
		Keepalive:    25,
		Enabled:      true,
	}, actor)
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.10.0.2/32" {
		t.Fatalf("自动分配地址错误: %v", p.AllowedIPs)
	}
	if p.ClientPrivateKey == "" || p.PresharedKey == "" {
		t.Fatal("创建节点时应生成密钥与预共享密钥")
	}

	// 第二个节点应分配到下一个空闲地址
	p2, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "笔记本", GenerateKeys: true, AutoAddress: true, Enabled: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(p2.AllowedIPs) != 1 || p2.AllowedIPs[0] != "10.10.0.3/32" {
		t.Fatalf("第二个节点地址分配错误: %v", p2.AllowedIPs)
	}

	// 客户端配置应可被解析且包含服务端公钥
	conf, err := svc.PeerConfig(ctx, p.ID)
	if err != nil {
		t.Fatalf("生成客户端配置失败: %v", err)
	}
	if !strings.Contains(conf.Conf, "[Interface]") || !strings.Contains(conf.Conf, "[Peer]") {
		t.Fatalf("客户端配置内容异常:\n%s", conf.Conf)
	}
	if !strings.Contains(conf.Conf, "PublicKey = "+it.PublicKey) {
		t.Fatalf("客户端配置缺少服务端公钥:\n%s", conf.Conf)
	}
	if !strings.Contains(conf.Conf, "Address = 10.10.0.2/32") {
		t.Fatalf("客户端配置缺少隧道地址:\n%s", conf.Conf)
	}

	// 更新接口时不携带私钥，私钥必须保留
	updated, err := svc.UpdateInterface(ctx, it.ID, service.CreateInterfaceInput{
		Name:       "wg0",
		ListenPort: 51821,
		MTU:        1400,
		Addresses:  []string{"10.10.0.1/24"},
		DNSMode:    "client",
		RouteTable: "auto",
		Enabled:    true,
		Autostart:  true,
	}, actor)
	if err != nil {
		t.Fatalf("更新接口失败: %v", err)
	}
	if updated.ListenPort != 51821 || updated.MTU != 1400 {
		t.Fatalf("接口字段未更新: %+v", updated)
	}
	stored, err := svc.ListInterfaces(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 1 || stored[0].ListenPort != 51821 {
		t.Fatal("接口更新未落库")
	}
	// 私钥未被清空（通过能否继续生成客户端配置间接验证）
	if _, err := svc.PeerConfig(ctx, p.ID); err != nil {
		t.Fatalf("更新接口后应仍可生成客户端配置: %v", err)
	}

	// 批量禁用
	if _, err := svc.BatchPeers(ctx, service.BatchPeerRequest{
		IDs: []int64{p.ID, p2.ID}, Action: "disable",
	}, actor); err != nil {
		t.Fatalf("批量禁用失败: %v", err)
	}
	peers, err := svc.ListPeers(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range peers {
		if peer.Enabled {
			t.Fatalf("节点 %s 应已被禁用", peer.Name)
		}
	}

	// 启用后删除节点
	if _, err := svc.BatchPeers(ctx, service.BatchPeerRequest{IDs: []int64{p.ID}, Action: "enable"}, actor); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeletePeer(ctx, p.ID, actor); err != nil {
		t.Fatalf("删除节点失败: %v", err)
	}
	peers, _ = svc.ListPeers(ctx, it.ID)
	if len(peers) != 1 {
		t.Fatalf("删除后节点数量错误: %d", len(peers))
	}

	// 删除接口会级联删除节点
	if err := svc.DeleteInterface(ctx, it.ID, actor); err != nil {
		t.Fatalf("删除接口失败: %v", err)
	}
	if list, _ := svc.ListInterfaces(ctx); len(list) != 0 {
		t.Fatal("接口未被删除")
	}
	if peers, _ := svc.ListPeers(ctx, 0); len(peers) != 0 {
		t.Fatal("接口删除后其节点应被级联清理")
	}
}

func TestValidation(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "WG0!", Addresses: []string{"10.10.0.1/24"},
	}, actor); err == nil {
		t.Fatal("非法接口名应被拒绝")
	}
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"not-a-cidr"},
	}, actor); err == nil {
		t.Fatal("非法网段应被拒绝")
	}
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.20.0.1/24"},
	}, actor); err == nil {
		t.Fatal("重名接口应被拒绝")
	}
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, PublicKey: "not-a-key", Enabled: true,
	}, actor); err == nil {
		t.Fatal("非法公钥应被拒绝")
	}
}

// TestInterfaceCrossConnectionConflicts 回归：监听端口重复与内部地址网段重叠
// 必须在业务层就被拒绝并给出可读的中文提示，不能留到内核层才报错。
func TestInterfaceCrossConnectionConflicts(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	first, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, ListenPort: 51820,
		Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// 端口与已有连接重复：提示应点名占用的连接
	_, err = svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"10.11.0.1/24"}, ListenPort: 51820,
		Enabled: true, Autostart: true,
	}, actor)
	if err == nil || !strings.Contains(err.Error(), "51820") || !strings.Contains(err.Error(), "wg0") {
		t.Fatalf("端口重复应被拒绝并提示占用的连接，实际: %v", err)
	}

	// 内部地址网段与已有连接重叠
	_, err = svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"10.10.0.5/24"}, ListenPort: 51821,
		Enabled: true, Autostart: true,
	}, actor)
	if err == nil || !strings.Contains(err.Error(), "重叠") {
		t.Fatalf("网段重叠应被拒绝，实际: %v", err)
	}

	// 不同协议族不算冲突（V6 网段与 V4 网段永远不重叠）
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg1", Addresses: []string{"fd00::1/64"}, ListenPort: 51821,
		Enabled: true, Autostart: true,
	}, actor); err != nil {
		t.Fatalf("不同协议族不应判定为冲突: %v", err)
	}

	// 更新连接时不应与自身判定为冲突
	if _, err := svc.UpdateInterface(ctx, first.ID, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, ListenPort: 51820,
		MTU: 1420, DNSMode: "client", RouteTable: "off", Enabled: true, Autostart: true,
	}, actor); err != nil {
		t.Fatalf("更新自身不应报冲突: %v", err)
	}
}

// TestInterfaceAutoAllocation 回归：地址与端口留空时应按连接序号自动错开，
// 新建第二条连接不必手工改端口和网段。
func TestInterfaceAutoAllocation(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	// 名称、地址、端口全部留空 → 自动分配 wg0 / 10.10.0.1/24 / 51820
	first, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{Enabled: true, Autostart: true}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "wg0" || first.ListenPort != 51820 || first.Addresses[0] != "10.10.0.1/24" {
		t.Fatalf("首条连接的默认值不正确: %s %d %v", first.Name, first.ListenPort, first.Addresses)
	}

	// 第二条同样留空 → 名称顺延为 wg1，地址与端口同步递增，从源头避开冲突
	second, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{Enabled: true, Autostart: true}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if second.Name != "wg1" || second.ListenPort != 51821 || second.Addresses[0] != "10.11.0.1/24" {
		t.Fatalf("第二条连接的默认值未随名称递增: %s %d %v", second.Name, second.ListenPort, second.Addresses)
	}

	// 指定名称 wg5、地址与端口留空 → 按名称序号给出 10.15.0.1/24 + 51825
	third, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg5", Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if third.ListenPort != 51825 || third.Addresses[0] != "10.15.0.1/24" {
		t.Fatalf("按名称序号分配不正确: %d %v", third.ListenPort, third.Addresses)
	}

	// 非 wgN 命名从 0 号位起顺延，跳过已被占用的端口与网段，而不是直接报冲突
	fourth, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "office", Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if fourth.ListenPort != 51822 || fourth.Addresses[0] != "10.12.0.1/24" {
		t.Fatalf("未跳过已占用的端口/网段: %d %v", fourth.ListenPort, fourth.Addresses)
	}

	// 用户显式指定的取值必须原样保留，不被自动分配覆盖
	fifth, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "custom", ListenPort: 52000, Addresses: []string{"172.20.0.1/24"},
		Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if fifth.ListenPort != 52000 || fifth.Addresses[0] != "172.20.0.1/24" {
		t.Fatalf("显式指定的取值被覆盖: %d %v", fifth.ListenPort, fifth.Addresses)
	}
}

func TestImportExportAndBackup(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	dir := t.TempDir()

	confText := `[Interface]
PrivateKey = aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5ISE=
Address = 10.66.0.1/24
ListenPort = 51820
DNS = 223.5.5.5

[Peer]
# 导入的节点
PublicKey = d29ybGQgaGVsbG8gdGhpcyBpcyBhIHRlc3Qga2V5ISE=
AllowedIPs = 10.66.0.2/32
PersistentKeepalive = 25
`
	it, count, err := svc.ImportConf(ctx, confText, "wg5", actor)
	if err != nil {
		t.Fatalf("导入失败: %v", err)
	}
	if count != 1 {
		t.Fatalf("导入节点数量错误: %d", count)
	}
	if it.Name != "wg5" || it.ListenPort != 51820 {
		t.Fatalf("导入接口字段错误: %+v", it)
	}

	filename, exported, err := svc.ExportInterface(ctx, it.ID)
	if err != nil {
		t.Fatal(err)
	}
	if filename != "wg5.conf" || !strings.Contains(exported, "ListenPort = 51820") {
		t.Fatalf("导出内容异常: %s\n%s", filename, exported)
	}
	if !strings.Contains(exported, "10.66.0.2/32") {
		t.Fatalf("导出内容缺少节点:\n%s", exported)
	}

	raw, zipName, err := svc.ExportAllZip(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || !strings.HasSuffix(zipName, ".zip") {
		t.Fatalf("打包导出异常: %s (%d 字节)", zipName, len(raw))
	}

	rec, err := svc.CreateBackup(ctx, dir, "单元测试备份", actor)
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	if rec.Size == 0 || rec.SHA256 == "" {
		t.Fatal("备份记录缺少校验信息")
	}
	// 覆盖式恢复
	if err := svc.DeleteInterface(ctx, it.ID, actor); err != nil {
		t.Fatal(err)
	}
	n, err := svc.RestoreBackup(ctx, dir, rec.ID, actor)
	if err != nil {
		t.Fatalf("恢复备份失败: %v", err)
	}
	if n != 1 {
		t.Fatalf("恢复接口数量错误: %d", n)
	}
	list, _ := svc.ListInterfaces(ctx)
	if len(list) != 1 || list[0].Name != "wg5" {
		t.Fatalf("恢复结果不正确: %+v", list)
	}
	peers, _ := svc.ListPeers(ctx, 0)
	if len(peers) != 1 || peers[0].Name != "导入的节点" {
		t.Fatalf("恢复的节点不正确: %+v", peers)
	}
}

func TestBackupFullRestore(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	dir := t.TempDir()

	// 准备现场：一个管理员账号 + 一个设置项
	hash, err := service.HashPassword("s3cret-pw")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &model.User{
		Username:     "admin",
		PasswordHash: hash,
		TOTPSecret:   "JBSWY3DPEHPK3PXP",
		Role:         model.RoleAdmin,
		Status:       1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "notify_webhook", "https://example.com/hook"); err != nil {
		t.Fatal(err)
	}

	rec, err := svc.CreateBackup(ctx, dir, "全量备份", actor)
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}

	// 破坏现场：删账号、改设置，再全量还原
	created, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteUser(ctx, created.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "notify_webhook", "https://changed.example.com"); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.RestoreBackup(ctx, dir, rec.ID, actor); err != nil {
		t.Fatalf("恢复备份失败: %v", err)
	}

	// 账号必须完整还原：密码哈希、TOTP、角色
	u, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("账号未恢复: %v", err)
	}
	if u.PasswordHash != hash {
		t.Fatal("密码哈希未还原")
	}
	if u.TOTPSecret != "JBSWY3DPEHPK3PXP" {
		t.Fatalf("TOTP 密钥未还原，实际: %s", u.TOTPSecret)
	}
	if u.Role != model.RoleAdmin {
		t.Fatalf("角色未还原: %s", u.Role)
	}
	// 设置必须还原
	if got := st.GetSetting(ctx, "notify_webhook", ""); got != "https://example.com/hook" {
		t.Fatalf("设置未还原，实际: %s", got)
	}
}

func TestBackupImportDownload(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}
	dir := t.TempDir()

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.9.0.1/24"}, Enabled: true, Autostart: true,
	}, actor); err != nil {
		t.Fatal(err)
	}
	rec, err := svc.CreateBackup(ctx, dir, "导出导入", actor)
	if err != nil {
		t.Fatal(err)
	}

	// 下载：拿到的原始内容应与记录一致
	raw, name, err := svc.DownloadBackup(ctx, dir, rec.ID)
	if err != nil {
		t.Fatalf("下载备份失败: %v", err)
	}
	if name != rec.Filename || len(raw) == 0 {
		t.Fatalf("下载内容异常: %s（%d 字节）", name, len(raw))
	}

	// 删掉原备份，模拟「从别处拿回备份文件再导入」
	if err := svc.DeleteBackup(ctx, dir, rec.ID, actor); err != nil {
		t.Fatal(err)
	}
	imported, err := svc.ImportBackup(ctx, dir, raw, rec.Filename, "导回", actor)
	if err != nil {
		t.Fatalf("导入备份失败: %v", err)
	}
	if imported.Filename != rec.Filename {
		t.Fatalf("导入文件名不符: %s", imported.Filename)
	}

	// 导入的备份应可直接还原
	if _, err := svc.RestoreBackup(ctx, dir, imported.ID, actor); err != nil {
		t.Fatalf("导入的备份还原失败: %v", err)
	}
	list, _ := svc.ListInterfaces(ctx)
	if len(list) != 1 || list[0].Name != "wg0" {
		t.Fatalf("还原结果不正确: %+v", list)
	}

	// 非法内容应被拒绝
	if _, err := svc.ImportBackup(ctx, dir, []byte("not-json"), "", "", actor); err == nil {
		t.Fatal("非法备份内容应被拒绝")
	}
}

func TestImportPeersBatch(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.20.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	res, err := svc.ImportPeers(ctx, it.ID, []service.PeerImportRow{
		{Name: "手机A"},
		{Name: "手机B", Remark: "备用"},
		{Name: "  "}, // 只有空白名称 → 应被逐条拒绝
	}, actor)
	if err != nil {
		t.Fatalf("批量导入失败: %v", err)
	}
	if res.Created != 2 || res.Failed != 1 {
		t.Fatalf("汇总不正确: created=%d failed=%d", res.Created, res.Failed)
	}
	if len(res.Items) != 3 || !res.Items[0].OK || !res.Items[1].OK || res.Items[2].OK {
		t.Fatalf("逐条结果不正确: %+v", res.Items)
	}
	if res.Items[2].Error == "" {
		t.Fatal("失败项必须带原因")
	}

	// 自动分配的内部地址必须互不相同，否则两台设备会互相抢地址
	list, _ := svc.ListPeers(ctx, it.ID)
	if len(list) != 2 {
		t.Fatalf("设备数量不正确: %d", len(list))
	}
	seen := map[string]bool{}
	for _, p := range list {
		for _, ip := range p.AllowedIPs {
			if seen[ip] {
				t.Fatalf("内部地址被重复分配: %s", ip)
			}
			seen[ip] = true
		}
	}
}

func TestImportPeersRejectsDuplicateKey(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.21.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	first, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "已有设备", AutoAddress: true, Enabled: true,
		GenerateKeys: true, GeneratePSK: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// 导入一个与已有设备相同识别码的行 → 应被逐条拒绝并给出原因
	res, err := svc.ImportPeers(ctx, it.ID, []service.PeerImportRow{
		{Name: "重复设备", PublicKey: first.PublicKey},
		{Name: "正常设备"},
	}, actor)
	if err != nil {
		t.Fatalf("批量导入失败: %v", err)
	}
	if res.Created != 1 || res.Failed != 1 {
		t.Fatalf("重复识别码应被拒绝: created=%d failed=%d", res.Created, res.Failed)
	}
	if res.Items[0].OK || res.Items[0].Error == "" {
		t.Fatalf("重复项应失败且带原因: %+v", res.Items[0])
	}
	if !res.Items[1].OK {
		t.Fatalf("正常项应成功: %+v", res.Items[1])
	}
}

func TestDNSRecordsCRUDAndValidation(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	r, err := svc.CreateDNSRecord(ctx, service.DNSRecordInput{Name: " NAS.Lan ", IP: "192.168.1.10"}, actor)
	if err != nil {
		t.Fatalf("新增失败: %v", err)
	}
	if r.Name != "nas.lan" || r.IP != "192.168.1.10" {
		t.Fatalf("名字应归一化为小写并去空白: %+v", r)
	}

	// 重名（大小写不同也算重名）
	if _, err := svc.CreateDNSRecord(ctx, service.DNSRecordInput{Name: "nas.lan", IP: "192.168.1.11"}, actor); err == nil {
		t.Fatal("重名应被拒绝")
	}

	for _, bad := range []service.DNSRecordInput{
		{Name: "", IP: "192.168.1.1"},
		{Name: "nas", IP: "not-an-ip"},
		{Name: "nas", IP: "fd00::1"}, // 目前只支持 IPv4
		{Name: "bad_name", IP: "192.168.1.1"},
		{Name: "-bad.lan", IP: "192.168.1.1"},
	} {
		if _, err := svc.CreateDNSRecord(ctx, bad, actor); err == nil {
			t.Fatalf("非法输入应被拒绝: %+v", bad)
		}
	}

	up, err := svc.UpdateDNSRecord(ctx, r.ID, service.DNSRecordInput{Name: "nas.lan", IP: "192.168.1.20", Note: "改过"}, actor)
	if err != nil {
		t.Fatalf("编辑失败: %v", err)
	}
	if up.IP != "192.168.1.20" || up.Note != "改过" {
		t.Fatalf("编辑未生效: %+v", up)
	}

	list, err := svc.ListDNSRecords(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("列表条数不对: %d (%v)", len(list), err)
	}
	if err := svc.DeleteDNSRecord(ctx, r.ID, actor); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if list, _ := svc.ListDNSRecords(ctx); len(list) != 0 {
		t.Fatalf("删除后应为空: %d", len(list))
	}
}

func TestAuthAndAudit(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	initialized, err := svc.HasUsers(ctx)
	if err != nil || initialized {
		t.Fatal("初始状态不应存在账号")
	}
	u, err := svc.Setup(ctx, "admin", "admin12345")
	if err != nil {
		t.Fatalf("初始化管理员失败: %v", err)
	}
	if u.Role != model.RoleAdmin {
		t.Fatalf("初始账号角色错误: %s", u.Role)
	}
	if _, err := svc.Setup(ctx, "other", "admin12345"); err == nil {
		t.Fatal("已初始化后不应允许重复初始化")
	}
	if _, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "wrong-password", UserAgent: "test", SrcIP: "127.0.0.1"}); err == nil {
		t.Fatal("错误口令应登录失败")
	}
	step, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "test", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if step.TOTPRequired() {
		t.Fatal("未开启二次验证的账号不应要求动态口令")
	}
	token, user := step.Token, step.User
	if user.Username != "admin" || token == "" {
		t.Fatal("登录返回值异常")
	}
	if _, err := svc.Authenticate(ctx, token); err != nil {
		t.Fatalf("令牌校验失败: %v", err)
	}
	if _, err := svc.Authenticate(ctx, "invalid-token"); err == nil {
		t.Fatal("非法令牌应校验失败")
	}

	// 写操作应产生审计记录，且哈希链完整
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, service.Actor{UserID: user.ID, Username: user.Username, SrcIP: "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	entries, total, err := svc.ListAudit(ctx, model.AuditFilter{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || len(entries) == 0 {
		t.Fatal("应产生审计记录")
	}
	intact, badID, err := svc.VerifyAudit(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !intact {
		t.Fatalf("审计链应完整，异常记录 ID=%d", badID)
	}
	if err := svc.Logout(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Authenticate(ctx, token); err == nil {
		t.Fatal("注销后令牌应失效")
	}
}

// TestPeerAllowedIPsRejectsDefaultRoute 回归：服务端准入地址绝不允许默认路由写法。
// 0.2.0 及更早版本允许在这里填 0.0.0.0/0，导致 NAS 系统默认路由被抢占、FN Connect 断网。
func TestPeerAllowedIPsRejectsDefaultRoute(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "危险配置", GenerateKeys: true, Enabled: true,
		AllowedIPs: []string{"0.0.0.0/0", "::/0"},
	}, actor); err == nil {
		t.Fatal("准入地址含 0.0.0.0/0 时必须被拒绝")
	}
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "正常配置", GenerateKeys: true, Enabled: true,
		AllowedIPs: []string{"10.10.0.2/32"}, RouteMode: model.RouteModeLAN,
	}, actor); err != nil {
		t.Fatalf("正常配置应被接受: %v", err)
	}
}

// TestClientAllowedIPsByRouteMode 验证「设备上网方式」只影响客户端配置，
// 不再以任何形式出现在 NAS 主机的路由里。
func TestClientAllowedIPsByRouteMode(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		mode     string
		custom   []string
		wantFull bool
	}{
		{model.RouteModeFull, nil, true},
		{model.RouteModeLAN, nil, false},
		{model.RouteModeCustom, []string{"10.20.0.0/24"}, false},
	}
	for _, c := range cases {
		p, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID: it.ID, Name: "设备-" + c.mode, GenerateKeys: true, Enabled: true,
			RouteMode: c.mode, ClientAllowedIPs: c.custom,
		}, actor)
		if err != nil {
			t.Fatalf("%s 模式创建失败: %v", c.mode, err)
		}
		conf, err := svc.PeerConfig(ctx, p.ID)
		if err != nil {
			t.Fatalf("%s 模式生成配置失败: %v", c.mode, err)
		}
		hasDefault := strings.Contains(conf.Conf, "0.0.0.0/0")
		if c.wantFull != hasDefault {
			t.Fatalf("%s 模式的客户端通行范围不正确（含默认路由=%v）:\n%s", c.mode, hasDefault, conf.Conf)
		}
		if c.mode == model.RouteModeCustom && !strings.Contains(conf.Conf, "10.20.0.0/24") {
			t.Fatalf("自定义模式应包含指定网段:\n%s", conf.Conf)
		}
	}
}

// TestOverviewAndReconcile(t *testing.T) 保留原有集成测试。
func TestOverviewAndReconcile(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true, Autostart: true,
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "节点A", GenerateKeys: true, AutoAddress: true, Enabled: true,
	}, actor); err != nil {
		t.Fatal(err)
	}

	actions, err := svc.ReconcileNow(ctx)
	if err != nil {
		t.Fatalf("收敛失败: %v", err)
	}
	if len(actions) == 0 {
		t.Fatal("首次收敛应产生动作")
	}
	// 刷新状态缓存后，概览应能读到内核侧数据
	deadline := time.Now().Add(3 * time.Second)
	for {
		if err := svc.Cache.Refresh(ctx); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("刷新状态缓存超时")
		}
		time.Sleep(50 * time.Millisecond)
	}
	ov, err := svc.GetOverview(ctx)
	if err != nil {
		t.Fatalf("获取概览失败: %v", err)
	}
	if ov.InterfaceCount != 1 || ov.PeerCount != 1 {
		t.Fatalf("概览统计错误: 接口 %d 节点 %d", ov.InterfaceCount, ov.PeerCount)
	}
	if ov.InterfaceUp != 1 {
		t.Fatal("接口应处于运行状态")
	}
	health := svc.Health(ctx)
	if !health.AgentUp {
		t.Fatalf("健康检查异常: %+v", health)
	}
}
