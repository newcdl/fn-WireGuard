// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

func snapshotFileCount(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "fn-wireguard-snapshot-") {
			n++
		}
	}
	return n
}

// TestSnapshotAutoCaptureAndRollback 覆盖 P2-3 的主链路：
// 关键操作自动留档 → 查看差异 → 一键回滚，配置回到快照时的状态。
func TestSnapshotAutoCaptureAndRollback(t *testing.T) {
	svc, st, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", ListenPort: 51820, Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor)
	if err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	for _, name := range []string{"手机", "笔记本"} {
		if _, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID: it.ID, Name: name, GenerateKeys: true, GeneratePSK: true,
		}, actor); err != nil {
			t.Fatalf("创建设备失败: %v", err)
		}
	}

	// 自动留档应当已经在关键操作前发生
	auto, err := svc.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	if len(auto) < 3 {
		t.Fatalf("关键操作应各自留档，期望至少 3 份，实际 %d", len(auto))
	}
	if auto[0].Kind != "auto" {
		t.Fatalf("快照类型应为 auto，实际 %s", auto[0].Kind)
	}

	base, err := svc.CreateSnapshot(ctx, "基线", actor)
	if err != nil {
		t.Fatalf("手动留档失败: %v", err)
	}
	if base == nil {
		t.Fatal("基线快照未生成")
	}

	// 连续改动：换监听端口 + 删掉一台设备
	if _, err := svc.UpdateInterface(ctx, it.ID, service.CreateInterfaceInput{
		Name: "wg0", ListenPort: 51999, Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("修改连接失败: %v", err)
	}
	peers, err := svc.ListPeers(ctx, it.ID)
	if err != nil {
		t.Fatalf("读取设备失败: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("设备数应为 2，实际 %d", len(peers))
	}
	if err := svc.DeletePeer(ctx, peers[0].ID, actor); err != nil {
		t.Fatalf("删除设备失败: %v", err)
	}

	// 差异必须如实反映「端口变了 + 少了一台设备」
	diff, err := svc.SnapshotDiff(ctx, dir, base.ID)
	if err != nil {
		t.Fatalf("差异计算失败: %v", err)
	}
	if diff.Empty {
		t.Fatal("配置已改动，差异不应为空")
	}
	if diff.Interfaces.Count() == 0 {
		t.Fatal("应检测到连接变化")
	}
	if len(diff.Peers.Removed) != 1 {
		t.Fatalf("应检测到 1 台设备被删除，实际 %d", len(diff.Peers.Removed))
	}
	if !strings.Contains(diff.Summary, "回滚将撤销") {
		t.Fatalf("差异摘要不可读: %s", diff.Summary)
	}

	if _, err := svc.RollbackSnapshot(ctx, dir, base.ID, actor); err != nil {
		t.Fatalf("回滚失败: %v", err)
	}

	ifaces, err := st.ListInterfaces(ctx)
	if err != nil {
		t.Fatalf("回滚后读取连接失败: %v", err)
	}
	if len(ifaces) != 1 {
		t.Fatalf("回滚后应剩 1 条连接，实际 %d", len(ifaces))
	}
	if ifaces[0].ListenPort != 51820 {
		t.Fatalf("监听端口未回滚，期望 51820，实际 %d", ifaces[0].ListenPort)
	}
	peers, err = st.ListPeers(ctx, ifaces[0].ID)
	if err != nil {
		t.Fatalf("回滚后读取设备失败: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("回滚后设备数应为 2，实际 %d", len(peers))
	}

	// 回滚后差异应为空：回滚到位了，而不是「看起来回滚了」
	diff, err = svc.SnapshotDiff(ctx, dir, base.ID)
	if err != nil {
		t.Fatalf("回滚后差异计算失败: %v", err)
	}
	if !diff.Empty {
		t.Fatalf("回滚后应与快照完全一致，实际差异: %s", diff.Summary)
	}
}

// TestSnapshotExcludesAccounts 保证「回滚配置」不会顺手回退账号安全设置。
//
// 管理员改密码通常是因为旧密码可能泄露。若回滚配置把密码哈希一起退回旧值，
// 等于用一个已经被怀疑泄露的密码重新打开大门——这是安全倒退，不是恢复。
func TestSnapshotExcludesAccounts(t *testing.T) {
	svc, st, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	// 回滚要求快照里有连接，先建一条
	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", ListenPort: 51820, Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	oldHash, err := service.HashPassword("old-password-1")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateUser(ctx, &model.User{
		Username: "admin", PasswordHash: oldHash, TOTPSecret: "OLDSECRET",
		Role: model.RoleAdmin, Status: 1,
	}); err != nil {
		t.Fatalf("创建账号失败: %v", err)
	}
	snap, err := svc.CreateSnapshot(ctx, "改密码前", actor)
	if err != nil || snap == nil {
		t.Fatalf("留档失败: %v", err)
	}

	// 快照文件本身就不该带账号
	payload, _, err := svc.LoadBackupPayload(ctx, dir, snap.ID)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	if len(payload.Users) != 0 {
		t.Fatalf("配置快照不应包含账号，实际 %d 条", len(payload.Users))
	}

	u, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateUser(ctx, u.ID, model.RoleAdmin, 1, "new-password-2", actor); err != nil {
		t.Fatalf("改密码失败: %v", err)
	}
	after, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := svc.RollbackSnapshot(ctx, dir, snap.ID, actor); err != nil {
		t.Fatalf("回滚失败: %v", err)
	}
	final, err := st.GetUserByUsername(ctx, "admin")
	if err != nil {
		t.Fatalf("回滚后账号丢失: %v", err)
	}
	if final.PasswordHash != after.PasswordHash {
		t.Fatal("回滚配置篡改了密码哈希，回滚不应触碰账号")
	}
	if final.TOTPSecret != "OLDSECRET" {
		t.Fatalf("回滚配置篡改了二次验证密钥，实际: %s", final.TOTPSecret)
	}
}

// TestSnapshotSkipsUnchangedConfig 验证去重：配置没变就不堆同样的文件。
func TestSnapshotSkipsUnchangedConfig(t *testing.T) {
	svc, _, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	first, err := svc.CreateSnapshot(ctx, "第一次", actor)
	if err != nil {
		t.Fatalf("留档失败: %v", err)
	}
	if first == nil {
		t.Fatal("首次留档不应被跳过")
	}
	second, err := svc.CreateSnapshot(ctx, "第二次", actor)
	if err != nil {
		t.Fatalf("留档失败: %v", err)
	}
	if second != nil {
		t.Fatal("配置未变化时不应重复留档")
	}
}

// TestSnapshotPruneKeepsLimit 验证保留策略：超出份数的旧快照连同文件一起清理。
func TestSnapshotPruneKeepsLimit(t *testing.T) {
	svc, st, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if err := st.SetSetting(ctx, service.SettingSnapshotKeep, "3"); err != nil {
		t.Fatalf("写入保留份数失败: %v", err)
	}
	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor)
	if err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	// 连加 6 台设备，每台之前的内容都不同，必然各留一份
	for i := 0; i < 6; i++ {
		if _, err := svc.CreatePeer(ctx, service.PeerInput{
			InterfaceID: it.ID, Name: "dev-" + strings.Repeat("x", i+1), GenerateKeys: true,
		}, actor); err != nil {
			t.Fatalf("创建设备失败: %v", err)
		}
	}

	recs, err := svc.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	if len(recs) != 3 {
		t.Fatalf("保留份数应为 3，实际 %d", len(recs))
	}
	if got := snapshotFileCount(t, dir); got != 3 {
		t.Fatalf("过期快照文件也应清理，期望 3 个，实际 %d", got)
	}
}

// TestSnapshotsStayOutOfBackupList 保证自动快照不会淹没用户自己存的备份。
func TestSnapshotsStayOutOfBackupList(t *testing.T) {
	svc, _, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	if _, err := svc.CreateBackup(ctx, dir, "手动备份", actor); err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}

	backups, err := svc.ListUserBackups(ctx)
	if err != nil {
		t.Fatalf("读取备份失败: %v", err)
	}
	if len(backups) != 1 || backups[0].Kind != "manual" {
		t.Fatalf("备份列表应只含手动备份，实际 %+v", backups)
	}
	snaps, err := svc.ListSnapshots(ctx)
	if err != nil {
		t.Fatalf("读取快照失败: %v", err)
	}
	if len(snaps) == 0 {
		t.Fatal("快照列表不应为空")
	}
}

// TestBackupCoversDNSRecords 验证备份把内网域名一并存档并能还原。
//
// 域名映射也是配置：只备份连接和设备的话，还原后设备用主机名访问家里设备会失败，
// 用户会以为「备份还原坏了」。
func TestBackupCoversDNSRecords(t *testing.T) {
	svc, st, dir := newTestEnvWithDir(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	if _, err := svc.CreateDNSRecord(ctx, service.DNSRecordInput{Name: "nas.lan", IP: "10.10.0.9"}, actor); err != nil {
		t.Fatalf("新增域名失败: %v", err)
	}
	rec, err := svc.CreateBackup(ctx, dir, "含域名", actor)
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	if err := svc.DeleteDNSRecord(ctx, 1, actor); err != nil {
		t.Fatalf("删除域名失败: %v", err)
	}
	if recs, _ := st.ListDNSRecords(ctx); len(recs) != 0 {
		t.Fatalf("删除后应无域名，实际 %d", len(recs))
	}
	if _, err := svc.RestoreBackup(ctx, dir, rec.ID, actor); err != nil {
		t.Fatalf("还原失败: %v", err)
	}
	recs, err := st.ListDNSRecords(ctx)
	if err != nil {
		t.Fatalf("还原后读取域名失败: %v", err)
	}
	if len(recs) != 1 || recs[0].Name != "nas.lan" || recs[0].IP != "10.10.0.9" {
		t.Fatalf("内网域名未还原，实际 %+v", recs)
	}
}

// TestRollbackRejectsNonSnapshot 保证回滚只作用于配置快照，不会拿手动备份来「回滚」。
func TestRollbackRejectsNonSnapshot(t *testing.T) {
	svc, _, dir := newTestEnvWithDir(t)
	svc.SetSnapshotDir(dir)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	if _, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}, actor); err != nil {
		t.Fatalf("创建连接失败: %v", err)
	}
	rec, err := svc.CreateBackup(ctx, dir, "手动备份", actor)
	if err != nil {
		t.Fatalf("创建备份失败: %v", err)
	}
	if _, err := svc.RollbackSnapshot(ctx, dir, rec.ID, actor); err == nil {
		t.Fatal("手动备份不应允许走快照回滚")
	}
}
