// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package agentapi_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"fnwg/internal/agentapi"
	"fnwg/internal/model"
)

// stubCore 只实现这次要往返验证的那几个方法，其余返回零值。
//
// 目的不是测业务逻辑，而是测**协议这条线本身**：方法名有没有对上、参数与返回的字段名有没有对上、
// 文件内容（[]byte → base64）能不能原样回来。这类错误编译器一条都不会报，
// 表现却全是「真机上点了没反应」—— 代理回一句「未知方法」，界面把它显示成一个没人看得懂的错误。
//
// 顺带说一句为什么不能靠 grep 二进制来验证：编译器会合并、折叠字符串常量，
// 方法名在二进制里查不到**完全正常**（一个只做字符串 switch 的最小程序，三个常量一个都搜不到）。
// 唯一能证明这件事的办法就是像这样真跑一遍。
type stubCore struct {
	dir      string
	name     string
	raw      []byte
	backupID int64
	username string
	srcIP    string
	userID   int64
	copied   string

	// 巡检：既要验证结论能不能原样回来，也要验证执行者信息有没有传过去（审计靠它）。
	inspected bool
}

func (s *stubCore) Reconcile(context.Context) ([]string, error) { return nil, nil }
func (s *stubCore) Status(context.Context) (model.Status, error) {
	return model.Status{}, nil
}
func (s *stubCore) Health(context.Context) (model.Health, error) { return model.Health{}, nil }
func (s *stubCore) DeleteInterface(context.Context, string) error {
	return nil
}

// LANDevices 返回一组固定事实：往返测试要核对的就是「这些字段能不能原样回来」。
// 特别覆盖空值（MAC/名称/状态缺省）—— 那条路径最容易在 JSON 标签上出错。
func (s *stubCore) LANDevices(context.Context) (*model.LANReport, error) {
	return &model.LANReport{
		Readable: true,
		Devices: []model.LANDevice{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:10", Name: "书房的电脑", Interface: "eth0", State: "reachable"},
			{IP: "192.168.1.20", State: "stale"},
		},
	}, nil
}

func (s *stubCore) InspectNetwork(context.Context) (model.NetworkReport, error) {
	return model.NetworkReport{}, nil
}
func (s *stubCore) RepairNetwork(context.Context) ([]string, error)  { return nil, nil }
func (s *stubCore) CleanupNetwork(context.Context) ([]string, error) { return nil, nil }
func (s *stubCore) DeleteForeignInterface(context.Context, string) ([]string, error) {
	return nil, nil
}
func (s *stubCore) RunBackupPlan(_ context.Context, userID int64, username, srcIP string) (agentapi.BackupRunResult, error) {
	s.userID, s.username, s.srcIP = userID, username, srcIP
	return agentapi.BackupRunResult{OK: true, File: "written.json"}, nil
}
func (s *stubCore) RunInspect(_ context.Context, userID int64, username, srcIP string) (agentapi.InspectRunResult, error) {
	s.inspected, s.userID, s.username, s.srcIP = true, userID, username, srcIP
	return agentapi.InspectRunResult{OK: false, Errors: 2, Warnings: 3, Summary: "检查 13 项，2 项需要处理"},
		nil
}
func (s *stubCore) InspectBackupDir(_ context.Context, dir string) (model.BackupDirInfo, error) {
	s.dir = dir
	return model.BackupDirInfo{
		OK:    true,
		Files: []model.BackupCopy{{Name: "fn-wireguard-backup-x.json", Size: 12}},
	}, nil
}
func (s *stubCore) ReadBackupCopy(_ context.Context, dir, name string) ([]byte, error) {
	s.dir, s.name = dir, name
	return s.raw, nil
}
func (s *stubCore) WriteBackupCopy(_ context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error) {
	s.dir, s.backupID, s.userID, s.username, s.srcIP = dir, backupID, userID, username, srcIP
	return s.copied, nil
}

// TestCoreRoundTrip 让每个方法真的走一次 socket：方法名、参数、返回字段、文件内容都要对得上。
func TestCoreRoundTrip(t *testing.T) {
	stub := &stubCore{
		// 故意放一段非 UTF-8 的字节：备份文件是 JSON，但不该假设它一定是合法文本，
		// base64 那条路要在任意字节上都成立。
		raw:    []byte{0x00, 0xff, 0x7b, 0x22, 0x61, 0x22, 0x3a, 0x31, 0x7d, '\n'},
		copied: "fn-wireguard-backup-y.json",
	}
	sock := filepath.Join(t.TempDir(), "sub", "agent.sock")
	srv := agentapi.NewServer(sock, "", stub, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer func() { _ = srv.Close() }()

	c := agentapi.NewClient(sock)
	if err := c.WaitReady(ctx, 5*time.Second); err != nil {
		t.Fatalf("等待代理就绪失败：%v", err)
	}

	// 立即执行一次：执行者信息要整份过去（审计靠它）
	res, err := c.RunBackupPlan(ctx, 42, "alice", "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.File != "written.json" {
		t.Fatalf("执行结果不对：%+v", res)
	}
	if stub.userID != 42 || stub.username != "alice" || stub.srcIP != "10.0.0.9" {
		t.Fatalf("执行者信息没传过去：%d/%s/%s", stub.userID, stub.username, stub.srcIP)
	}

	// 立即巡检：结论文案与各计数都要原样回来（界面直接显示它们）
	ins, err := c.RunInspect(ctx, 7, "bob", "10.0.0.8")
	if err != nil {
		t.Fatal(err)
	}
	if ins.OK || ins.Errors != 2 || ins.Warnings != 3 || ins.Summary == "" {
		t.Fatalf("巡检结果不对：%+v", ins)
	}
	if !stub.inspected || stub.userID != 7 || stub.username != "bob" || stub.srcIP != "10.0.0.8" {
		t.Fatalf("巡检的执行者信息没传过去：%v %d/%s/%s", stub.inspected, stub.userID, stub.username, stub.srcIP)
	}

	// 内网设备清单：字段名与空值都要原样回来（拓扑图靠它画节点）
	lan, err := c.LANDevices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lan == nil || !lan.Readable || len(lan.Devices) != 2 {
		t.Fatalf("内网设备清单不对：%+v", lan)
	}
	if lan.Devices[0].Name != "书房的电脑" || lan.Devices[0].Interface != "eth0" || lan.Devices[0].State != "reachable" {
		t.Fatalf("设备字段没原样回来：%+v", lan.Devices[0])
	}
	if lan.Devices[1].IP != "192.168.1.20" || lan.Devices[1].MAC != "" || lan.Devices[1].Name != "" {
		t.Fatalf("空字段也要能原样回来：%+v", lan.Devices[1])
	}

	// 目标目录实况
	info, err := c.InspectBackupDir(ctx, "/vol1/1000/backup")
	if err != nil {
		t.Fatal(err)
	}
	if !info.OK || len(info.Files) != 1 || info.Files[0].Size != 12 {
		t.Fatalf("目录实况不对：%+v", info)
	}
	if stub.dir != "/vol1/1000/backup" {
		t.Fatalf("目录参数没传过去：%q", stub.dir)
	}

	// 读副本：字节要一模一样
	raw, err := c.ReadBackupCopy(ctx, "/vol1/1000/backup", "fn-wireguard-backup-x.json")
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(stub.raw) {
		t.Fatalf("副本内容在协议上变了：%q", raw)
	}
	if stub.name != "fn-wireguard-backup-x.json" {
		t.Fatalf("文件名没传过去：%q", stub.name)
	}

	// 另存：源按 ID、执行者整份过去
	name, err := c.WriteBackupCopy(ctx, "/vol1/1000/backup", 7, 42, "alice", "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	if name != stub.copied {
		t.Fatalf("另存返回的文件名不对：%q", name)
	}
	if stub.backupID != 7 || stub.userID != 42 || stub.username != "alice" {
		t.Fatalf("另存参数没传过去：id=%d %d/%s", stub.backupID, stub.userID, stub.username)
	}
}
