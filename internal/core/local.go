// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package core 提供 Core 接口的本地实现，用于开发模式（不启动独立代理进程）。
package core

import (
	"context"

	"fnwg/internal/agentapi"
	"fnwg/internal/model"
	"fnwg/internal/reconcile"
)

// Local 直接把收敛引擎当作 Core 使用。
type Local struct {
	Eng *reconcile.Engine
}

// NewLocal 包装收敛引擎。
func NewLocal(eng *reconcile.Engine) agentapi.Core { return &Local{Eng: eng} }

// Reconcile 执行收敛。
func (l *Local) Reconcile(ctx context.Context) ([]string, error) {
	d, err := l.Eng.Reconcile(ctx)
	return d.Actions, err
}

// Status 返回状态快照。
func (l *Local) Status(ctx context.Context) (model.Status, error) {
	return l.Eng.Status(), nil
}

// Health 返回健康度。
func (l *Local) Health(ctx context.Context) (model.Health, error) {
	return l.Eng.Health(ctx), nil
}

// DeleteInterface 删除接口。
func (l *Local) DeleteInterface(ctx context.Context, name string) error {
	return l.Eng.DeleteInterface(ctx, name)
}

// LANDevices 读内网里的设备清单（只读）。
func (l *Local) LANDevices(ctx context.Context) (*model.LANReport, error) {
	return l.Eng.LANDevices(ctx)
}

// InspectNetwork 网络自检。
func (l *Local) InspectNetwork(ctx context.Context) (model.NetworkReport, error) {
	return l.Eng.InspectNetwork(ctx)
}

// RepairNetwork 修复残留网络设置。
func (l *Local) RepairNetwork(ctx context.Context) ([]string, error) {
	return l.Eng.RepairNetwork(ctx)
}

// CleanupNetwork 清理本应用创建的内核对象。
func (l *Local) CleanupNetwork(ctx context.Context) ([]string, error) {
	return l.Eng.CleanupNetwork(ctx)
}

// RunInspect 立即做一次配置漂移巡检（本实现即以本进程的身份执行）。
func (l *Local) RunInspect(ctx context.Context, userID int64, username, srcIP string) (agentapi.InspectRunResult, error) {
	ok, errs, warns, reason := l.Eng.RunInspectNow(ctx, userID, username, srcIP)
	return agentapi.InspectRunResult{OK: ok, Errors: errs, Warnings: warns, Summary: reason}, nil
}

// RunBackupPlan 立即执行一次计划备份（本实现即以本进程的特权身份执行）。
func (l *Local) RunBackupPlan(ctx context.Context, userID int64, username, srcIP string) (agentapi.BackupRunResult, error) {
	ok, file, reason := l.Eng.RunBackupNow(ctx, userID, username, srcIP)
	return agentapi.BackupRunResult{OK: ok, File: file, Error: reason}, nil
}

// InspectBackupDir 检查备份目标目录并列出其中的副本（本实现即以本进程身份读写）。
func (l *Local) InspectBackupDir(ctx context.Context, dir string) (model.BackupDirInfo, error) {
	return l.Eng.InspectBackupDir(ctx, dir)
}

// ReadBackupCopy 读取目标目录里的一份副本。
func (l *Local) ReadBackupCopy(ctx context.Context, dir, name string) ([]byte, error) {
	return l.Eng.ReadBackupCopy(ctx, dir, name)
}

// WriteBackupCopy 把一份本地备份另存到目标目录。
func (l *Local) WriteBackupCopy(ctx context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error) {
	return l.Eng.WriteBackupCopy(ctx, dir, backupID, userID, username, srcIP)
}

// DeleteForeignInterface 删除一个不属于本应用的 WireGuard 网卡。
func (l *Local) DeleteForeignInterface(ctx context.Context, name string) ([]string, error) {
	return l.Eng.DeleteForeignInterface(ctx, name)
}
