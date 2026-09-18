// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

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

// DeleteForeignInterface 删除一个不属于本应用的 WireGuard 网卡。
func (l *Local) DeleteForeignInterface(ctx context.Context, name string) ([]string, error) {
	return l.Eng.DeleteForeignInterface(ctx, name)
}
