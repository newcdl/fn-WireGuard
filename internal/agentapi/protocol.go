// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package agentapi 定义无特权 Web 进程与特权代理之间的通信协议。
//
// 通信载体为 Unix Domain Socket 上的「一行一个 JSON」请求/响应，
// 方法与参数均为强类型白名单，代理不提供任何 shell 或任意命令执行能力。
package agentapi

import (
	"context"
	"encoding/json"

	"fnwg/internal/model"
)

// 支持的方法名。
const (
	MethodPing            = "ping"
	MethodReconcile       = "reconcile"
	MethodStatus          = "status"
	MethodHealth          = "health"
	MethodDeleteInterface = "iface.delete"
	MethodNetInspect      = "net.inspect"
	MethodNetRepair       = "net.repair"
	MethodNetCleanup      = "net.cleanup"
	// MethodNetDeleteForeign 删除一个不属于本应用的 WireGuard 网卡（疑似残留）。
	// 这是白名单里唯一会触碰非受管对象的方法，代理侧会再次校验网卡类型。
	MethodNetDeleteForeign = "net.delete_foreign_iface"
)

// Request 是一次调用请求。
type Request struct {
	ID     int64           `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

// Response 是一次调用响应。
type Response struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// DeleteInterfaceParams 删除接口的参数。
type DeleteInterfaceParams struct {
	Name string `json:"name"`
}

// DeleteForeignInterfaceParams 删除疑似残留网卡的参数。
type DeleteForeignInterfaceParams struct {
	Name string `json:"name"`
}

// Core 是特权能力的抽象，既可由本地引擎实现，也可由 UDS 客户端实现。
//
// 注意：这里不对上层暴露任何"修改系统路由"的能力，从协议层就杜绝越权。
type Core interface {
	// Reconcile 按数据库期望态收敛内核配置，返回执行的动作列表。
	Reconcile(ctx context.Context) ([]string, error)
	// Status 返回内核实时状态快照。
	Status(ctx context.Context) (model.Status, error)
	// Health 返回代理与内核能力健康度。
	Health(ctx context.Context) (model.Health, error)
	// DeleteInterface 删除指定接口。
	DeleteInterface(ctx context.Context, name string) error
	// InspectNetwork 网络自检（只读）。
	InspectNetwork(ctx context.Context) (model.NetworkReport, error)
	// RepairNetwork 清除本应用残留在系统上的危险路由。
	RepairNetwork(ctx context.Context) ([]string, error)
	// CleanupNetwork 删除本应用创建的全部内核对象（停用/卸载使用）。
	CleanupNetwork(ctx context.Context) ([]string, error)
	// DeleteForeignInterface 删除一个不属于本应用的 WireGuard 网卡。
	// 代理侧只允许删除 link 类型为 wireguard 的网卡，其余一律拒绝。
	DeleteForeignInterface(ctx context.Context, name string) ([]string, error)
}
