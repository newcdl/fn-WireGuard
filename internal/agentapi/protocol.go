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
	// MethodInspectRun 立即执行一次配置漂移巡检。
	//
	// 巡检要读内核里的规则与路由，还要读通知与备份的状态：这些事实都在代理侧，
	// 判定也只有一份实现（就在代理进程里），界面进程只显示结论。
	MethodInspectRun = "inspect.run"
	// MethodBackupRun 立即执行一次计划备份。
	// 写授权目录需要特权身份：界面进程（fnwg）对用户授权的共享文件夹没有写权限。
	MethodBackupRun = "backup.run"
	// MethodBackupDirInspect 检查备份目标目录并列出其中的副本。
	MethodBackupDirInspect = "backup.dir.inspect"
	// MethodBackupCopyRead 读取目标目录里的一份副本。
	MethodBackupCopyRead = "backup.copy.read"
	// MethodBackupCopyWrite 把一份本地备份另存到目标目录。
	//
	// 源用备份 ID 指定而不是路径：代理是特权进程，协议里不提供任意路径读写（见 Core 的说明）。
	MethodBackupCopyWrite = "backup.copy.write"
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

// BackupRunParams 立即执行计划备份的参数。
//
// 执行者信息整份带过去：这次执行要写审计，审计页得能看出「谁、从哪个 IP 手动跑了一次」。
// 只带用户名会让审计里少一列 —— 事后追查时，缺的偏偏就是那一列。
type BackupRunParams struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	SrcIP    string `json:"src_ip"`
}

// InspectRunParams 立即巡检查的参数。
//
// 执行者信息整份带过去：这次巡检要写审计，审计页得能看出「谁、从哪个 IP 手动跑了一次」。
type InspectRunParams struct {
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	SrcIP    string `json:"src_ip"`
}

// InspectRunResult 是一次立即巡检的结果。
//
// 「查出了问题」是**正常结果**，不是协议错误：它要显示在界面上。
// 协议层的 Error 只留给「巡检执行器本身不可用」。
type InspectRunResult struct {
	OK       bool `json:"ok"`
	Errors   int  `json:"errors"`
	Warnings int  `json:"warnings"`
	// Summary 一句话结论（含前几条错误项的标题），供界面直接显示。
	Summary string `json:"summary,omitempty"`
}

// BackupRunResult 是一次计划备份的执行结果。
//
// 「执行失败」是**正常结果**，不是协议错误：它要显示在界面上（这次没写进目标目录），
// 而不是让调用方重试。协议层的 Error 只留给「执行器本身不可用」。
type BackupRunResult struct {
	OK    bool   `json:"ok"`
	File  string `json:"file,omitempty"`
	Error string `json:"error,omitempty"`
}

// BackupDirParams 目标目录相关的参数。
type BackupDirParams struct {
	Dir string `json:"dir"`
}

// BackupCopyReadParams 读取副本的参数。
type BackupCopyReadParams struct {
	Dir  string `json:"dir"`
	Name string `json:"name"`
}

// BackupCopyWriteParams 另存一份的参数。
//
// Dir 是目标目录，BackupID 是本地那份备份的 ID（由代理自己按 ID 找文件，
// 不接受调用方给路径）。执行者信息整份带过去：这会在代理侧写一条审计。
type BackupCopyWriteParams struct {
	Dir      string `json:"dir"`
	BackupID int64  `json:"backup_id"`
	UserID   int64  `json:"user_id"`
	Username string `json:"username"`
	SrcIP    string `json:"src_ip"`
}

// BackupCopyWriteResult 是另存一份的结果。
type BackupCopyWriteResult struct {
	Name string `json:"name"`
}

// BackupCopyRawResult 承载文件内容。[]byte 在 JSON 里是 base64，收发两端都不用自己编码。
type BackupCopyRawResult struct {
	Raw []byte `json:"raw"`
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
	// RunInspect 立即执行一次配置漂移巡检（判定与落库都在代理进程里）。
	RunInspect(ctx context.Context, userID int64, username, srcIP string) (InspectRunResult, error)
	// RunBackupPlan 以特权身份立即执行一次计划备份。
	RunBackupPlan(ctx context.Context, userID int64, username, srcIP string) (BackupRunResult, error)
	// InspectBackupDir 检查备份目标目录并列出其中的副本。
	//
	// 目标目录（用户授权给应用的共享文件夹）**只由代理读写**：界面进程对它没有写权限，
	// 由界面进程去探测或读写，会得到「界面说不可写、备份其实成功」这种自相矛盾的结果。
	InspectBackupDir(ctx context.Context, dir string) (model.BackupDirInfo, error)
	// ReadBackupCopy 读取目标目录里的一份副本。
	ReadBackupCopy(ctx context.Context, dir, name string) ([]byte, error)
	// WriteBackupCopy 把一份本地备份另存到目标目录，返回实际写出的文件名。
	WriteBackupCopy(ctx context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error)
}
