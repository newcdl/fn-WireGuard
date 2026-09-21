// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package wgback 抽象 WireGuard 数据面后端。
//
// 设计要点：
//   - 全部操作通过 netlink / generic netlink 完成，不调用 wg / wg-quick 等外部命令，
//     从根本上消除 shell 注入面；
//   - Apply 接收「期望态」，内部与当前实际状态做差异比较后再下发，天然幂等，
//     因此重启后只需重新 Apply 一次即可恢复，不会出现配置漂移。
package wgback

import (
	"context"
	"strings"

	"fnwg/internal/model"
)

// ApplyOptions 控制下发行为。
type ApplyOptions struct {
	// DryRun 只计算差异不实际下发。
	DryRun bool
	// RemoveMissing 删除期望态中不存在的、由本应用管理的接口。
	RemoveMissing bool
}

// Diff 记录一次 Apply 实际执行（或将执行）的动作，用于审计与 dry-run 预览。
type Diff struct {
	Actions []string
}

// Append 追加动作描述。
func (d *Diff) Append(format string, args ...any) {
	d.Actions = append(d.Actions, sprintf(format, args...))
}

// Capabilities 描述后端能力与宿主环境。
type Capabilities struct {
	Backend      string `json:"backend"`       // kernel | userspace | mock
	KernelModule bool   `json:"kernel_module"` // 内核 wireguard 模块是否可用
	TunDevice    bool   `json:"tun_device"`    // /dev/net/tun 是否可用（用户态回退前提）
}

// Backend 是数据面后端。
//
// 安全契约（所有实现都必须遵守）：
//   - 只操作本应用创建过的对象，绝不接管或删除他人（含 fnOS 系统）创建的对象；
//   - 绝不创建、修改、删除系统默认路由，也绝不覆盖任何已存在的路由；
//   - Cleanup 只清理自己创建的对象。
type Backend interface {
	// Kind 返回后端类型标识。
	Kind() string
	// Caps 返回能力信息。
	Caps() Capabilities
	// Apply 将期望态收敛到内核。
	Apply(specs []model.InterfaceSpec, opts ApplyOptions) (Diff, error)
	// DeleteInterface 删除本应用创建的接口。
	DeleteInterface(name string) error
	// Snapshot 采集实时状态（只返回本应用创建的接口）。
	Snapshot(names []string) ([]model.InterfaceStatus, error)
	// Heal 清除本应用可能残留在系统上的危险路由，必要时恢复系统默认路由。
	Heal(ctx context.Context) ([]string, error)
	// Cleanup 删除本应用创建的全部接口与残留路由（用于停用与卸载）。
	Cleanup(ctx context.Context) ([]string, error)
	// ManagedInterfaces 返回本应用创建过的接口名。
	ManagedInterfaces() []string
	// Inspect 网络自检（只读）。
	Inspect(ctx context.Context) (model.NetworkReport, error)
	// LANDevices 读内网里的设备清单（只读，来自内核邻居表）。
	LANDevices(ctx context.Context) (*model.LANReport, error)
	// DeleteForeignInterface 删除一个**不属于本应用**的 WireGuard 接口。
	//
	// 这是全项目唯一一处允许触碰非受管对象的能力，因此实现必须自校验：
	// 只允许删除 link 类型为 wireguard 的接口，其它类型一律拒绝。
	// 调用方（界面）还要用户输入接口名二次确认。
	DeleteForeignInterface(name string) ([]string, error)
	// NATStatus 返回内网访问规则当前的实际状态。
	NATStatus() model.NATStatus
}

// findDevice 在快照中按名称查找接口状态。
func findDevice(list []model.InterfaceStatus, name string) *model.InterfaceStatus {
	for i := range list {
		if list[i].Name == name {
			return &list[i]
		}
	}
	return nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func normAddrs(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
