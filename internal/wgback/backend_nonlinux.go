// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

//go:build !linux

package wgback

// New 在非 Linux 平台返回内存后端：开发机上无法创建内核 WireGuard 设备，
// 用内存态模拟即可让前端与 API 完整联调。
//
// Linux 上的同名实现见 linux.go（真实内核后端）；单元测试若想脱离内核与 root，
// 应显式使用平台无关的 NewMock（见 mock.go）。
func New(statePath string) Backend { return NewMock(statePath) }
