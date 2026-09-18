// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

//go:build embedui

// Package webui 通过 go:embed 内嵌前端构建产物，由 Go 直接托管，
// 从而让 fpk 不依赖 Node 运行时。
//
// 该文件仅在开启 embedui 构建标签时参与编译（由 scripts/build.sh 自动加上），
// 日常开发与单元测试使用 webui_placeholder.go 的占位实现。
package webui

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var embedded embed.FS

// FS 返回前端静态资源文件系统。
func FS() (fs.FS, error) {
	return fs.Sub(embedded, "dist")
}
