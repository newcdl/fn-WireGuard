// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAppSockPathFallsBackToExecutableDir 锁定「从飞牛桌面点图标只有 502」
// 那次真机故障的根因。
//
// 故障链：systemd 不继承安装脚本的 TRIM_APPDEST → 服务进程拿不到应用目录 →
// 网关 socket 被当成相对路径（systemd 下即 /）去建 → 普通用户对 / 没有写权限，
// bind 直接失败 → 统一网关入口整个不可用 → 点飞牛桌面图标只有 Bad Gateway，
// 而日志里只有一句容易被忽略的警告。
//
// 二进制本身就装在应用 target 目录里，所以退到可执行文件所在目录必然正确。
func TestAppSockPathFallsBackToExecutableDir(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// 与实现保持一致：软链要先解析，「可执行文件在哪」指的是真实位置
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	want := filepath.Dir(exe)

	for _, appDest := range []string{"", ".", "target"} {
		got := (&Config{AppDest: appDest}).AppSockPath()
		if !filepath.IsAbs(got) {
			t.Fatalf("appdest=%q 时 socket 路径必须是绝对路径，实际 %q", appDest, got)
		}
		if filepath.Dir(got) != want {
			t.Fatalf("appdest=%q 时应退到可执行文件目录 %q，实际 %q", appDest, want, filepath.Dir(got))
		}
		if filepath.Base(got) != AppSockFile {
			t.Fatalf("socket 文件名应为 %q，实际 %q", AppSockFile, filepath.Base(got))
		}
	}
}

// TestAppSockPathHonoursAbsoluteAppDest 显式给了绝对的应用目录时必须以它为准：
// 那是网关约定的位置，不能被兜底逻辑覆盖。
func TestAppSockPathHonoursAbsoluteAppDest(t *testing.T) {
	const dest = "/vol1/@appstore/fn-wireguard/target"
	want := filepath.Join(dest, AppSockFile)
	if got := (&Config{AppDest: dest}).AppSockPath(); got != want {
		t.Fatalf("应使用显式给出的应用目录，want %q got %q", want, got)
	}
}
