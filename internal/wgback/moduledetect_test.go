// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"os"
	"path/filepath"
	"testing"
)

// 内核模块探测的用例。
//
// 这份探测决定整台机器走标准模式还是兼容模式：判错成「不可用」的代价是真机整机降级
// （能连、更慢），并且每次重启都会因「数据面实现变了」而重建全部网卡，正在用的异地组网
// 会因此断掉 —— 真机踩到过（飞牛 6.18 内核把模块放在 kernel/drivers/net/wireguard/，
// 而当时只找了 kernel/net/wireguard/）。判错成「可用」的代价是内核驱动在创建网卡时才失败、
// 运行期回退到用户态，而界面显示「标准模式可用」，更难查。两个方向都要用例锁住。

// writeModuleFile 建出目录并写入一个空文件。
func writeModuleFile(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestModuleTreeHasWireguardLayouts 各发行版把 wireguard.ko 放得到处都是，几种都要认。
func TestModuleTreeHasWireguardLayouts(t *testing.T) {
	cases := []struct {
		name string
		path string
	}{
		{"发行版常见布局 kernel/net/wireguard", "kernel/net/wireguard/wireguard.ko"},
		{"飞牛 6.18 的布局 kernel/drivers/net/wireguard", "kernel/drivers/net/wireguard/wireguard.ko"},
		{"压缩后缀 .ko.zst", "kernel/net/wireguard/wireguard.ko.zst"},
		{"压缩后缀 .ko.xz", "kernel/drivers/net/wireguard/wireguard.ko.xz"},
		{"DKMS 的 updates/dkms", "updates/dkms/wireguard.ko"},
		{"backports 的 updates", "updates/net/wireguard/wireguard.ko"},
		{"厂商自带目录 extra", "extra/drivers/wireguard/wireguard.ko"},
		{"weak-updates", "weak-updates/net/wireguard/wireguard.ko"},
		{"完全未知目录（遍历兜底）", "vendor/whatever/lib/wireguard.ko"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			writeModuleFile(t, filepath.Join(root, c.path))
			if !moduleTreeHasWireguard(root) {
				t.Fatalf("%s 应当被认出来：%s", c.name, c.path)
			}
		})
	}
}

// TestModuleTreeHasWireguardRejectsOthers 只有别的模块、同名目录或说明文件时，不能判成可用。
func TestModuleTreeHasWireguardRejectsOthers(t *testing.T) {
	root := t.TempDir()
	writeModuleFile(t, filepath.Join(root, "kernel/net/other/other.ko"))
	writeModuleFile(t, filepath.Join(root, "kernel/net/wireguard/README"))
	// 目录名本身以 wireguard.ko 开头，但它不是文件，不能算
	if err := os.MkdirAll(filepath.Join(root, "kernel/net/wireguard/wireguard.ko.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	if moduleTreeHasWireguard(root) {
		t.Fatal("没有 wireguard.ko* 文件时不该判成可用")
	}
	if moduleTreeHasWireguard(filepath.Join(root, "不存在的目录")) {
		t.Fatal("目录不存在时应当返回 false，而不是报可用")
	}
	if moduleTreeHasWireguard("") {
		t.Fatal("空路径不该被当成可用")
	}
}

// TestWireguardModuleInDirsScopedToRunningKernel 只认运行内核版本的模块文件。
//
// 拿旧内核残留的模块文件当「可用」，会让内核驱动在创建网卡时才发现不行（运行期回退），
// 界面却显示「标准模式可用」——这是最难自查的一种错。
func TestWireguardModuleInDirsScopedToRunningKernel(t *testing.T) {
	base := t.TempDir()
	writeModuleFile(t, filepath.Join(base, "6.1.0-trim", "kernel/drivers/net/wireguard/wireguard.ko"))

	if !wireguardModuleInDirs([]string{base}, "6.1.0-trim") {
		t.Fatal("运行内核的模块文件应当被判为可用")
	}
	if wireguardModuleInDirs([]string{base}, "6.18.18.c1145-trim") {
		t.Fatal("只有其它内核版本的模块文件时不该判成可用（会造成误判：以为有内核加速）")
	}
	// 读不到内核版本时退回「任意版本都算」：宁可多试一次内核驱动，
	// 也不要在这种环境里把整台机器降级到兼容模式。
	if !wireguardModuleInDirs([]string{base}, "") {
		t.Fatal("读不到内核版本时应退回宽松判定")
	}
	if wireguardModuleInDirs([]string{t.TempDir()}, "6.1.0-trim") {
		t.Fatal("空的模块目录不该判成可用")
	}
}

// TestIsWireguardModuleFile 文件名判据：含压缩后缀都算，别的模块不算。
func TestIsWireguardModuleFile(t *testing.T) {
	for _, name := range []string{"wireguard.ko", "wireguard.ko.zst", "wireguard.ko.xz", "wireguard.ko.gz"} {
		if !isWireguardModuleFile(name) {
			t.Fatalf("%s 应被认作 wireguard 模块", name)
		}
	}
	for _, name := range []string{"other.ko", "wireguard", "wireguards.ko", "wireguard.so"} {
		if isWireguardModuleFile(name) {
			t.Fatalf("%s 不该被认作 wireguard 模块", name)
		}
	}
}
