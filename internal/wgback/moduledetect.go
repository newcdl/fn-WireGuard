// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// 本文件是「内核 wireguard 模块是否存在」的判定逻辑。
//
// 刻意不带构建标签、也不碰 netlink：判断本身与平台无关，而它决定的东西很重 ——
// 判成「没有模块」会让整台机器降级到用户态实现，因此必须能在开发机上用例穷举，
// 而不是只能在真机上试。Linux 侧的 kernelModuleAvailable 只是把真实路径喂进来。

// wireguardModuleInDirs 在若干模块根目录下查找运行内核对应的 wireguard 模块文件。
//
// 两个真实教训（见 driver_kernel.go 里 kernelModuleAvailable 的说明）：
//   - 目录层级不能写死：飞牛 6.18 内核放在 kernel/drivers/net/wireguard/，
//     只看 kernel/net/wireguard/ 会把整机误判成「无内核模块」；
//   - 版本要限定为运行内核：旧内核残留的模块文件会造成反方向误判（以为有内核加速）。
func wireguardModuleInDirs(bases []string, release string) bool {
	for _, base := range bases {
		if release != "" {
			if moduleTreeHasWireguard(filepath.Join(base, release)) {
				return true
			}
			continue
		}
		// 读不到运行内核版本（极少见，例如 /proc 不可用时）才退回「任意版本都算」，
		// 以免在这种环境里把明明可用的内核模块也判成不可用。
		dirs, _ := filepath.Glob(filepath.Join(base, "*"))
		for _, dir := range dirs {
			if moduleTreeHasWireguard(dir) {
				return true
			}
		}
	}
	return false
}

// runningKernelRelease 返回运行内核版本（与 `uname -r` 一致）；读不到时返回空串。
func runningKernelRelease() string {
	raw, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// moduleTreeHasWireguard 在一个模块根目录下查找 wireguard 模块文件（任意层级）。
//
// 先用几个已知布局快速命中（绝大多数发行版落在这里，省掉遍历），命中不了再退化为遍历：
// 宁可多花几毫秒，也不能因为目录名和猜想不同就把整台机器降级到兼容模式。
func moduleTreeHasWireguard(root string) bool {
	if root == "" {
		return false
	}
	known := []string{
		"kernel/net/wireguard",
		"kernel/drivers/net/wireguard",
		"updates",
		"updates/dkms",
		"extra",
		"weak-updates",
	}
	for _, dir := range known {
		if globHasRegularFile(filepath.Join(root, dir, "wireguard.ko*")) {
			return true
		}
	}
	found := false
	_ = filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // 读不到的子树跳过，不影响其余部分
		}
		if d.IsDir() {
			return nil
		}
		if isWireguardModuleFile(d.Name()) {
			found = true
			return fs.SkipAll
		}
		return nil
	})
	return found
}

// globHasRegularFile 判断 glob 结果里是否存在**普通文件**。
//
// 不能只看「路径存在」：同名目录（例如 .../wireguard.ko.d）也会被 glob 命中，
// 于是"目录里根本没有模块文件"也会被判成有内核加速 —— 用例 `RejectsOthers` 抓到的就是这个。
// 用 os.Stat 而不是 Lstat：部分发行版把模块做成软链，跟随后仍应算作可用。
func globHasRegularFile(pattern string) bool {
	matches, _ := filepath.Glob(pattern)
	for _, m := range matches {
		if fi, err := os.Stat(m); err == nil && fi.Mode().IsRegular() {
			return true
		}
	}
	return false
}

// isWireguardModuleFile 判断模块文件名是否就是 wireguard 模块（含 .ko.zst/.ko.xz 等压缩后缀）。
//
// 用前缀而不是精确等值：各发行版压缩后缀不统一，漏认一种就等于整机降级。
// 代价是「wireguard.ko.bak」这类备份文件也会被算作可用 —— 有备份文件时通常也有真文件，
// 且万一真不可用，内核驱动会在创建网卡时报错并自动回退，不会让用户卡住。
func isWireguardModuleFile(name string) bool {
	return strings.HasPrefix(name, "wireguard.ko")
}
