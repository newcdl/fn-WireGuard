// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import "testing"

// TestCachedLocalIPv4Stable 自动探测的本机地址必须稳定。
//
// 它会被算进「设备配置指纹」：一旦每次探测的结果可能不同（多网卡机器上很常见），
// 设备列表里的「需重新扫码」就会永远清不掉 —— 用户重新导入同一份配置也没用（真实发生过）。
// 这条用例看起来"必然通过"，但它正是那种被删掉缓存就会失效的护栏。
func TestCachedLocalIPv4Stable(t *testing.T) {
	first := cachedLocalIPv4()
	for i := 0; i < 3; i++ {
		if got := cachedLocalIPv4(); got != first {
			t.Fatalf("缓存期内必须返回同一个地址：%q → %q", first, got)
		}
	}
}
