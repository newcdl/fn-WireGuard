// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import "testing"

// TestEndpointForInterface 锁定「对外访问地址」的端口策略。
//
// 这条策略决定多连接时每台设备的二维码指向哪个端口：
//   - 设置里没写端口 → 用**本连接**的监听端口（多连接各用各的，才能同时对外）；
//   - 设置里写了端口 → 原样使用（用户自己配了「外部端口 → 本机端口」的映射）。
//
// 曾经一律原样返回设置值，于是第二条连接监听 51821、二维码却写 51820，
// 包落到 wg0 上公钥对不上，现象只有「一直连不上」——状态与日志里都看不出来。
func TestEndpointForInterface(t *testing.T) {
	cases := []struct {
		name       string
		host       string
		listenPort int
		want       string
	}{
		{"只填域名：按连接端口拼接", "home.example.com", 51820, "home.example.com:51820"},
		{"第二条连接用自己的端口", "home.example.com", 51821, "home.example.com:51821"},
		{"只填公网 IP", "113.108.1.1", 51821, "113.108.1.1:51821"},
		{"端口留空按默认值", "home.example.com", 0, "home.example.com:51820"},
		{"写了端口就原样保留（路由器上有映射）", "home.example.com:60000", 51821, "home.example.com:60000"},
		{"手滑留下冒号视同没写端口", "home.example.com:", 51821, "home.example.com:51821"},
		{"IPv6 带方括号且没写端口", "[fd00::1]", 51821, "[fd00::1]:51821"},
		{"IPv6 裸地址", "fd00::1", 51821, "[fd00::1]:51821"},
		{"IPv6 带端口", "[fd00::1]:60000", 51821, "[fd00::1]:60000"},
		{"两边空白", "  home.example.com  ", 51821, "home.example.com:51821"},
		{"没配置", "", 51821, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := endpointForInterface(c.host, c.listenPort); got != c.want {
				t.Fatalf("endpointForInterface(%q, %d) = %q，期望 %q", c.host, c.listenPort, got, c.want)
			}
		})
	}
}

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
