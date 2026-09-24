// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import "testing"

// TestBuildLANDevices 邻居表的过滤规则：拓扑图上「内网设备」这一层的正确性全在这里。
//
// 每条丢弃规则都有明确的错误后果：把隧道设备混进来会让图上出现两台一样的机器；
// 不按网段过滤会把公网对端画成家里的设备；把 failed 记录画出来会让人以为设备在线。
func TestBuildLANDevices(t *testing.T) {
	entries := []neighEntry{
		{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:10", State: "reachable", Link: "eth0"},
		{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", State: "stale", Link: "eth0"},
		{IP: "10.10.0.5", MAC: "aa:bb:cc:00:00:05", State: "reachable", Link: "wg0"},  // 隧道设备：不算内网
		{IP: "8.8.8.8", MAC: "aa:bb:cc:00:00:08", State: "reachable", Link: "eth0"},   // 公网：不算内网
		{IP: "192.168.1.30", MAC: "aa:bb:cc:00:00:30", State: "failed", Link: "eth0"}, // 没打通：不画
		{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:99", State: "stale", Link: "eth0"},  // 重复：只留一条
		{IP: "224.0.0.1", MAC: "01:00:5e:00:00:01", State: "reachable", Link: "eth0"}, // 组播：不画
		{IP: "", MAC: "aa:bb:cc:00:00:11", State: "reachable", Link: "eth0"},          // 非法：不画
	}
	got := buildLANDevices(entries, LANDeviceFilter{TunnelLinks: []string{"wg0"}, Subnets: []string{"192.168.1.0/24"}})
	if len(got) != 2 {
		t.Fatalf("应当只剩两台内网设备，实际：%+v", got)
	}
	if got[0].IP != "192.168.1.10" || got[1].IP != "192.168.1.20" {
		t.Fatalf("应按地址排序，实际：%v / %v", got[0].IP, got[1].IP)
	}
	if got[1].State != "stale" {
		t.Fatalf("邻居状态要原样带上（界面据此显示「待确认」）：%+v", got[1])
	}
	if got[0].Interface != "eth0" {
		t.Fatalf("要记住设备在哪张网卡上：%+v", got[0])
	}
}

// TestBuildLANDevicesWithoutSubnets 探测不到内网网段时一个都不列。
//
// 宁可空着让用户去填「家里网段」，也不能把整张邻居表（含公网对端）画成家里的设备。
func TestBuildLANDevicesWithoutSubnets(t *testing.T) {
	entries := []neighEntry{{IP: "192.168.1.10", State: "reachable", Link: "eth0"}}
	if got := buildLANDevices(entries, LANDeviceFilter{}); len(got) != 0 {
		t.Fatalf("没有内网网段时不应列出任何设备，实际：%+v", got)
	}
}
