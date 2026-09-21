// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"net"
	"sort"
	"strings"

	"fnwg/internal/model"
)

// 本文件把「内核邻居表里的记录」整理成「内网里的设备清单」。
//
// 刻意做成纯函数（不碰 netlink、不带 build tag）：过滤规则决定拓扑图上画什么，
// 判错了要么把隧道设备混进内网、要么漏掉整段内网 —— 这类规则必须能在任何平台上穷举核对。
// 读表本身在 linux.go（只有 Linux 有邻居表）。

// neighEntry 是邻居表里一条记录的纯数据形式。
type neighEntry struct {
	IP    string
	MAC   string
	State string
	Link  string
}

// LANDeviceFilter 决定哪些邻居算「内网里的设备」。
type LANDeviceFilter struct {
	// TunnelLinks 是隧道网卡（本应用创建的，以及内核里其它 WireGuard 网卡）：
	// 这些网卡上的邻居是「连上隧道的设备」，不是内网里的机器，混进来会让拓扑图自相矛盾。
	TunnelLinks []string
	// Subnets 是内网网段：只保留落在其中的地址。
	// 空表示「探测不到内网网段」——此时宁可一个都不列，也不要把公网邻居画成家里设备。
	Subnets []string
}

// buildLANDevices 过滤、去重并排序邻居记录。
//
// 丢弃的情形（每一条都会在图上造成错误印象）：
//  1. 隧道网卡上的记录 —— 那是隧道设备，另有它们自己的节点；
//  2. 不落在任何内网网段里的地址 —— 例如默认网关之外的公网对端；
//  3. 组播/广播/回环/无效地址；
//  4. 内核状态为 failed / incomplete 的记录 —— 那是「没打通」，画出来会让人以为设备在线。
func buildLANDevices(entries []neighEntry, f LANDeviceFilter) []model.LANDevice {
	subnets := parseCIDRs(f.Subnets)
	out := []model.LANDevice{}
	seen := map[string]bool{}
	for _, e := range entries {
		ip := net.ParseIP(strings.TrimSpace(e.IP))
		if ip == nil || ip.To4() == nil {
			continue
		}
		if ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() {
			continue
		}
		if contains(f.TunnelLinks, e.Link) {
			continue
		}
		if !overlapsAny(&net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}, subnets) {
			continue
		}
		state := strings.ToLower(strings.TrimSpace(e.State))
		if state == "failed" || state == "incomplete" {
			continue
		}
		key := ip.String()
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.LANDevice{
			IP: key, MAC: strings.TrimSpace(e.MAC), State: state, Interface: strings.TrimSpace(e.Link),
		})
	}
	// 按地址排序（数值序）：界面上同一台机器的位置不该随邻居表的顺序变来变去
	sort.Slice(out, func(i, j int) bool {
		a, b := net.ParseIP(out[i].IP), net.ParseIP(out[j].IP)
		return strings.Compare(string(a.To4()), string(b.To4())) < 0
	})
	return out
}

// neighStateName 把内核的邻居状态翻译成界面能用的词。
//
// 只分三档：可达（reachable/permanent）、待确认（delay/probe/stale）、未知。
// 翻译得比内核更细没有意义 —— 用户要判断的是「这台机器在不在线」。
func neighStateName(state int) string {
	switch state {
	case 0x02, 0x80: // NUD_REACHABLE, NUD_PERMANENT
		return "reachable"
	case 0x01, 0x04, 0x08: // NUD_INCOMPLETE, NUD_STALE, NUD_DELAY/PROBE
		return "stale"
	default:
		return "unknown"
	}
}
