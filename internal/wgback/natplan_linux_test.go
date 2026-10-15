// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

//go:build linux

package wgback

import (
	"testing"

	"fnwg/internal/model"
)

// planNATLocked 是「从连接期望态推导数据面决策」的那一步，只在 Linux 后端里存在，
// 因此这个用例带 linux 构建约束。
//
// 它要证明的是**识别站点连接**这一步没有偏差：站点互联的连接（路由方式 client）
// 带着「隧道之外的对端网段」，它必须被认出来并作为源地址改写目标；
// 普通设备连接的准入地址只有隧道内地址，不该被误当成站点。
func TestPlanNATDerivesSiteNAT(t *testing.T) {
	b := &linuxBackend{state: LoadState("")}
	specs := []model.InterfaceSpec{
		{
			Name: "wg0", Up: true, Addresses: []string{"10.20.0.1/24"}, AllowLAN: true,
			Peers: []model.PeerSpec{{AllowedIPs: []string{"10.20.0.2/32"}}},
		},
		{
			Name: "wg1", Up: true, Addresses: []string{"10.10.0.1/24"}, AllowLAN: true,
			RouteTable: model.RouteTableClient,
			Peers:      []model.PeerSpec{{Name: "nas-b", AllowedIPs: []string{"10.10.0.2/32", "192.168.2.0/24"}}},
		},
	}
	plan, _, _ := b.planNATLocked(specs)
	// 两个隧道网段各一条：设备所在的 wg0 那条是真正把设备流量送出对端的规则；
	// wg1 自己那条是空操作（本机地址改写成本机地址），但必须也在，否则
	// 「设备与站点同连接」的拓扑下会一条都没有。
	if len(plan.SiteMasq) != 2 {
		t.Fatalf("应识别出 2 条站点改写规则（wg0/wg1 各一），实际: %+v", plan.SiteMasq)
	}
	found := false
	for _, r := range plan.SiteMasq {
		if r.Src == "10.20.0.0/24" && r.Dst == "192.168.2.0/24" && r.Dev == "wg1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少「设备网段 → 对端内网」的改写规则: %+v", plan.SiteMasq)
	}
}
