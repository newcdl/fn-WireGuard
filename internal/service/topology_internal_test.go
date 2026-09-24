// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"strings"
	"testing"

	"fnwg/internal/model"
)

func nodesOfKind(g TopologyGraph, kind string) []TopologyNode {
	out := []TopologyNode{}
	for _, n := range g.Nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func nodeByID(g TopologyGraph, id string) (TopologyNode, bool) {
	for _, n := range g.Nodes {
		if n.ID == id {
			return n, true
		}
	}
	return TopologyNode{}, false
}

func detailOf(n TopologyNode, key string) string {
	for _, kv := range n.Details {
		if kv.Key == key {
			return kv.Value
		}
	}
	return ""
}

// TestBuildTopology 覆盖一张图上的每一层：本机、内网网段、内网设备、隧道设备、
// 对端 NAS 及其内网、疑似残留网卡。判错的后果是用户对着图得到错误的网络印象，所以逐项钉住。
func TestBuildTopology(t *testing.T) {
	facts := topologyFacts{
		HostName:    "nas-1",
		HomeSubnets: []string{"192.168.1.0/24"},
		WANs:        []string{"eth0"},
		Interfaces: []model.Interface{
			{ID: 1, Name: "wg0", Enabled: true, Addresses: []string{"10.10.0.1/24"}, Up: true},
		},
		Peers: []model.Peer{
			{ID: 1, InterfaceID: 1, Name: "手机", AllowedIPs: []string{"10.10.0.2/32"},
				Enabled: true, Online: true, RxBytes: 1024, TxBytes: 2048, RxRate: 100,
				RouteMode: model.RouteModeLAN, LANPolicy: model.LANPolicyRestrict,
				LANTargets: []string{"192.168.1.10:445"}},
			{ID: 2, InterfaceID: 1, Name: "nas-b", AllowedIPs: []string{"10.10.0.3/32", "192.168.2.0/24"},
				Enabled: true, Online: true, Remark: "站点互联", EndpointHost: "b.example.com", EndpointPort: 51820},
		},
		LAN: &model.LANReport{Readable: true, Devices: []model.LANDevice{
			{IP: "192.168.1.10", MAC: "aa:bb:cc:00:00:10", State: "reachable", Interface: "eth0"},
			{IP: "192.168.1.20", MAC: "aa:bb:cc:00:00:20", State: "stale", Interface: "eth0"},
			{IP: "8.8.8.8", State: "reachable", Interface: "eth0"}, // 不属于任何内网网段：不画
		}},
		DNSNames: map[string]string{"192.168.1.10": "书房的电脑"},
		Foreign:  []model.ForeignInterface{{Name: "wg9", ListenPort: 51820, PeerCount: 2, Addresses: []string{"10.99.0.1/24"}}},
	}
	g := buildTopology(facts)

	if len(nodesOfKind(g, TopoNodeNAS)) != 1 || len(nodesOfKind(g, TopoNodeLAN)) != 1 {
		t.Fatalf("应当只有一个中心节点与一个内网网段：%+v", g.Nodes)
	}
	if hosts := nodesOfKind(g, TopoNodeHost); len(hosts) != 2 {
		t.Fatalf("内网设备只该画出落在内网网段里的两台，实际 %d：%+v", len(hosts), hosts)
	}
	if devs := nodesOfKind(g, TopoNodeDevice); len(devs) != 1 {
		t.Fatalf("客户端设备应只有一个节点：%+v", devs)
	}
	if sites := nodesOfKind(g, TopoNodeSite); len(sites) != 1 {
		t.Fatalf("对端 NAS 应有一个节点：%+v", sites)
	}
	if siteLANs := nodesOfKind(g, TopoNodeSiteLAN); len(siteLANs) != 1 || siteLANs[0].Label != "192.168.2.0/24" {
		t.Fatalf("对端内网应画出一个网段节点：%+v", siteLANs)
	}
	if len(nodesOfKind(g, TopoNodeForeign)) != 1 {
		t.Fatalf("疑似残留网卡应有一个节点：%+v", nodesOfKind(g, TopoNodeForeign))
	}

	named, ok := nodeByID(g, topoID(TopoNodeHost, "192.168.1.10"))
	if !ok || named.Label != "书房的电脑" || named.Sublabel != "192.168.1.10" {
		t.Fatalf("登记过内网域名的设备应显示名字+地址：%+v", named)
	}
	if named.Status != "ok" {
		t.Fatalf("可达的邻居应为正常：%+v", named)
	}
	unnamed, _ := nodeByID(g, topoID(TopoNodeHost, "192.168.1.20"))
	if unnamed.Label != "192.168.1.20" || unnamed.Status != "warn" {
		t.Fatalf("没登记名字的设备应显示地址、状态为待确认：%+v", unnamed)
	}

	dev, _ := nodeByID(g, topoID(TopoNodeDevice, "1"))
	if detailOf(dev, "隧道地址") != "10.10.0.2/32" || detailOf(dev, "连接") != "wg0" {
		t.Fatalf("设备的隧道地址与连接要说清：%+v", dev.Details)
	}
	if !strings.Contains(detailOf(dev, "内网访问"), "192.168.1.10:445") {
		t.Fatalf("要写明这台设备被限制到哪些目标：%q", detailOf(dev, "内网访问"))
	}

	site, _ := nodeByID(g, topoID(TopoNodeSite, "2"))
	if site.Label != "nas-b" || site.Sublabel != "另一台 NAS" {
		t.Fatalf("对端 NAS 节点不对：%+v", site)
	}
	if detailOf(site, "对端内网") != "192.168.2.0/24" {
		t.Fatalf("要写明对端内网网段：%q", detailOf(site, "对端内网"))
	}
	if !strings.Contains(detailOf(site, "说明"), "对端 NAS") {
		t.Fatalf("必须说清对端设备明细看不到：%q", detailOf(site, "说明"))
	}

	kinds := map[string]int{}
	for _, l := range g.Links {
		kinds[l.Kind]++
	}
	if kinds[TopoLinkLAN] != 1 || kinds[TopoLinkHost] != 2 || kinds[TopoLinkTunnel] != 1 ||
		kinds[TopoLinkSite] != 1 || kinds[TopoLinkSiteLAN] != 1 || kinds[TopoLinkForeign] != 1 {
		t.Fatalf("连线数量不对：%+v（links=%+v）", kinds, g.Links)
	}
	for _, l := range g.Links {
		if l.Kind == TopoLinkTunnel && (l.Label != "wg0" || l.Rate != 100) {
			t.Fatalf("隧道连线应带连接名与速率：%+v", l)
		}
	}
	if !strings.Contains(strings.Join(g.Notes, " "), "邻居表") {
		t.Fatalf("必须说明内网设备来自邻居表：%v", g.Notes)
	}
}

// TestBuildTopologyDegrades 取不到内网设备时要留说明，而不是让人以为「家里没有别的机器」。
func TestBuildTopologyDegrades(t *testing.T) {
	g := buildTopology(topologyFacts{
		HostName:    "nas-1",
		HomeSubnets: []string{"192.168.1.0/24"},
		LAN:         &model.LANReport{Readable: false, Reason: "代理没有响应"},
	})
	if !strings.Contains(strings.Join(g.Notes, " "), "代理没有响应") {
		t.Fatalf("读不到内网设备时要写明原因：%v", g.Notes)
	}
	if len(nodesOfKind(g, TopoNodeHost)) != 0 {
		t.Fatal("读不到时不应凭空造出设备节点")
	}

	// 演示模式：样板地址不会落在本机探测到的网段里，但仍要画出节点（说明里已明说这是样板数据）
	g2 := buildTopology(topologyFacts{
		HostName:    "nas-1",
		HomeSubnets: []string{"10.5.198.0/23"},
		LAN: &model.LANReport{Readable: true, Demo: true, Devices: []model.LANDevice{
			{IP: "192.168.1.1", Name: "主路由", State: "reachable"},
			{IP: "192.168.1.20", State: "stale"},
		}},
	})
	if !strings.Contains(strings.Join(g2.Notes, " "), "演示模式") {
		t.Fatalf("演示数据要明说：%v", g2.Notes)
	}
	if hosts := nodesOfKind(g2, TopoNodeHost); len(hosts) != 2 {
		t.Fatalf("演示数据也要画出来（挂在唯一的内网网段下）：%+v", hosts)
	}
	// 非演示数据仍然严格按网段过滤：公网对端绝不能画成家里的设备
	g4 := buildTopology(topologyFacts{
		HostName:    "nas-1",
		HomeSubnets: []string{"10.5.198.0/23"},
		LAN: &model.LANReport{Readable: true, Devices: []model.LANDevice{
			{IP: "192.168.1.1", State: "reachable"},
		}},
	})
	if len(nodesOfKind(g4, TopoNodeHost)) != 0 {
		t.Fatal("真实数据里不属于内网网段的地址不该画出来")
	}

	g3 := buildTopology(topologyFacts{HostName: "nas-1"})
	if !strings.Contains(strings.Join(g3.Notes, " "), "家里网段") {
		t.Fatalf("没有内网网段时要提示去哪里填：%v", g3.Notes)
	}
}
