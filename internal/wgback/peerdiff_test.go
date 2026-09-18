// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import "testing"

// 本文件是「隧道不抖动」的回归测试。
//
// 收敛循环每 10 秒执行一次；稳态下必须产生**零**下发请求，
// 否则内核会重置节点的会话密钥与动态学习到的 endpoint，客户端周期性掉线。
// 任何一条用例失败都意味着这个故障又回来了。

func TestDiffPeersSteadyStateProducesNoChanges(t *testing.T) {
	// 期望态与内核现状一致 → 一次下发都不该产生
	want := []PeerWant{{
		PublicKey:    "KEY-A",
		AllowedIPs:   []string{"10.210.0.2/32"},
		Keepalive:    25,
		HasPreshared: true,
	}}
	have := []PeerHave{{
		PublicKey: "KEY-A",
		// 内核动态学习到的客户端地址：与期望无关，绝不能因此触发下发
		Endpoint:     "203.0.113.7:51820",
		AllowedIPs:   []string{"10.210.0.2/32"},
		Keepalive:    25,
		HasPreshared: true,
	}}
	if changes := DiffPeers(want, have, func(string) bool { return false }); len(changes) != 0 {
		t.Fatalf("稳态下不应产生任何下发，实际: %+v", changes)
	}
}

// TestDiffPeersKeepsDynamicEndpoint 服务端场景的核心：
// 客户端在 NAT 后主动连入，endpoint 是内核学到的，覆盖它会打断已建立的连接。
func TestDiffPeersKeepsDynamicEndpoint(t *testing.T) {
	want := []PeerWant{{PublicKey: "KEY-A", AllowedIPs: []string{"10.10.0.2/32"}}}
	have := []PeerHave{{
		PublicKey:  "KEY-A",
		Endpoint:   "198.51.100.9:41641",
		AllowedIPs: []string{"10.10.0.2/32"},
	}}
	if changes := DiffPeers(want, have, nil); len(changes) != 0 {
		t.Fatalf("不得覆盖内核动态学习到的对端地址，实际: %+v", changes)
	}
}

// TestDiffPeersPushesConfiguredEndpoint 站点互联场景：显式配置了固定对端地址时才下发。
func TestDiffPeersPushesConfiguredEndpoint(t *testing.T) {
	want := []PeerWant{{PublicKey: "KEY-A", Endpoint: "198.51.100.9:51820"}}
	have := []PeerHave{{PublicKey: "KEY-A", Endpoint: "198.51.100.9:41641"}}
	changes := DiffPeers(want, have, nil)
	if len(changes) != 1 || !changes[0].SetEndpoint || changes[0].Endpoint != "198.51.100.9:51820" {
		t.Fatalf("配置了固定对端地址且不一致时应下发，实际: %+v", changes)
	}
}

func TestDiffPeersAllowedIPsOrderInsensitive(t *testing.T) {
	want := []PeerWant{{PublicKey: "K", AllowedIPs: []string{"10.0.0.0/24", "192.168.1.0/24"}}}
	have := []PeerHave{{PublicKey: "K", AllowedIPs: []string{"192.168.1.0/24", "10.0.0.0/24"}}}
	if changes := DiffPeers(want, have, nil); len(changes) != 0 {
		t.Fatalf("仅顺序不同不应判定为变化，实际: %+v", changes)
	}
}

func TestDiffPeersDetectsRealAllowedIPsChange(t *testing.T) {
	want := []PeerWant{{PublicKey: "K", AllowedIPs: []string{"10.0.0.0/24"}}}
	have := []PeerHave{{PublicKey: "K", AllowedIPs: []string{"10.0.0.0/24", "192.168.1.0/24"}}}
	changes := DiffPeers(want, have, nil)
	if len(changes) != 1 || !changes[0].SetAllowedIPs || changes[0].Kind != PeerDiffUpdate {
		t.Fatalf("通行范围变化应触发更新，实际: %+v", changes)
	}
}

func TestDiffPeersKeepaliveChange(t *testing.T) {
	want := []PeerWant{{PublicKey: "K", Keepalive: 25}}
	have := []PeerHave{{PublicKey: "K", Keepalive: 0}}
	changes := DiffPeers(want, have, nil)
	if len(changes) != 1 || !changes[0].SetKeepalive || changes[0].Keepalive != 25 {
		t.Fatalf("心跳变化应触发更新，实际: %+v", changes)
	}
}

// TestDiffPeersPresharedKeyOnlyWhenChanged 口令没变时绝不能重发：
// 重发口令会让内核销毁该节点当前的会话密钥。
func TestDiffPeersPresharedKeyOnlyWhenChanged(t *testing.T) {
	want := []PeerWant{{PublicKey: "K", HasPreshared: true}}
	have := []PeerHave{{PublicKey: "K", HasPreshared: true}}

	if changes := DiffPeers(want, have, func(string) bool { return false }); len(changes) != 0 {
		t.Fatalf("口令未变不应重新下发，实际: %+v", changes)
	}
	changes := DiffPeers(want, have, func(string) bool { return true })
	if len(changes) != 1 || !changes[0].SetPresharedKey || !changes[0].PresharedWanted {
		t.Fatalf("口令轮换时必须下发，实际: %+v", changes)
	}
	if changes := DiffPeers(want, have, nil); len(changes) != 0 {
		t.Fatalf("无法判断口令是否变化时应保守地不重发，实际: %+v", changes)
	}
}

func TestDiffPeersPresharedKeyPresenceTransitions(t *testing.T) {
	// 期望有口令、内核没有 → 下发
	add := DiffPeers(
		[]PeerWant{{PublicKey: "K", HasPreshared: true}},
		[]PeerHave{{PublicKey: "K", HasPreshared: false}},
		nil,
	)
	if len(add) != 1 || !add[0].SetPresharedKey || !add[0].PresharedWanted {
		t.Fatalf("应补发口令，实际: %+v", add)
	}
	// 期望没有、内核有 → 清除
	del := DiffPeers(
		[]PeerWant{{PublicKey: "K", HasPreshared: false}},
		[]PeerHave{{PublicKey: "K", HasPreshared: true}},
		nil,
	)
	if len(del) != 1 || !del[0].SetPresharedKey || del[0].PresharedWanted {
		t.Fatalf("应清除口令，实际: %+v", del)
	}
}

func TestDiffPeersAddAndRemove(t *testing.T) {
	want := []PeerWant{{PublicKey: "NEW", AllowedIPs: []string{"10.0.0.2/32"}, Keepalive: 25, HasPreshared: true}}
	have := []PeerHave{{PublicKey: "GONE", AllowedIPs: []string{"10.0.0.9/32"}}}

	changes := DiffPeers(want, have, nil)
	if len(changes) != 2 {
		t.Fatalf("应同时产生 1 个新增与 1 个移除，实际: %+v", changes)
	}
	var add, remove *PeerDiff
	for i := range changes {
		switch changes[i].Kind {
		case PeerDiffAdd:
			add = &changes[i]
		case PeerDiffRemove:
			remove = &changes[i]
		}
	}
	if add == nil || add.PublicKey != "NEW" || !add.SetAllowedIPs || !add.SetKeepalive || !add.SetPresharedKey {
		t.Fatalf("新增节点应携带完整字段，实际: %+v", add)
	}
	if remove == nil || remove.PublicKey != "GONE" {
		t.Fatalf("已从配置移除的节点应被删除，实际: %+v", remove)
	}
}

func TestDiffPeersEmptyHaveMeansAllNew(t *testing.T) {
	want := []PeerWant{{PublicKey: "A"}, {PublicKey: "B"}}
	changes := DiffPeers(want, nil, nil)
	if len(changes) != 2 {
		t.Fatalf("内核无节点时应全部按新增处理，实际: %+v", changes)
	}
	for _, c := range changes {
		if c.Kind != PeerDiffAdd {
			t.Fatalf("应为新增，实际: %+v", c)
		}
	}
}

func TestPskFingerprint(t *testing.T) {
	if pskFingerprint("abc") != pskFingerprint("abc") {
		t.Fatal("同一口令的指纹应稳定")
	}
	if pskFingerprint("abc") == pskFingerprint("abd") {
		t.Fatal("不同口令的指纹应不同")
	}
	if got := len(pskFingerprint("abc")); got != 16 {
		t.Fatalf("指纹应为 16 个十六进制字符，实际 %d", got)
	}
}
