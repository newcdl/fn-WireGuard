// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package reconcile_test

import (
	"context"
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/reconcile"
	"fnwg/internal/store"
)

// TestDecideQuota 逐条穷举额度与期限的判定分支。
//
// 这段判定会改动用户的设备状态（停用一台设备等于把它踢下线），所以每条分支都必须有明确结论：
// 什么时候停用、什么时候恢复，以及最要紧的一条 —— 管理员手工停用的设备绝不能被自动放开。
func TestDecideQuota(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.Local)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)

	peer := func(mut func(*model.Peer)) model.Peer {
		p := model.Peer{ID: 1, Name: "手机", Enabled: true}
		if mut != nil {
			mut(&p)
		}
		return p
	}

	cases := []struct {
		name   string
		peer   model.Peer
		usage  store.TrafficTotal
		want   reconcile.QuotaDecision
		reason string
	}{
		{"无额度无期限：不动", peer(nil), store.TrafficTotal{}, reconcile.QuotaKeep, ""},
		{"额度未用满：不动", peer(func(p *model.Peer) { p.QuotaTx = 1000 }),
			store.TrafficTotal{TxBytes: 999}, reconcile.QuotaKeep, ""},
		{"本月发送刚好用满：停用", peer(func(p *model.Peer) { p.QuotaTx = 1000 }),
			store.TrafficTotal{TxBytes: 1000}, reconcile.QuotaDisable, model.PeerDisabledQuota},
		{"接收额度同理", peer(func(p *model.Peer) { p.QuotaRx = 500 }),
			store.TrafficTotal{RxBytes: 500}, reconcile.QuotaDisable, model.PeerDisabledQuota},
		{"已到期：停用", peer(func(p *model.Peer) { p.ExpireAt = &past }),
			store.TrafficTotal{}, reconcile.QuotaDisable, model.PeerDisabledExpired},
		{"未到期：不动", peer(func(p *model.Peer) { p.ExpireAt = &future }),
			store.TrafficTotal{}, reconcile.QuotaKeep, ""},
		{"额度停用后本月用量归零（新的一月）：恢复",
			peer(func(p *model.Peer) { p.QuotaTx = 1000; p.Enabled = false; p.DisabledReason = model.PeerDisabledQuota }),
			store.TrafficTotal{}, reconcile.QuotaRestore, ""},
		{"到期后延长了期限：恢复",
			peer(func(p *model.Peer) {
				p.ExpireAt = &future
				p.Enabled = false
				p.DisabledReason = model.PeerDisabledExpired
			}),
			store.TrafficTotal{}, reconcile.QuotaRestore, ""},
		{"管理员手工停用（原因为空）：永不自动恢复",
			peer(func(p *model.Peer) { p.Enabled = false }), store.TrafficTotal{}, reconcile.QuotaKeep, ""},
		{"额度停用且仍超限：保持停用",
			peer(func(p *model.Peer) { p.QuotaTx = 1000; p.Enabled = false; p.DisabledReason = model.PeerDisabledQuota }),
			store.TrafficTotal{TxBytes: 2000}, reconcile.QuotaKeep, ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, reason, _ := reconcile.DecideQuota(c.peer, c.usage, now)
			if got != c.want {
				t.Fatalf("结论不符：got=%v want=%v", got, c.want)
			}
			if c.reason != "" && reason != c.reason {
				t.Fatalf("停用原因不符：got=%q want=%q", reason, c.reason)
			}
		})
	}
}

// TestEnforceQuotaDisablesThenRestores 端到端走一遍：本月用量超限 → 停用并写下原因；
// 到了新的一月（本月合计里不再含旧用量）→ 自动恢复；管理员手工停用的那台始终不动。
func TestEnforceQuotaDisablesThenRestores(t *testing.T) {
	env := newEngineEnv(t, "")
	ctx := context.Background()
	it := env.createInterface(t, "wg0")

	mk := func(name string, quota int64) *model.Peer {
		p := &model.Peer{
			InterfaceID: it.ID, Name: name, PublicKey: name + "-pub",
			Enabled: true, RouteMode: model.RouteModeLAN, QuotaTx: quota,
		}
		if err := env.store.CreatePeer(ctx, p); err != nil {
			t.Fatal(err)
		}
		return p
	}
	over := mk("超额设备", 1000)
	manual := mk("手工停用设备", 0)
	manual.Enabled = false // 管理员手工停用：不写原因
	if err := env.store.UpdatePeer(ctx, manual); err != nil {
		t.Fatal(err)
	}

	// 本月用量：只有超额那台有 2000 字节
	if err := env.store.AddTrafficDelta(ctx, over.ID, it.ID, time.Now().Add(-time.Hour), 0, 2000); err != nil {
		t.Fatal(err)
	}
	env.engine.EnforceQuota(ctx)

	reload := func(id int64) *model.Peer {
		p, err := env.store.GetPeer(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	if got := reload(over.ID); got.Enabled || got.DisabledReason != model.PeerDisabledQuota {
		t.Fatalf("超额设备应被停用并记下原因，实际 enabled=%v reason=%q", got.Enabled, got.DisabledReason)
	}

	// 模拟「到了新的一月」：删掉旧用量，本月合计归零
	if _, err := env.store.PruneTraffic(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	env.engine.EnforceQuota(ctx)
	if got := reload(over.ID); !got.Enabled || got.DisabledReason != "" {
		t.Fatalf("新的一月应自动恢复，实际 enabled=%v reason=%q", got.Enabled, got.DisabledReason)
	}
	if got := reload(manual.ID); got.Enabled {
		t.Fatal("管理员手工停用的设备不能被自动放开")
	}
}
