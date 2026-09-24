// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package traffic

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/secretbox"
	"fnwg/internal/store"
)

type testEnv struct {
	rec     *Recorder
	st      *store.Store
	snap    *model.Status
	ifaceID int64
	peerID  int64
}

// newTestEnv 造一套「库 + 可控状态快照」的采样环境：状态由测试逐轮改写，
// 模拟内核里累计计数的变化。
func newTestEnv(t *testing.T) *testEnv {
	t.Helper()
	dir := t.TempDir()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx := context.Background()
	it := &model.Interface{
		Name: "wg0", UUID: "test-uuid", PrivateKey: "priv", PublicKey: "srv-pub",
		ListenPort: 51820, Addresses: []string{"10.10.0.1/24"}, Enabled: true,
	}
	if err := st.CreateInterface(ctx, it); err != nil {
		t.Fatal(err)
	}
	p := &model.Peer{InterfaceID: it.ID, Name: "手机", PublicKey: "peer-pub", Enabled: true}
	if err := st.CreatePeer(ctx, p); err != nil {
		t.Fatal(err)
	}

	snap := &model.Status{
		Interfaces: []model.InterfaceStatus{
			{Name: "wg0", Peers: []model.PeerStatus{{PublicKey: "peer-pub"}}},
		},
	}
	rec := New(st, func() model.Status { return *snap }, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return &testEnv{rec: rec, st: st, snap: snap, ifaceID: it.ID, peerID: p.ID}
}

func (e *testEnv) setCounters(rx, tx int64) {
	e.snap.Interfaces[0].Peers[0].RxBytes = rx
	e.snap.Interfaces[0].Peers[0].TxBytes = tx
}

func (e *testEnv) rows(t *testing.T) []store.TrafficRow {
	t.Helper()
	rows, err := e.st.TrafficSince(context.Background(), time.Now().Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// TestSampleRecordsDeltaPerHour 锁定核心语义：第一轮只记基线，之后把增量累加到同一小时。
//
// 第一轮不能记账，是因为进程刚启动时内存里没有基线，会把「从 0 到当前累计」
// 这一整段算进当前小时 —— 报表上会出现一根凭空的巨柱。
// 同一小时要累加而不是覆盖，是因为采样每分钟一次、一小时 60 次。
func TestSampleRecordsDeltaPerHour(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.setCounters(1000, 500)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := env.rows(t); len(rows) != 0 {
		t.Fatalf("第一轮采样只应记基线，实际写入 %d 行", len(rows))
	}

	env.setCounters(1600, 700)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	env.setCounters(2000, 900)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}

	rows := env.rows(t)
	if len(rows) != 1 {
		t.Fatalf("同一小时内应只有一行，实际 %d 行", len(rows))
	}
	if rows[0].RxBytes != 1000 || rows[0].TxBytes != 400 {
		t.Fatalf("增量累加不正确：rx=%d tx=%d（期望 1000 / 400）", rows[0].RxBytes, rows[0].TxBytes)
	}
	if rows[0].PeerID != env.peerID || rows[0].InterfaceID != env.ifaceID {
		t.Fatalf("记录未关联到正确的设备/连接：%+v", rows[0])
	}
}

// TestSampleIgnoresCounterReset 锁定计数回绕：接口重建后累计计数归零，
// 既不能把负数写进报表，也不能把归零后的读数当成「又用了一大截」。
func TestSampleIgnoresCounterReset(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	env.setCounters(5000, 5000)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	// 接口被重建：计数回到 0
	env.setCounters(0, 0)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	if rows := env.rows(t); len(rows) != 0 {
		t.Fatalf("计数回绕的那一轮不应记账，实际写入 %d 行", len(rows))
	}

	// 回绕之后从零开始继续累计，应当照常记账
	env.setCounters(300, 100)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}
	rows := env.rows(t)
	if len(rows) != 1 || rows[0].RxBytes != 300 || rows[0].TxBytes != 100 {
		t.Fatalf("回绕后应继续正常记账，实际 %+v", rows)
	}
}

// TestSamplePrunesByRetention 锁定保留策略：超过保留期的记录被清掉，未过期的保留。
func TestSamplePrunesByRetention(t *testing.T) {
	env := newTestEnv(t)
	ctx := context.Background()

	old := time.Now().Add(-100 * 24 * time.Hour)
	if err := env.st.AddTrafficDelta(ctx, env.peerID, env.ifaceID, old, 111, 222); err != nil {
		t.Fatal(err)
	}
	if err := env.st.AddTrafficDelta(ctx, env.peerID, env.ifaceID, time.Now().Add(-time.Hour), 1, 2); err != nil {
		t.Fatal(err)
	}
	// 默认保留 90 天：上面那条 100 天前的应当被清掉
	if err := env.st.SetSetting(ctx, SettingRetentionDays, "90"); err != nil {
		t.Fatal(err)
	}
	env.setCounters(10, 10)
	if err := env.rec.Sample(ctx); err != nil {
		t.Fatal(err)
	}

	rows := env.rows(t)
	for _, r := range rows {
		if r.RxBytes == 111 {
			t.Fatal("超过保留期的记录应被清理")
		}
	}
	if len(rows) == 0 {
		t.Fatal("未过期的记录不应被清掉")
	}

	// 保留天数被设成非法值时必须回落到默认值，而不是「不清理」或「全清」
	if err := env.st.SetSetting(ctx, SettingRetentionDays, "0"); err != nil {
		t.Fatal(err)
	}
	if got := int(env.rec.Retention(ctx).Hours() / 24); got != int(defaultRetention.Hours()/24) {
		t.Fatalf("非法保留天数应回落到默认值，实际得到 %d 天", got)
	}
}

// TestSampleWritesRawSnapshotEveryN 锁定原始快照的节奏：它供近期曲线用，粒度比聚合细，
// 但只保留几天，所以不能每轮都写。
func TestSampleWritesRawSnapshotEveryN(t *testing.T) {
	env := newTestEnv(t)
	env.rec.rawEvery = 3
	ctx := context.Background()

	for i := 1; i <= 6; i++ {
		env.setCounters(int64(i*100), int64(i*100))
		if err := env.rec.Sample(ctx); err != nil {
			t.Fatal(err)
		}
	}
	pts, err := env.st.PeerHistory(ctx, env.ifaceID, "peer-pub", time.Now().Add(-time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	// 第 1 轮（补一个即时点）与第 3、6 轮，共 3 条
	if len(pts) != 3 {
		t.Fatalf("6 轮采样、每 3 轮写一条快照，应得 3 条，实际 %d 条", len(pts))
	}
}
