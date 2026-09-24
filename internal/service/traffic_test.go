// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"fnwg/internal/service"
	"fnwg/internal/traffic"
)

// TestTrafficReportAggregatesByDay 锁定报表的口径：
// 按本地自然日归并（同一天的多条记录要合并）、区间内每天都有桶、没流量的设备也要出现、
// 按用量排序、区间外的记录不能算进来、本月合计单独累计。
//
// 这些口径全都是「看一眼觉得对、不看就会错」的地方：比如少了某一天，折线会把
// 不相邻的两天连成直线，看上去像「那天用了很多」，而数字本身没有任何异常。
func TestTrafficReportAggregatesByDay(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	talker, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "手机", GenerateKeys: true, AutoAddress: true,
		QuotaTx: 1024, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	quiet, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: "平板", GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}

	// 用「今天零点 + 10 小时」作锚点，避开整点边界：报表按自然日归并，
	// 若把记录放在 23:59 附近，夏令时切换当天会落到相邻的桶里。
	now := time.Now()
	anchor := time.Date(now.Year(), now.Month(), now.Day(), 10, 0, 0, 0, now.Location())
	stamps := []struct {
		at      time.Time
		rx, tx  int64
		inRange bool // 是否落在「近 7 天」区间内
	}{
		{anchor, 100, 200, true},
		{anchor.Add(2 * time.Hour), 300, 400, true}, // 同一天的第二条，必须与上一条合并
		{anchor.AddDate(0, 0, -1), 50, 60, true},
		{anchor.AddDate(0, 0, -6), 7, 8, true},        // 区间的最后一天（第 7 天）
		{anchor.AddDate(0, 0, -7), 9999, 9999, false}, // 刚好在区间之外
	}
	for _, s := range stamps {
		if err := st.AddTrafficDelta(ctx, talker.ID, it.ID, s.at, s.rx, s.tx); err != nil {
			t.Fatal(err)
		}
	}

	rep, err := svc.TrafficReport(ctx, 7)
	if err != nil {
		t.Fatal(err)
	}

	if rep.Days != 7 || len(rep.Daily) != 7 {
		t.Fatalf("区间应为 7 天且逐日桶齐全，实际 %d 天 / %d 个桶", rep.Days, len(rep.Daily))
	}
	// 今天的桶（最后一个）应当是两条记录之和
	todayBucket := rep.Daily[6]
	var wantTodayRx int64 = 100 + 300
	var wantTodayTx int64 = 200 + 400
	if todayBucket.Day != anchor.Format("2006-01-02") || todayBucket.RxBytes != wantTodayRx || todayBucket.TxBytes != wantTodayTx {
		t.Fatalf("今天的合计应把同一天的两条记录合并，实际 %+v", todayBucket)
	}

	// 区间合计 = 区间内各条之和（排除第 8 天那条）
	var wantRx, wantTx int64
	for _, s := range stamps {
		if s.inRange {
			wantRx += s.rx
			wantTx += s.tx
		}
	}
	if rep.RxBytes != wantRx || rep.TxBytes != wantTx {
		t.Fatalf("区间合计应为 %d/%d，实际 %d/%d", wantRx, wantTx, rep.RxBytes, rep.TxBytes)
	}

	// 每台设备都要出现：一台从没用过的设备不能从报表里消失
	if len(rep.Peers) != 2 {
		t.Fatalf("报表应包含全部 2 台设备，实际 %d 台", len(rep.Peers))
	}
	if rep.Peers[0].PeerID != talker.ID || rep.Peers[1].PeerID != quiet.ID {
		t.Fatalf("应按用量从大到小排列，实际首台是 %s", rep.Peers[0].Name)
	}
	if got := rep.Peers[1].RxBytes + rep.Peers[1].TxBytes; got != 0 {
		t.Fatalf("没有流量的设备应显示为 0，实际 %d", got)
	}
	if len(rep.Peers[1].Daily) != 7 {
		t.Fatalf("没有流量的设备也要有完整的逐日桶，实际 %d 个", len(rep.Peers[1].Daily))
	}

	// 额度与自动停用原因要跟着设备走：设备列表里显示「本月用量 / 额度」靠的就是这两项
	if rep.Peers[0].QuotaTx != 1024 {
		t.Fatalf("发送额度应带到报表里，实际 %d", rep.Peers[0].QuotaTx)
	}
	// 本月合计：按测试自己插入的数据算一遍期望值（测试可能在月初、月中、月末跑，不能写死）
	var wantMonthTx int64
	for _, s := range stamps {
		if !s.at.Before(time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())) {
			wantMonthTx += s.tx
		}
	}
	if rep.Peers[0].MonthTxBytes != wantMonthTx {
		t.Fatalf("本月合计应为 %d，实际 %d", wantMonthTx, rep.Peers[0].MonthTxBytes)
	}

	// 保留期与占用：报表页要显示「留多久、留了多少」，与采样器必须同一口径
	if rep.RetentionDays != 90 {
		t.Fatalf("未设置时应与采样器的默认保留期一致（90 天），实际 %d", rep.RetentionDays)
	}
	if rep.HourRows == 0 || rep.Oldest == nil {
		t.Fatal("报表应带上小时记录条数与最早一条的时间")
	}
}

// TestTrafficCSV 覆盖导出：带 BOM（否则 Excel 打开是乱码）、一行一台设备一天、
// 末尾一行合计，以及设备名里的逗号/引号必须转义（不然整张表会错列）。
func TestTrafficCSV(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	it, err := svc.CreateInterface(ctx, service.CreateInterfaceInput{
		Name: "wg0", Addresses: []string{"10.10.0.1/24"}, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	p, err := svc.CreatePeer(ctx, service.PeerInput{
		InterfaceID: it.ID, Name: `客厅, "电视"`, GenerateKeys: true, AutoAddress: true, Enabled: boolPtr(true),
	}, actor)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddTrafficDelta(ctx, p.ID, it.ID, time.Now().Add(-2*time.Hour), 1024, 2048); err != nil {
		t.Fatal(err)
	}

	body, err := svc.TrafficCSV(ctx, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body, "\uFEFF") {
		t.Fatal("导出的 CSV 缺少 BOM，Excel 打开中文列名会乱码")
	}
	if !strings.Contains(body, `"客厅, ""电视"""`) {
		t.Fatalf("含逗号与引号的设备名未被正确转义：\n%s", body)
	}
	lines := strings.Split(strings.TrimRight(body, "\n"), "\n")
	// 表头 + 1 台设备 × 3 天 + 合计
	if len(lines) != 5 {
		t.Fatalf("导出应为 5 行（表头 + 3 天明细 + 合计），实际 %d 行：\n%s", len(lines), body)
	}
	if !strings.HasPrefix(lines[len(lines)-1], "合计") {
		t.Fatalf("最后一行应为合计，实际 %q", lines[len(lines)-1])
	}
}

// TestTrafficRetentionValidation 覆盖保留天数的校验：
// 越界值必须被明确拒绝，不能静默回落成默认值 —— 那样界面显示着一个数、
// 采样器按另一个数清理，属于表面接受、实际不生效，是最难排查的一类不一致。
func TestTrafficRetentionValidation(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	if err := svc.SetTrafficRetentionDays(ctx, 3, actor); err == nil {
		t.Fatal("低于下限的保留天数应被拒绝")
	}
	if err := svc.SetTrafficRetentionDays(ctx, 30, actor); err != nil {
		t.Fatalf("合法天数应被接受: %v", err)
	}
	if got := traffic.RetentionDays(ctx, st); got != 30 {
		t.Fatalf("设置后应立即生效，实际 %d 天", got)
	}
	// 设置接口接受任意键值对，从这里绕过同样要被挡住
	if err := svc.SetSettings(ctx, map[string]string{traffic.SettingRetentionDays: "0"}, actor); err == nil {
		t.Fatal("经设置接口写入越界值也应被拒绝")
	}
	if got := traffic.RetentionDays(ctx, st); got != 30 {
		t.Fatalf("被拒绝的值不应改动已有设置，实际 %d 天", got)
	}
}
