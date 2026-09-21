// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// 巡检的日程与保留策略：跑起来之后要能回答三个问题 ——
// 「到点跑了吗」「不会重复跑吧」「报告不会无限涨吧」。
func TestInspectPlanScheduleAndKeep(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester", SrcIP: "127.0.0.1"}

	// 默认关闭：到点也不跑
	if ran, _, _ := svc.RunInspectIfDue(ctx, time.Now()); ran {
		t.Fatal("默认是关闭的，不该自己跑起来")
	}

	// 配置校验：频率、时刻、保留份数各拦一次
	for _, bad := range []service.InspectPlan{
		{Enabled: true, Schedule: service.Schedule{Freq: "hourly", At: "06:30"}, Keep: 14},
		{Enabled: true, Schedule: service.Schedule{Freq: service.FreqDaily, At: "6点半"}, Keep: 14},
		{Enabled: true, Schedule: service.Schedule{Freq: service.FreqDaily, At: "06:30"}, Keep: 0},
		{Enabled: true, Schedule: service.Schedule{Freq: service.FreqDaily, At: "06:30"}, Keep: 999},
		{Enabled: true, Schedule: service.Schedule{Freq: service.FreqWeekly, At: "06:30", Weekday: 9}, Keep: 14},
	} {
		if err := svc.SaveInspectPlan(ctx, bad, time.Now(), actor); err == nil {
			t.Fatalf("这份配置应当被拒绝：%+v", bad)
		}
	}

	// 打开开关：保留 2 份，每天 06:30
	plan := service.InspectPlan{
		Enabled:  true,
		Schedule: service.Schedule{Freq: service.FreqDaily, At: "06:30", Weekday: 1},
		Keep:     2,
	}
	base := time.Date(2026, 9, 20, 6, 0, 0, 0, time.Local)
	if err := svc.SaveInspectPlan(ctx, plan, base, actor); err != nil {
		t.Fatal(err)
	}

	// 刚打开开关当天不算「错过了上一场」：立刻检查也不该补跑
	if ran, _, _ := svc.RunInspectIfDue(ctx, base); ran {
		t.Fatal("刚启用就补跑会让用户莫名其妙多一份报告")
	}
	// 到点（当天 06:30 之后）跑一次
	ran, ok, reason := svc.RunInspectIfDue(ctx, base.Add(40*time.Minute))
	if !ran {
		t.Fatal("到点应当执行一次")
	}
	if !ok || reason == "" {
		t.Fatalf("演示/测试后端下不该报出需要处理的问题：ok=%v reason=%s", ok, reason)
	}
	// 同一场日程不重复跑
	if ran, _, _ := svc.RunInspectIfDue(ctx, base.Add(2*time.Hour)); ran {
		t.Fatal("同一场日程不该重复执行")
	}
	// 第二天再跑，且历史按保留份数裁剪（新的在前）
	for _, day := range []int{1, 2} {
		at := base.AddDate(0, 0, day).Add(40 * time.Minute)
		if ran, _, _ := svc.RunInspectIfDue(ctx, at); !ran {
			t.Fatalf("第 %d 天到点应当执行", day)
		}
	}
	status := service.InspectStatusOf(ctx, st, base.AddDate(0, 0, 3))
	if len(status.Reports) != 2 {
		t.Fatalf("保留 2 份，实际存了 %d 份", len(status.Reports))
	}
	if status.Last == nil || !status.Last.At.After(status.Reports[1].At) {
		t.Fatalf("历史报告应当新的在前：%+v", status.Reports)
	}
	if status.NextAt == nil {
		t.Fatal("启用中的计划应当给出下一次执行时间")
	}
}

// 手动巡检要把执行者整份写进审计，并把报告留在历史里（界面上点一下就有记录）。
func TestInspectRunNowKeepsActor(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()

	ok, errs, warns, reason := svc.RunInspectNow(ctx, 42, "alice", "10.0.0.9")
	status := service.InspectStatusOf(ctx, st, time.Now())
	// 测试环境（内存后端、没有连接、没配通知、没开内网访问）是一台「什么都没配」的机器：
	// 它不该被报成有异常，也不该挂着「待确认」—— 后者是同一类噪音，
	// 一份永远带一条「待确认」的报告，用户看两次就不看了。
	if !ok || errs != 0 || warns != 0 {
		t.Fatalf("测试后端下不该有异常或待确认：ok=%v errs=%d warns=%d %s\n%+v",
			ok, errs, warns, reason, status.Last)
	}

	if status.Last == nil || !status.Last.Manual {
		t.Fatalf("手动巡检应当留下一份标记为手动的报告：%+v", status.Last)
	}
	if len(status.Last.Items) == 0 || status.Last.Passed == 0 {
		t.Fatalf("报告里应当有检查结论：%+v", status.Last)
	}

	entries, _, err := st.ListAudit(ctx, model.AuditFilter{Username: "alice"})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Action == "inspect.run" && e.UserID == 42 && e.SrcIP == "10.0.0.9" {
			found = true
		}
	}
	if !found {
		t.Fatal("审计里应当能看到是谁、从哪个 IP 手动巡检的")
	}
}

// 即时判定走完整条链路（Service → Core → 引擎 → 判定）：顶栏的异常清单读的就是它。
func TestInspectChecksThroughService(t *testing.T) {
	svc, _ := newTestEnv(t)
	items := svc.InspectChecks(context.Background())
	if len(items) == 0 {
		t.Fatal("即时判定不该返回空清单（那会让顶栏误显示为一切正常）")
	}
	// 测试环境是内存后端（演示模式）：不该报内核能力问题，也不该报任何异常
	for _, it := range items {
		if it.Level == service.InspectError {
			t.Fatalf("测试后端下不该有异常项：%+v", it)
		}
		if it.Key == "kernel" && it.Level != service.InspectOK {
			t.Fatalf("演示模式的内核项应当是正常：%+v", it)
		}
	}
}

// 桌面入口状态由界面进程登记、代理进程读取，两端对同一条记录的解读必须一致。
func TestGatewayFactRoundTrip(t *testing.T) {
	_, st := newTestEnv(t)
	ctx := context.Background()

	if _, ok := service.LoadGatewayFact(ctx, st); ok {
		t.Fatal("没登记过时不该读出状态（否则代理会凭空断言桌面入口有问题）")
	}
	entry := model.GatewayEntry{Configured: true, Path: "/run/fnwg/gw.sock", Ready: false, Detail: "没人监听", Fix: "重启应用"}
	service.SaveGatewayFact(ctx, st, entry, time.Now())

	got, ok := service.LoadGatewayFact(ctx, st)
	if !ok || got != entry {
		t.Fatalf("登记之后应当原样读回：ok=%v got=%+v", ok, got)
	}
}
