// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/service"
)

// TestNotifySettingsNormalized 回归「事件通知」几个设置项的落库形态。
//
// 这几个值直接决定「配了到底能不能收到消息」，因此入库前必须归一化：
// 事件名拼错、格式名写错都会表现为「配完了但一直没动静」，
// 而用户几乎不可能从现象反推出原因。
func TestNotifySettingsNormalized(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	// ① 事件开关存的是「被明确关闭的事件」，并丢掉不认识的名字
	if err := svc.SetSettings(ctx, map[string]string{
		"notify_off": "peer_offline,不认识的事件,peer_offline,iface_down",
	}, actor); err != nil {
		t.Fatal(err)
	}
	if got := st.GetSetting(ctx, "notify_off", ""); got != "iface_down,peer_offline" {
		t.Fatalf("关闭集应去重、丢未知项并排序，实际: %q", got)
	}

	// ② 格式名归一化（大小写与空格都要能容忍）
	for input, want := range map[string]string{
		"markdown":   "markdown",
		" MARKDOWN ": "markdown",
		"纯文本":        "json",
		"text":       "text",
	} {
		if err := svc.SetSettings(ctx, map[string]string{"notify_format": input}, actor); err != nil {
			t.Fatal(err)
		}
		if got := st.GetSetting(ctx, "notify_format", ""); got != want {
			t.Fatalf("格式 %q 应归一化为 %q，实际: %q", input, want, got)
		}
	}

	// ③ 兼容 0.7.0 客户端提交的「开启集」：换算成关闭集，且不再写回旧键
	if err := svc.SetSettings(ctx, map[string]string{
		"notify_events": "peer_online,peer_offline",
	}, actor); err != nil {
		t.Fatal(err)
	}
	off := st.GetSetting(ctx, "notify_off", "")
	disabled := map[string]bool{}
	for _, k := range strings.Split(off, ",") {
		disabled[strings.TrimSpace(k)] = true
	}
	for _, k := range []string{"peer_online", "peer_offline"} {
		if disabled[k] {
			t.Fatalf("旧配置里开启的事件不应出现在关闭集里（%s），实际: %q", k, off)
		}
	}
	for _, k := range []string{"peer_quota", "iface_down", "apply_failed"} {
		if !disabled[k] {
			t.Fatalf("旧配置里没有的事件应被关掉（%s），实际: %q", k, off)
		}
	}

	// ④ 地址非法直接拒绝保存：否则用户会对着一个静默失效的配置反复检查
	if err := svc.SetSettings(ctx, map[string]string{"notify_webhook": "hook.example.com/x"}, actor); err == nil {
		t.Fatal("缺少协议的地址应被拒绝")
	}
	if err := svc.SetSettings(ctx, map[string]string{"notify_webhook": "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x"}, actor); err != nil {
		t.Fatalf("合法地址应被接受: %v", err)
	}
}

// TestNotifyStatusReflectsSettings 界面上的开关与格式应当来自后端真实状态，
// 而不是前端自己拼的默认值。
func TestNotifyStatusReflectsSettings(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "tester"}

	status := svc.NotifyStatus(ctx)
	if status.Configured || len(status.AllKinds) == 0 || len(status.Groups) == 0 {
		t.Fatalf("未配置时也应下发完整的事件清单与分组，实际: %+v", status)
	}
	if len(status.Events) != len(status.AllKinds) {
		t.Fatalf("全新安装时所有事件都应开启，实际 %d/%d", len(status.Events), len(status.AllKinds))
	}

	if err := svc.SetSettings(ctx, map[string]string{
		"notify_webhook": "https://oapi.dingtalk.com/robot/send?access_token=secret-token",
		"notify_format":  "markdown",
		"notify_off":     "peer_online",
	}, actor); err != nil {
		t.Fatal(err)
	}
	status = svc.NotifyStatus(ctx)
	if !status.Configured || status.Format != "markdown" {
		t.Fatalf("状态应反映已配置与 Markdown 格式，实际: %+v", status)
	}
	if strings.Contains(status.URL, "secret-token") {
		t.Fatalf("下发给界面的地址必须脱敏，实际: %s", status.URL)
	}
	for _, k := range status.Events {
		if k == "peer_online" {
			t.Fatal("被关闭的事件不应出现在已开启列表里")
		}
	}
	if status.Problem != "" {
		t.Fatalf("钉钉地址 + Markdown 应可用，实际报: %s", status.Problem)
	}
}
