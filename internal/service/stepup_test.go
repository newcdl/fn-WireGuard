// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"fnwg/internal/core"
	"fnwg/internal/model"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/store"
	"fnwg/internal/totp"
	"fnwg/internal/wgback"
)

// newStepUpEnv 起一个最小环境（与 service_test.go 的 newTestEnv 同构）。
//
// 本文件用**内部包**而不是 service_test：许可的有效期要能拨表验证（stepUpClock），
// 那是这套逻辑里最容易写错的一处 —— 写成永久有效就是一次不显眼的越权。
func newStepUpEnv(t *testing.T) *Service {
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
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := wgback.NewMock(filepath.Join(dir, "netstate.json"))
	return New(st, core.NewLocal(reconcile.New(st, backend, logger)), logger, "test")
}

// TestStepUpSwitchDefaultsOff 开关默认必须是关的：不给飞牛用户平白加一道坎，
// 而且要能分辨「关着」与「配了个乱七八糟的值」。
func TestStepUpSwitchDefaultsOff(t *testing.T) {
	svc := newStepUpEnv(t)
	ctx := context.Background()

	if svc.StepUpEnabled(ctx) {
		t.Fatal("默认必须是关闭：从飞牛桌面点开就免密进来，是这套功能的意义所在")
	}
	if err := svc.SetSettings(ctx, map[string]string{SettingGatewayStepUp: "1"}, Actor{}); err != nil {
		t.Fatal(err)
	}
	if !svc.StepUpEnabled(ctx) {
		t.Fatal("设为 1 后应当打开")
	}
	if err := svc.SetSettings(ctx, map[string]string{SettingGatewayStepUp: "0"}, Actor{}); err != nil {
		t.Fatal(err)
	}
	if svc.StepUpEnabled(ctx) {
		t.Fatal("设为 0 后应当关闭")
	}
	// 只认 0/1：true/on 这类写法会造成「界面开着、服务端按关处理」的两边不一致
	if err := svc.SetSettings(ctx, map[string]string{SettingGatewayStepUp: "on"}, Actor{}); err == nil {
		t.Fatal("非法取值应当拒收")
	}
}

// TestStepUpGrantExpires 许可必须会过期。写错成永久有效就是一次不显眼的越权，
// 所以这条用拨表来验，而不是靠「看着像是对的」。
func TestStepUpGrantExpires(t *testing.T) {
	svc := newStepUpEnv(t)
	base := time.Now()
	restore := stepUpClock
	stepUpClock = func() time.Time { return base }
	t.Cleanup(func() { stepUpClock = restore })

	if svc.StepUpFresh(7) {
		t.Fatal("没验证过就不该算已验证")
	}
	svc.MarkStepUpVerified(7)
	if !svc.StepUpFresh(7) {
		t.Fatal("刚验证过应当放行")
	}

	// 有效期内（差 1 分钟到期）仍然放行
	stepUpClock = func() time.Time { return base.Add(StepUpTTL - time.Minute) }
	if !svc.StepUpFresh(7) {
		t.Fatal("有效期内应当放行")
	}
	// 超过有效期：必须重新验证
	stepUpClock = func() time.Time { return base.Add(StepUpTTL + time.Second) }
	if svc.StepUpFresh(7) {
		t.Fatal("超过有效期必须重新验证")
	}
}

// TestVerifyStepUp 动态口令校验的两条边界：
// 没绑定口令时要给出「先去绑一次」这种能照做的指引；绑了之后验证码要对得上才算数。
func TestVerifyStepUp(t *testing.T) {
	svc := newStepUpEnv(t)
	ctx := context.Background()

	// 飞牛身份账号默认没有动态口令：必须说清该做什么，而不是一句「验证失败」
	u := &model.User{ID: 1, Username: "nas:1000", Role: model.RoleAdmin, Status: 1}
	err := svc.VerifyStepUp(ctx, u, "123456")
	if err == nil || !strings.Contains(err.Error(), "绑定") {
		t.Fatalf("未绑定口令时应引导去绑定，实际：%v", err)
	}
	if svc.StepUpFresh(u.ID) {
		t.Fatal("校验没通过就不该记成已验证")
	}

	secret, err := totp.GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	u.TOTPSecret = secret

	if err := svc.VerifyStepUp(ctx, u, "000000"); err == nil {
		t.Fatal("错误的验证码必须拒绝")
	}
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.VerifyStepUp(ctx, u, code); err != nil {
		t.Fatalf("正确的动态口令应当通过：%v", err)
	}
	if !svc.StepUpFresh(u.ID) {
		t.Fatal("通过后应记成已验证")
	}
}
