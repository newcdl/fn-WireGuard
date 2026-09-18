// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/service"
)

// TestSecurityCodeEmergencyLogin 覆盖应急登录的主干：
// 安全码一次性、能重置口令、旧码立刻失效、新码可用。
func TestSecurityCodeEmergencyLogin(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}

	// 尚未生成安全码时，应急登录必须直接拒绝（而不是当成「码错了」）
	if configured, err := svc.SecurityCodeConfigured(ctx); err != nil || configured {
		t.Fatalf("初始化后不应自动存在安全码: %v/%v", configured, err)
	}
	if _, err := svc.EmergencyLogin(ctx, strings.Repeat("A", 52), "", "ua", "1.2.3.4", actor); err == nil {
		t.Fatal("未设置安全码时应急登录应当失败")
	}

	code, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatalf("生成安全码失败: %v", err)
	}
	if len(code) != 52 {
		t.Fatalf("安全码长度应为 52 个字符，实际 %d", len(code))
	}
	if configured, _ := svc.SecurityCodeConfigured(ctx); !configured {
		t.Fatal("生成后状态应为「已设置」")
	}

	// 长度不符 / 内容错误都必须拒绝
	if _, err := svc.EmergencyLogin(ctx, "too-short", "", "ua", "1.2.3.4", actor); err == nil {
		t.Fatal("长度不符的安全码应当被拒绝")
	}
	if _, err := svc.EmergencyLogin(ctx, strings.Repeat("A", 52), "", "ua", "1.2.3.4", actor); err == nil {
		t.Fatal("内容错误的安全码不应通过")
	}

	// 正确安全码（带分组连字符）+ 新口令：一步把控制权收回来
	res, err := svc.EmergencyLogin(ctx, service.GroupSecurityCode(code), "newadminpass1", "ua", "1.2.3.4", actor)
	if err != nil {
		t.Fatalf("应急登录失败: %v", err)
	}
	if res.Token == "" || res.User == nil || res.User.Username != "admin" {
		t.Fatalf("应急登录返回值异常: %+v", res)
	}
	if res.NewCode == "" || res.NewCode == code {
		t.Fatal("应急登录后必须下发一枚不同的新安全码")
	}
	if _, err := svc.Authenticate(ctx, res.Token); err != nil {
		t.Fatalf("应急登录应签发可用会话: %v", err)
	}

	// 口令已按新密码重置
	if _, err := loginAs(svc, ctx, "admin", "admin12345", ""); err == nil {
		t.Fatal("应急登录重置口令后，旧口令应当失效")
	}
	if _, err := loginAs(svc, ctx, "admin", "newadminpass1", ""); err != nil {
		t.Fatalf("新口令应当可用: %v", err)
	}

	// 旧安全码一次性：用过就不能再用
	if _, err := svc.EmergencyLogin(ctx, code, "", "ua", "1.2.3.4", actor); err == nil {
		t.Fatal("旧安全码用过一次后必须失效")
	}
	// 新安全码可用，且同样接受带分组连字符的写法
	if _, err := svc.EmergencyLogin(ctx, service.GroupSecurityCode(res.NewCode), "", "ua", "1.2.3.4", actor); err != nil {
		t.Fatalf("新安全码应当可用: %v", err)
	}
}

// TestSecurityCodeEmergencyWithoutPassword 验证「只进来看一眼、不改密码」也能用：
// 不传新口令时旧口令保持不变。
func TestSecurityCodeEmergencyWithoutPassword(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	code, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EmergencyLogin(ctx, code, "", "ua", "1.2.3.4", actor); err != nil {
		t.Fatalf("应急登录失败: %v", err)
	}
	if _, err := loginAs(svc, ctx, "admin", "admin12345", ""); err != nil {
		t.Fatalf("未传新口令时，原口令应当保持不变: %v", err)
	}
}

// TestSecurityCodeRegenerateInvalidatesOld 验证重新生成会让旧码立即作废。
func TestSecurityCodeRegenerateInvalidatesOld(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	first, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	second, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("两次生成的安全码不应相同")
	}
	if _, err := svc.EmergencyLogin(ctx, first, "", "ua", "1.2.3.4", actor); err == nil {
		t.Fatal("重新生成后，旧安全码必须立即失效")
	}
	if _, err := svc.EmergencyLogin(ctx, second, "", "ua", "1.2.3.4", actor); err != nil {
		t.Fatalf("新生成的安全码应当可用: %v", err)
	}
}

// TestEmergencyLoginResetsTrustedDevices 验证应急登录携带新口令时，
// 会沿用「改密码」那条安全约束：作废受信任设备并清掉其它会话。
func TestEmergencyLoginResetsTrustedDevices(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	uid, secret, _ := newTOTPUser(t, svc, ctx, actor)
	deviceToken, oldSession := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	code, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EmergencyLogin(ctx, code, "brandnewpass1", "ua", "1.2.3.4", actor); err != nil {
		t.Fatalf("应急登录失败: %v", err)
	}

	if _, err := svc.Authenticate(ctx, oldSession); err == nil {
		t.Fatal("应急重置口令后，原有会话应当失效")
	}
	if list, _ := svc.ListTrustedDevices(ctx, uid); len(list) != 0 {
		t.Fatalf("应急重置口令后应清空受信任设备，实际还有 %d 台", len(list))
	}
	// 二次验证仍然开着（应急登录不碰 2FA 开关），所以旧设备令牌不该再生效
	step, err := loginAs(svc, ctx, "admin", "brandnewpass1", deviceToken)
	if err != nil {
		t.Fatal(err)
	}
	if !step.TOTPRequired() {
		t.Fatal("应急重置口令后，旧设备令牌不应再生效")
	}
}

// TestEmergencyLoginPicksEnabledAdmin 验证应急登录落在「第一个启用的管理员」上。
func TestEmergencyLoginPicksEnabledAdmin(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "root"}
	first, err := svc.Setup(ctx, "admin", "admin12345")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateUser(ctx, "ops2", "ops2pass123", "admin", actor); err != nil {
		t.Fatal(err)
	}
	// 把第一个管理员停用，应急登录就应当落到第二个上
	if err := svc.UpdateUser(ctx, first.ID, "", 0, "", actor); err != nil {
		t.Fatal(err)
	}
	code, err := svc.IssueSecurityCode(ctx, actor)
	if err != nil {
		t.Fatal(err)
	}
	res, err := svc.EmergencyLogin(ctx, code, "", "ua", "1.2.3.4", actor)
	if err != nil {
		t.Fatalf("应急登录失败: %v", err)
	}
	if res.User.Username != "ops2" {
		t.Fatalf("应当落到第一个启用的管理员上，实际是 %s", res.User.Username)
	}
	_ = st
}

// TestSecurityCodeFormat 验证安全码的规整与分组展示。
func TestSecurityCodeFormat(t *testing.T) {
	code, err := service.GenerateSecurityCode()
	if err != nil {
		t.Fatal(err)
	}
	grouped := service.GroupSecurityCode(code)
	if len(grouped) != 52+10 { // 52 个字符，每 5 个插一个连字符 → 10 个连字符
		t.Fatalf("分组展示长度异常: %d（%s）", len(grouped), grouped)
	}
	// 规整函数必须能吃下各种抄录写法，还原成同一串
	for _, in := range []string{code, grouped, strings.ToLower(grouped), "  " + grouped + "  "} {
		if got := service.NormalizeSecurityCode(in); got != code {
			t.Errorf("规整失败: %q → %q", in, got)
		}
	}
	// 规整后必须能通过校验：走一遍完整链路，确认「抄录时带连字符/小写」真的能登进来
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	issued, err := svc.IssueSecurityCode(ctx, service.Actor{Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	loose := strings.ToLower(strings.Join(strings.Split(issued, ""), " "))
	if _, err := svc.EmergencyLogin(ctx, loose, "", "ua", "1.2.3.4", service.Actor{Username: "admin"}); err != nil {
		t.Fatalf("带空格与小写的抄录写法应当可用: %v", err)
	}
}
