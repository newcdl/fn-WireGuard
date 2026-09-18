// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service_test

import (
	"context"
	"testing"
	"time"

	"fnwg/internal/service"
	"fnwg/internal/totp"
)

// chromeUA 是一段真实的 Chrome/macOS User-Agent，用于验证设备名解析。
const chromeUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// loginAs 发起登录第一步，把错误原样返回便于断言。
func loginAs(svc *service.Service, ctx context.Context, user, pass, deviceToken string) (*service.LoginStep, error) {
	return svc.Login(ctx, service.LoginInput{
		Username:    user,
		Password:    pass,
		DeviceToken: deviceToken,
		UserAgent:   chromeUA,
		SrcIP:       "192.168.1.9",
	})
}

// trustDeviceFor 走完一次完整登录并勾选「信任本设备」，返回设备令牌与会话令牌。
func trustDeviceFor(t *testing.T, svc *service.Service, ctx context.Context, user, pass, secret string) (string, string) {
	t.Helper()
	step, err := loginAs(svc, ctx, user, pass, "")
	if err != nil {
		t.Fatalf("登录第一步失败: %v", err)
	}
	if !step.TOTPRequired() {
		t.Fatal("开启二次验证后应当返回挑战")
	}
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	done, err := svc.CompleteTOTPLogin(ctx, step.Challenge, code, true, chromeUA, "192.168.1.9")
	if err != nil {
		t.Fatalf("完成二次验证失败: %v", err)
	}
	if done.DeviceToken == "" {
		t.Fatal("勾选「信任本设备」后应下发设备令牌")
	}
	return done.DeviceToken, done.Token
}

// TestTrustedDeviceSkipsTOTP 覆盖「信任本设备」主干：
// 勾选后该设备可跳过动态口令；未勾选、令牌无效、令牌不属于该账号时都必须走第二步。
func TestTrustedDeviceSkipsTOTP(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	uid, secret, _ := newTOTPUser(t, svc, ctx, service.Actor{Username: "admin"})

	deviceToken, sessionToken := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)
	if _, err := svc.Authenticate(ctx, sessionToken); err != nil {
		t.Fatalf("应签发可用会话: %v", err)
	}

	// 列表里能看到这台设备，且名称由 UA 解析而来
	list, err := svc.ListTrustedDevices(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 {
		t.Fatalf("应有 1 台受信任设备，实际 %d", len(list))
	}
	if list[0].Name != "Chrome · macOS" {
		t.Errorf("设备名解析错误: %q", list[0].Name)
	}
	if list[0].TokenHash != "" {
		t.Error("接口返回的数据里不应带令牌哈希")
	}

	// 带设备令牌 → 跳过第二步，直接拿到会话
	again, err := loginAs(svc, ctx, "admin", "admin12345", deviceToken)
	if err != nil {
		t.Fatalf("受信任设备登录失败: %v", err)
	}
	if again.TOTPRequired() {
		t.Fatal("受信任设备应当跳过二次验证")
	}
	if again.Token == "" {
		t.Fatal("受信任设备登录应直接签发会话")
	}

	// 不带令牌 → 仍要第二步
	plain, err := loginAs(svc, ctx, "admin", "admin12345", "")
	if err != nil {
		t.Fatal(err)
	}
	if !plain.TOTPRequired() {
		t.Fatal("不带设备令牌时仍应要求二次验证")
	}

	// 伪造令牌 → 仍要第二步（而不是放行，也不是报错）
	fake, err := loginAs(svc, ctx, "admin", "admin12345", "not-a-real-device-token")
	if err != nil {
		t.Fatal(err)
	}
	if !fake.TOTPRequired() {
		t.Fatal("伪造的设备令牌不应被接受")
	}

	// 关键越权断言：设备令牌只能省掉第二步，绝不能替代口令
	if _, err := loginAs(svc, ctx, "admin", "wrong-password", deviceToken); err == nil {
		t.Fatal("设备令牌不能替代口令：密码错误时必须失败")
	}
}

// TestTrustedDeviceIsPerUser 验证设备令牌不能跨账号使用。
func TestTrustedDeviceIsPerUser(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}

	// admin 开二次验证并信任一台设备
	_, secret, _ := newTOTPUser(t, svc, ctx, actor)
	adminDevice, _ := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	// 再造一个开了二次验证的账号 bob
	if _, err := svc.CreateUser(ctx, "bob", "bob12345678", "operator", actor); err != nil {
		t.Fatalf("创建 bob 失败: %v", err)
	}
	users, err := svc.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var bobID int64
	for _, u := range users {
		if u.Username == "bob" {
			bobID = u.ID
		}
	}
	if bobID == 0 {
		t.Fatal("未找到 bob")
	}
	setup, err := svc.BeginTOTPSetup(ctx, bobID, "bob12345678", actor)
	if err != nil {
		t.Fatal(err)
	}
	bobCode, _ := totp.Code(setup.Secret, time.Now())
	if _, err := svc.EnableTOTP(ctx, bobID, "bob12345678", setup.Secret, bobCode, actor); err != nil {
		t.Fatal(err)
	}

	// 拿 admin 的设备令牌去登 bob：必须仍然要求二次验证
	step, err := loginAs(svc, ctx, "bob", "bob12345678", adminDevice)
	if err != nil {
		t.Fatalf("bob 登录失败: %v", err)
	}
	if !step.TOTPRequired() {
		t.Fatal("别人的设备令牌不应生效")
	}
}

// TestTrustedDeviceRevokedOnSensitiveChanges 覆盖「什么时候必须作废」：
// 改密码、关闭二次验证都要立刻失效，且重新开启后旧令牌不能复活。
func TestTrustedDeviceRevokedOnSensitiveChanges(t *testing.T) {
	t.Run("改密码", func(t *testing.T) {
		svc, _ := newTestEnv(t)
		ctx := context.Background()
		uid, secret, _ := newTOTPUser(t, svc, ctx, service.Actor{Username: "admin"})
		deviceToken, sessionToken := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

		if err := svc.ChangePassword(ctx, uid, "admin12345", "newpassword1", sessionToken,
			service.Actor{UserID: uid, Username: "admin"}); err != nil {
			t.Fatalf("改密码失败: %v", err)
		}
		// 受信任设备必须被清空
		if list, _ := svc.ListTrustedDevices(ctx, uid); len(list) != 0 {
			t.Fatalf("改密码后不应残留受信任设备: %d 台", len(list))
		}
		// 旧设备令牌必须失效
		step, err := loginAs(svc, ctx, "admin", "newpassword1", deviceToken)
		if err != nil {
			t.Fatal(err)
		}
		if !step.TOTPRequired() {
			t.Fatal("改密码后旧设备令牌必须失效")
		}
		// 当前会话要保留（不能把正在操作的人踢出去）
		if _, err := svc.Authenticate(ctx, sessionToken); err != nil {
			t.Fatalf("改密码不应使当前会话失效: %v", err)
		}
	})

	t.Run("关闭二次验证后重新开启", func(t *testing.T) {
		svc, _ := newTestEnv(t)
		ctx := context.Background()
		actor := service.Actor{Username: "admin"}
		uid, secret, _ := newTOTPUser(t, svc, ctx, actor)
		deviceToken, _ := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

		code, _ := totp.Code(secret, time.Now())
		if err := svc.DisableTOTP(ctx, uid, "admin12345", code, actor); err != nil {
			t.Fatalf("关闭二次验证失败: %v", err)
		}
		if list, _ := svc.ListTrustedDevices(ctx, uid); len(list) != 0 {
			t.Fatalf("关闭二次验证后不应残留受信任设备: %d 台", len(list))
		}

		// 重新开启二次验证
		setup, err := svc.BeginTOTPSetup(ctx, uid, "admin12345", actor)
		if err != nil {
			t.Fatal(err)
		}
		code2, _ := totp.Code(setup.Secret, time.Now())
		if _, err := svc.EnableTOTP(ctx, uid, "admin12345", setup.Secret, code2, actor); err != nil {
			t.Fatal(err)
		}

		// 旧的设备令牌绝不能在重新开启后「复活」
		step, err := loginAs(svc, ctx, "admin", "admin12345", deviceToken)
		if err != nil {
			t.Fatal(err)
		}
		if !step.TOTPRequired() {
			t.Fatal("重新开启二次验证后，旧设备令牌不应复活")
		}
	})
}

// TestRevokeTrustedDevice 覆盖手动撤销，含越权保护。
func TestRevokeTrustedDevice(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	uid, secret, _ := newTOTPUser(t, svc, ctx, actor)
	deviceToken, _ := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	list, _ := svc.ListTrustedDevices(ctx, uid)
	if len(list) != 1 {
		t.Fatalf("应有 1 台受信任设备，实际 %d", len(list))
	}

	// 越权：另一个账号不能撤销这台设备
	if err := svc.RevokeTrustedDevice(ctx, uid+999, list[0].ID, actor); err == nil {
		t.Fatal("不应允许撤销不属于自己的设备")
	}

	// 正常撤销
	if err := svc.RevokeTrustedDevice(ctx, uid, list[0].ID, actor); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	step, err := loginAs(svc, ctx, "admin", "admin12345", deviceToken)
	if err != nil {
		t.Fatal(err)
	}
	if !step.TOTPRequired() {
		t.Fatal("撤销后设备令牌必须失效")
	}

	// 「撤销全部」也要生效
	deviceToken2, _ := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)
	if err := svc.RevokeAllTrustedDevices(ctx, uid, actor); err != nil {
		t.Fatal(err)
	}
	step2, err := loginAs(svc, ctx, "admin", "admin12345", deviceToken2)
	if err != nil {
		t.Fatal(err)
	}
	if !step2.TOTPRequired() {
		t.Fatal("撤销全部后设备令牌必须失效")
	}
}

// TestAdminResetUserTOTP 覆盖管理员的救急手段：
// 重置后该账号的二次验证、恢复码、受信任设备与在线会话全部清空。
func TestAdminResetUserTOTP(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	admin := service.Actor{Username: "admin"}
	uid, secret, _ := newTOTPUser(t, svc, ctx, admin)
	deviceToken, sessionToken := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	// 未开启二次验证的账号重置应当报错
	if err := svc.ResetUserTOTP(ctx, uid+999, admin); err == nil {
		t.Fatal("账号不存在时应报错")
	}

	if err := svc.ResetUserTOTP(ctx, uid, admin); err != nil {
		t.Fatalf("管理员重置二次验证失败: %v", err)
	}

	// 密钥被清空 → 登录不再需要动态口令
	u, err := st.GetUser(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if u.TOTPSecret != "" {
		t.Fatal("重置后应当清空二次验证密钥")
	}
	// 恢复码与受信任设备一并清空
	if left, _ := st.ListUnusedRecoveryCodes(ctx, uid); len(left) != 0 {
		t.Fatalf("重置后不应残留恢复码: %d 枚", len(left))
	}
	if list, _ := svc.ListTrustedDevices(ctx, uid); len(list) != 0 {
		t.Fatalf("重置后不应残留受信任设备: %d 台", len(list))
	}
	// 在线会话也要收掉
	if _, err := svc.Authenticate(ctx, sessionToken); err == nil {
		t.Fatal("重置后旧会话应当失效")
	}
	// 只剩口令一道防线：直接登录、不要求二次验证
	step, err := loginAs(svc, ctx, "admin", "admin12345", deviceToken)
	if err != nil {
		t.Fatalf("重置后应能直接用口令登录: %v", err)
	}
	if step.TOTPRequired() || step.Token == "" {
		t.Fatal("重置后不应再要求二次验证")
	}
	// 重复重置应报「未开启」
	if err := svc.ResetUserTOTP(ctx, uid, admin); err == nil {
		t.Fatal("已重置过的账号再重置应报错")
	}
}

// TestAdminResetPasswordKicksSessions 验证管理员改他人密码后，
// 该账号的在线会话与「免二次验证」资格都被收回。
func TestAdminResetPasswordKicksSessions(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	admin := service.Actor{Username: "admin"}
	uid, secret, _ := newTOTPUser(t, svc, ctx, admin)
	deviceToken, sessionToken := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	if err := svc.UpdateUser(ctx, uid, "", -1, "resetbyadmin1", admin); err != nil {
		t.Fatalf("管理员重置密码失败: %v", err)
	}
	if _, err := svc.Authenticate(ctx, sessionToken); err == nil {
		t.Fatal("管理员重置密码后，该账号的旧会话应当失效")
	}
	if list, _ := svc.ListTrustedDevices(ctx, uid); len(list) != 0 {
		t.Fatal("管理员重置密码后应清空受信任设备")
	}
	step, err := loginAs(svc, ctx, "admin", "resetbyadmin1", deviceToken)
	if err != nil {
		t.Fatal(err)
	}
	if !step.TOTPRequired() {
		t.Fatal("管理员重置密码后，旧设备令牌不应再生效")
	}
}

// TestChangePasswordKicksOtherSessions 验证改密码会把其它设备踢下线，但保留当前会话。
func TestChangePasswordKicksOtherSessions(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	uid, secret, _ := newTOTPUser(t, svc, ctx, service.Actor{Username: "admin"})
	_, otherSession := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)
	_, currentSession := trustDeviceFor(t, svc, ctx, "admin", "admin12345", secret)

	if err := svc.ChangePassword(ctx, uid, "admin12345", "brandnewpass1", currentSession,
		service.Actor{UserID: uid, Username: "admin"}); err != nil {
		t.Fatalf("改密码失败: %v", err)
	}
	if _, err := svc.Authenticate(ctx, otherSession); err == nil {
		t.Fatal("改密码后其它设备的会话应当失效")
	}
	if _, err := svc.Authenticate(ctx, currentSession); err != nil {
		t.Fatalf("改密码后当前会话应当保留: %v", err)
	}
}
