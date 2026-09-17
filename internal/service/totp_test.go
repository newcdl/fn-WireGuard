package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"fnwg/internal/service"
	"fnwg/internal/totp"
)

// newTOTPUser 建好一个管理员并为其开启二次验证，返回账号与一次性恢复码。
func newTOTPUser(t *testing.T, svc *service.Service, ctx context.Context, actor service.Actor) (int64, string, []string) {
	t.Helper()
	u, err := svc.Setup(ctx, "admin", "admin12345")
	if err != nil {
		t.Fatalf("初始化管理员失败: %v", err)
	}
	setup, err := svc.BeginTOTPSetup(ctx, u.ID, "admin12345", actor)
	if err != nil {
		t.Fatalf("生成绑定信息失败: %v", err)
	}
	code, err := totp.Code(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := svc.EnableTOTP(ctx, u.ID, "admin12345", setup.Secret, code, actor)
	if err != nil {
		t.Fatalf("开启二次验证失败: %v", err)
	}
	return u.ID, setup.Secret, codes
}

// TestTOTPEnableAndLogin 覆盖 V8 的主干：开启后必须过动态口令、错误口令进不来、
// 恢复码可用、以及最容易被写错的一条——「口令通过但还没过二次验证」时不能有会话。
func TestTOTPEnableAndLogin(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}

	created, err := svc.Setup(ctx, "admin", "admin12345")
	if err != nil {
		t.Fatal(err)
	}
	uid := created.ID

	// 开启前：走的就是老路径，不应要求二次验证（升级不改变既有行为）
	step, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("普通登录失败: %v", err)
	}
	if step.TOTPRequired() || step.Token == "" {
		t.Fatal("未开启二次验证时不应要求动态口令")
	}

	// 开启绑定必须验证当前口令：否则被盗会话可以绑上攻击者自己的验证器
	if _, err := svc.BeginTOTPSetup(ctx, uid, "wrong-password", actor); err == nil {
		t.Fatal("口令错误时不应允许开始绑定")
	}
	setup, err := svc.BeginTOTPSetup(ctx, uid, "admin12345", actor)
	if err != nil {
		t.Fatalf("生成绑定信息失败: %v", err)
	}
	if setup.Secret == "" || !strings.HasPrefix(setup.URI, "otpauth://totp/") {
		t.Fatalf("绑定信息异常: %+v", setup)
	}
	if !strings.Contains(setup.URI, "secret="+totp.NormalizeSecret(setup.Secret)) {
		t.Fatalf("扫码链接里没有携带密钥: %s", setup.URI)
	}

	// 绑定确认必须用一次真实动态口令：密钥抄错时若直接放行，
	// 用户会在下次登录被自己锁在门外，且那时已无法自救
	if _, err := svc.EnableTOTP(ctx, uid, "admin12345", setup.Secret, "000000", actor); err == nil {
		t.Fatal("错误动态口令不应通过绑定确认")
	}
	good, err := totp.Code(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	codes, err := svc.EnableTOTP(ctx, uid, "admin12345", setup.Secret, good, actor)
	if err != nil {
		t.Fatalf("开启二次验证失败: %v", err)
	}
	if len(codes) != totp.RecoveryCodeCount {
		t.Fatalf("恢复码数量应为 %d，实际 %d", totp.RecoveryCodeCount, len(codes))
	}

	st, err := svc.TOTPStatusOf(ctx, uid)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Enabled || st.RecoveryRemaining != totp.RecoveryCodeCount {
		t.Fatalf("开启后状态异常: %+v", st)
	}

	// 开启后：口令通过只是拿到挑战，**绝不能同时给出会话**
	step, err = svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("二次验证登录第一步失败: %v", err)
	}
	if !step.TOTPRequired() {
		t.Fatal("已开启二次验证，应当返回挑战")
	}
	if step.Token != "" || step.User != nil {
		t.Fatal("二次验证未通过前不得签发会话")
	}
	// 挑战不是会话令牌：拿它去访问受保护接口必须失败
	if _, err := svc.Authenticate(ctx, step.Challenge); err == nil {
		t.Fatal("登录挑战不得被当作会话令牌使用")
	}

	// 错误动态口令进不来
	if _, err := svc.CompleteTOTPLogin(ctx, step.Challenge, "000000", false, "ua", "127.0.0.1"); err == nil {
		t.Fatal("错误动态口令不应登录成功")
	}
	// 正确动态口令放行
	code, err := totp.Code(setup.Secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	done, err := svc.CompleteTOTPLogin(ctx, step.Challenge, code, false, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("正确动态口令应登录成功: %v", err)
	}
	if done.Token == "" || done.User == nil || done.User.Username != "admin" {
		t.Fatalf("登录返回值异常: %+v", done)
	}
	if _, err := svc.Authenticate(ctx, done.Token); err != nil {
		t.Fatalf("签发的会话应可用: %v", err)
	}
	// 挑战一次性：同一个挑战不能换出第二个会话
	if _, err := svc.CompleteTOTPLogin(ctx, step.Challenge, code, false, "ua", "127.0.0.1"); err == nil {
		t.Fatal("挑战用过一次后应当失效")
	}

	// 恢复码：可用，且用完即废
	step2, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	rec := codes[0]
	done2, err := svc.CompleteTOTPLogin(ctx, step2.Challenge, rec, false, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("恢复码应当可用于登录: %v", err)
	}
	if done2.Token == "" {
		t.Fatal("恢复码登录应签发会话")
	}
	if st, _ := svc.TOTPStatusOf(ctx, uid); st.RecoveryRemaining != totp.RecoveryCodeCount-1 {
		t.Fatalf("用过一枚恢复码后应剩 %d 枚，实际 %d", totp.RecoveryCodeCount-1, st.RecoveryRemaining)
	}
	step3, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteTOTPLogin(ctx, step3.Challenge, rec, false, "ua", "127.0.0.1"); err == nil {
		t.Fatal("同一枚恢复码不应能重复使用")
	}
	// 恢复码允许带连字符/小写输入（用户是照着手抄的）
	step4, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	loose := strings.ToLower(strings.ReplaceAll(codes[1], "-", " "))
	if _, err := svc.CompleteTOTPLogin(ctx, step4.Challenge, loose, false, "ua", "127.0.0.1"); err != nil {
		t.Fatalf("规整后的恢复码应当可用: %v", err)
	}
}

// TestTOTPChallengeAttemptLimit 验证单个挑战的失败次数上限：
// 动态口令只有 6 位，没有上限就等于允许在线爆破。
func TestTOTPChallengeAttemptLimit(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	uid, secret, _ := newTOTPUser(t, svc, ctx, service.Actor{Username: "admin"})
	_ = uid

	step, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	// 连错 5 次（上限）后挑战作废
	for i := 0; i < 5; i++ {
		if _, err := svc.CompleteTOTPLogin(ctx, step.Challenge, "000000", false, "ua", "127.0.0.1"); err == nil {
			t.Fatalf("第 %d 次错误口令不应成功", i+1)
		}
	}
	// 作废之后，即使给出正确动态口令也不能再用
	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CompleteTOTPLogin(ctx, step.Challenge, code, false, "ua", "127.0.0.1"); err == nil {
		t.Fatal("超出尝试上限后挑战应当作废，正确口令也不应可用")
	}
	// 挑战作废不影响账号状态，重新走一遍第一步即可正常登录
	step2, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	code2, _ := totp.Code(secret, time.Now())
	if _, err := svc.CompleteTOTPLogin(ctx, step2.Challenge, code2, false, "ua", "127.0.0.1"); err != nil {
		t.Fatalf("重新登录应当可用: %v", err)
	}
	_ = uid
}

// TestTOTPDisableRestoresPlainLogin 覆盖 V8 的另一半：
// 关闭需验证当前口令，且关闭后行为与升级前完全一致。
func TestTOTPDisableRestoresPlainLogin(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	uid, secret, _ := newTOTPUser(t, svc, ctx, actor)

	code, err := totp.Code(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	// 口令错误 → 拒绝
	if err := svc.DisableTOTP(ctx, uid, "wrong-password", code, actor); err == nil {
		t.Fatal("口令错误时不应允许关闭二次验证")
	}
	// 口令正确但动态口令错误 → 拒绝（降低安全的操作要双重确认）
	if err := svc.DisableTOTP(ctx, uid, "admin12345", "000000", actor); err == nil {
		t.Fatal("动态口令错误时不应允许关闭二次验证")
	}
	// 两项都对 → 关闭
	if err := svc.DisableTOTP(ctx, uid, "admin12345", code, actor); err != nil {
		t.Fatalf("关闭二次验证失败: %v", err)
	}
	if st, _ := svc.TOTPStatusOf(ctx, uid); st.Enabled || st.RecoveryRemaining != 0 {
		t.Fatalf("关闭后状态异常: %+v", st)
	}
	// 关闭后恢复码必须一并作废，不能留下还能用的「后门」
	if left, err := svc.Store.ListUnusedRecoveryCodes(ctx, uid); err != nil {
		t.Fatal(err)
	} else if len(left) != 0 {
		t.Fatalf("关闭后不应残留恢复码，实际还有 %d 枚", len(left))
	}
	// 关键：关闭后回到「口令即可登录」，与升级前完全一致
	step, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatalf("关闭后应能直接登录: %v", err)
	}
	if step.TOTPRequired() || step.Token == "" {
		t.Fatal("关闭二次验证后不应再要求动态口令")
	}
	if err := svc.DisableTOTP(ctx, uid, "admin12345", code, actor); err == nil {
		t.Fatal("未开启时关闭应当报错")
	}
}

// TestTOTPChallengeUser 验证失败限流键能反查到账号（限流器只知道随机挑战令牌）。
func TestTOTPChallengeUser(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	newTOTPUser(t, svc, ctx, service.Actor{Username: "admin"})

	step, err := svc.Login(ctx, service.LoginInput{Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	name, ok := svc.TOTPChallengeUser(ctx, step.Challenge)
	if !ok || name != "admin" {
		t.Fatalf("应能反查出挑战所属账号，实际 %q/%v", name, ok)
	}
	// 伪造/空挑战应安全返回 false，而不是报错或 panic
	if _, ok := svc.TOTPChallengeUser(ctx, "not-a-real-challenge"); ok {
		t.Fatal("伪造挑战不应反查出账号")
	}
	if _, ok := svc.TOTPChallengeUser(ctx, ""); ok {
		t.Fatal("空挑战不应反查出账号")
	}
}
