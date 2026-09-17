package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// TestGatewayLoginProvisionsAccountAndSyncsRole 覆盖飞牛账号免密登录的主干：
// 首次登录自动开户、角色跟随飞牛的「是否管理员」、被映射的账号不能用密码登录。
func TestGatewayLoginProvisionsAccountAndSyncsRole(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()

	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "1000", Username: "alice", IsAdmin: true,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("首次网关登录失败: %v", err)
	}
	if step.Token == "" || step.User == nil {
		t.Fatal("网关登录应签发会话")
	}
	if step.User.Role != model.RoleAdmin {
		t.Fatalf("飞牛管理员应映射为应用管理员，实际 %s", step.User.Role)
	}
	if _, err := svc.Authenticate(ctx, step.Token); err != nil {
		t.Fatalf("签发的会话应可用: %v", err)
	}

	local, err := st.GetUserByUsername(ctx, "nas:1000")
	if err != nil {
		t.Fatalf("应自动建立本地账号: %v", err)
	}
	if local.ID != step.User.ID {
		t.Fatalf("会话账号与映射账号不一致: %d vs %d", step.User.ID, local.ID)
	}

	// 被映射的账号不允许用密码登录：它的口令散列是占位值，
	// 任何输入（包括空）都必须验证失败。
	for _, pw := range []string{"", "external:sso", "nas:1000"} {
		if _, err := svc.Login(ctx, service.LoginInput{
			Username: "nas:1000", Password: pw, UserAgent: "ua", SrcIP: "127.0.0.1",
		}); err == nil {
			t.Fatalf("网关映射账号不应能用密码登录（试了 %q）", pw)
		}
	}

	// 飞牛侧撤销管理员后，本应用必须跟着降权 —— 否则权限只会涨不会落。
	if _, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "1000", Username: "alice2", IsAdmin: false,
	}, "ua", "127.0.0.1"); err != nil {
		t.Fatalf("二次网关登录失败: %v", err)
	}
	after, err := st.GetUser(ctx, local.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Role != model.RoleViewer {
		t.Fatalf("飞牛撤权后应降为只读，实际 %s", after.Role)
	}
	g, err := st.GetGatewayIdentity(ctx, "1000")
	if err != nil {
		t.Fatal(err)
	}
	if g.TrimUsername != "alice2" || g.IsAdmin {
		t.Fatalf("映射记录未同步: %+v", g)
	}
}

// TestGatewayIdentityKeyedByUIDNotUsername 是安全回归：
// 飞牛侧一个叫 admin 的普通用户，绝不能对上本地自建的管理员账号。
func TestGatewayIdentityKeyedByUIDNotUsername(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()

	local, err := svc.Setup(ctx, "admin", "admin12345")
	if err != nil {
		t.Fatal(err)
	}

	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "2001", Username: "admin", IsAdmin: false,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatalf("网关登录失败: %v", err)
	}
	if step.User.ID == local.ID {
		t.Fatal("危险：飞牛普通用户直接拿到了本地管理员账号")
	}
	if step.User.Role != model.RoleViewer {
		t.Fatalf("普通用户应为只读，实际 %s", step.User.Role)
	}
	// 原管理员账号不受影响
	still, err := st.GetUser(ctx, local.ID)
	if err != nil {
		t.Fatal(err)
	}
	if still.Role != model.RoleAdmin || still.Username != "admin" {
		t.Fatalf("本地管理员账号被改写: %+v", still)
	}

	// 自建账号不能占用映射账号的命名空间
	if _, err := svc.CreateUser(ctx, "nas:2001", "password123", model.RoleAdmin, service.Actor{Username: "admin"}); err == nil {
		t.Fatal("自建用户名不允许包含冒号（保留给飞牛账号映射）")
	}
}

// TestGatewayLoginRejectsBadIdentity 覆盖输入校验：
// 空 UID、非数字 UID 都必须拒绝 —— 后者说明这不是网关注入的头。
func TestGatewayLoginRejectsBadIdentity(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	for _, bad := range []service.GatewayIdentity{
		{UID: "", Username: "nobody"},
		{UID: "   ", Username: "nobody"},
		{UID: "admin", Username: "someone"},
		{UID: "1000 OR 1=1", Username: "someone"},
	} {
		if _, err := svc.GatewayLogin(ctx, bad, "ua", "127.0.0.1"); err == nil {
			t.Fatalf("非法身份应被拒绝: %+v", bad)
		}
	}
}

// TestGatewayOnlyRequiresProvenGateway 是防自锁回归：
// 没证明过「飞牛桌面能进来」之前，不允许关闭端口上的账号密码登录。
func TestGatewayOnlyRequiresProvenGateway(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	admin := service.Actor{Username: "admin"}

	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	if svc.LoginMode(ctx) != service.LoginModeBoth {
		t.Fatalf("默认登录方式应为 both，实际 %s", svc.LoginMode(ctx))
	}

	// 还没用过网关 → 拒绝关闭端口登录，并说明该怎么做
	err := svc.SetLoginMode(ctx, service.LoginModeGatewayOnly, admin)
	if err == nil {
		t.Fatal("未验证网关可用前不应允许关闭端口登录")
	}
	if !strings.Contains(err.Error(), "飞牛") {
		t.Fatalf("拒绝时必须说清怎么解决，实际: %v", err)
	}
	if svc.LoginMode(ctx) != service.LoginModeBoth {
		t.Fatal("被拒绝时不应改动设置")
	}

	// 成功用过一次网关登录后，才允许切换
	if _, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "3000", Username: "alice", IsAdmin: true,
	}, "ua", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetLoginMode(ctx, service.LoginModeGatewayOnly, admin); err != nil {
		t.Fatalf("已验证网关可用后应允许切换: %v", err)
	}
	if svc.LoginMode(ctx) != service.LoginModeGatewayOnly {
		t.Fatalf("切换未生效: %s", svc.LoginMode(ctx))
	}

	// 非法取值一律拒绝，且不改变现状
	if err := svc.SetLoginMode(ctx, "whatever", admin); err == nil {
		t.Fatal("非法登录方式应被拒绝")
	}
	if svc.LoginMode(ctx) != service.LoginModeGatewayOnly {
		t.Fatal("非法输入不应改动设置")
	}
}

// TestPasswordOnlyModeBlocksGatewayLogin 覆盖「关闭免密登录」这一侧。
func TestPasswordOnlyModeBlocksGatewayLogin(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetLoginMode(ctx, service.LoginModePasswordOnly, service.Actor{Username: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "4000", Username: "bob", IsAdmin: true,
	}, "ua", "127.0.0.1"); err == nil {
		t.Fatal("关闭免密登录后网关登录必须被拒绝")
	}
	// 账号密码通道不受影响
	if _, err := svc.Login(ctx, service.LoginInput{
		Username: "admin", Password: "admin12345", UserAgent: "ua", SrcIP: "127.0.0.1",
	}); err != nil {
		t.Fatalf("关闭免密不应影响账号密码登录: %v", err)
	}
}

// TestGenericSettingsCannotBypassLoginModeGuard 是防自锁的第二条回归：
// 通用设置接口不能成为绕过「先验证网关可用」这条校验的后门。
func TestGenericSettingsCannotBypassLoginModeGuard(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	admin := service.Actor{Username: "admin"}

	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	// 混在其它设置里一起提交，同样必须被拦下
	err := svc.SetSettings(ctx, map[string]string{
		"server_endpoint": "example.com",
		"login_mode":      service.LoginModeGatewayOnly,
	}, admin)
	if err == nil {
		t.Fatal("通用设置接口不应能绕过登录方式的防自锁校验")
	}
	if got := st.GetSetting(ctx, service.SettingLoginMode, service.LoginModeBoth); got != service.LoginModeBoth {
		t.Fatalf("登录方式被偷偷改掉了: %s", got)
	}
	// 同批次的其它设置项同样写入失败（校验先行），但这是可接受的取舍：
	// 宁可让用户重提一次，也不能让「关闭端口登录」在不该生效时生效。
	if got := st.GetSetting(ctx, "server_endpoint", ""); got != "" {
		t.Fatalf("校验失败时不应写入其它设置项: %s", got)
	}
}

// TestDisabledGatewayAccountStaysDisabled 回归：
// 应用管理员在本地停用某账号后，该用户不能靠飞牛网关把自己「登」回来。
func TestDisabledGatewayAccountStaysDisabled(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()

	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "5000", Username: "carol", IsAdmin: true,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.GetUser(ctx, step.User.ID)
	if err != nil {
		t.Fatal(err)
	}
	u.Status = 0
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "5000", Username: "carol", IsAdmin: true,
	}, "ua", "127.0.0.1"); err == nil {
		t.Fatal("本地停用的账号不应能通过网关免密登录")
	}
}
