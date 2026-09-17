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

// TestSetupLoginModeValidation 覆盖初始化页对三种登录方式的取值校验。
//
// 关键在判据的选择：初始化时问「这一次请求是不是经飞牛网关进来的」，而不是
// 「历史上有没有成功用过免密登录」—— 后者在初始化之前必然为假，照它判就等于
// 把「仅飞牛账号登录」做成了一个永远点不动的选项。
func TestSetupLoginModeValidation(t *testing.T) {
	svc, _ := newTestEnv(t)

	// 在端口上打开初始化页：「两种都可用」「仅账号密码」都能选，
	// 「仅飞牛账号」不行 —— 此刻没有任何证据表明免密真的能进来，
	// 选了它就是把唯一还走得通的入口关掉。
	for _, mode := range []string{service.LoginModeBoth, service.LoginModePasswordOnly} {
		if err := svc.CheckLoginModeAtSetup(mode, false); err != nil {
			t.Fatalf("端口上初始化应允许选 %s: %v", mode, err)
		}
	}
	err := svc.CheckLoginModeAtSetup(service.LoginModeGatewayOnly, false)
	if err == nil {
		t.Fatal("端口上初始化不应允许选「仅飞牛账号登录」")
	}
	if !strings.Contains(err.Error(), "飞牛桌面") {
		t.Fatalf("拒绝时要给出这一步真做得到的补救动作，实际: %v", err)
	}

	// 从飞牛桌面打开初始化页：免密要用的身份头此刻就在这个请求里，
	// 「能不能用」已经不是猜测，三种都该可选。
	for _, mode := range []string{
		service.LoginModeBoth, service.LoginModePasswordOnly, service.LoginModeGatewayOnly,
	} {
		if err := svc.CheckLoginModeAtSetup(mode, true); err != nil {
			t.Fatalf("网关通道上初始化应允许选 %s: %v", mode, err)
		}
	}

	// 非法取值一律拒绝，且这个只校验的入口不能产生任何副作用。
	for _, bad := range []string{"", "whatever", "gateway-only", "BOTH", " both"} {
		if err := svc.CheckLoginModeAtSetup(bad, true); err == nil {
			t.Fatalf("非法登录方式应被拒绝: %q", bad)
		}
	}
	if got := svc.LoginMode(context.Background()); got != service.LoginModeBoth {
		t.Fatalf("只校验的入口不应改动设置: %s", got)
	}
}

// TestSetupAppliesLoginModeFromDesktop 覆盖初始化时真的选定「仅飞牛账号登录」。
//
// 顺序按真实调用链来：先校验（在建号之前）、再建号、最后落库。
// 任何一步都不该被登录方式卡住 —— 卡住的后果是用户拿到一个
// 「账号建好了、却没有任何入口进得去」的实例。
func TestSetupAppliesLoginModeFromDesktop(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	admin := service.Actor{Username: "admin"}

	if err := svc.CheckLoginModeAtSetup(service.LoginModeGatewayOnly, true); err != nil {
		t.Fatalf("网关通道上应允许选「仅飞牛账号登录」: %v", err)
	}
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatalf("初始化建号不应受登录方式影响: %v", err)
	}
	if err := svc.SetLoginModeAtSetup(ctx, service.LoginModeGatewayOnly, true, admin); err != nil {
		t.Fatalf("落库失败: %v", err)
	}
	if got := svc.LoginMode(ctx); got != service.LoginModeGatewayOnly {
		t.Fatalf("初始化选定的登录方式未生效: %s", got)
	}
	// 落库路径自己也要把关：绕过校验直接调它，同样拒绝且不改动现状。
	if err := svc.SetLoginModeAtSetup(ctx, "whatever", true, admin); err == nil {
		t.Fatal("非法登录方式不应落库")
	}
	if got := svc.LoginMode(ctx); got != service.LoginModeGatewayOnly {
		t.Fatalf("非法输入不应改动设置: %s", got)
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

// TestGatewayAccountMarkedBySource 覆盖「飞牛账号要标记出来」与「账号名要认得出来」：
// 账号列表必须区分来源，飞牛账号用飞牛侧用户名做展示名，
// 而不是 nas:<uid> 这个用户从未设置、也认不出来的内部锚点。
func TestGatewayAccountMarkedBySource(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "6000", Username: "dave", IsAdmin: false,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	// 登录返回的账号应当立刻带展示名，界面不必再自己判断来源
	if step.User.Source != service.SourceGateway || step.User.DisplayName != "dave" || step.User.TrimUID != "6000" {
		t.Fatalf("网关登录返回的账号缺少来源/展示名: %+v", step.User)
	}

	list, err := svc.ListUsers(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var sawGateway, sawLocal bool
	for _, u := range list {
		if u.ID == step.User.ID {
			sawGateway = true
			if u.Source != service.SourceGateway || u.DisplayName != "dave" || u.TrimUID != "6000" {
				t.Fatalf("飞牛账号未正确标注: %+v", u)
			}
			if u.Username != "nas:6000" {
				t.Fatalf("飞牛账号的本地锚点应为 nas:6000，实际 %s", u.Username)
			}
			continue
		}
		sawLocal = true
		if u.Source != service.SourceLocal || u.DisplayName != u.Username {
			t.Fatalf("本地账号应标为 local 且展示名回落为用户名: %+v", u)
		}
	}
	if !sawGateway || !sawLocal {
		t.Fatalf("列表应同时含飞牛账号与本地账号: gateway=%v local=%v", sawGateway, sawLocal)
	}

	// 飞牛侧没给用户名时也不能退回 nas:<uid>——那正是用户看不懂的东西，
	// 回落到「飞牛账号 <uid>」至少还能让他在飞牛用户列表里对上号。
	anon, err := svc.GatewayLogin(ctx, service.GatewayIdentity{UID: "6001"}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if anon.User.DisplayName != "飞牛账号 6001" {
		t.Fatalf("缺用户名时应回落到可核对的展示名，实际 %q", anon.User.DisplayName)
	}
}

// TestGatewayAccountPasswordNotManageable 回归「飞牛账号不能在本应用改密码」：
// 它从网关免密进入，本地口令只是占位值；在这里改密码只会「看起来成功、实际用不上」，
// 因此必须直接拒绝并指向飞牛，同时不影响本应用自己的角色/状态管理。
func TestGatewayAccountPasswordNotManageable(t *testing.T) {
	svc, st := newTestEnv(t)
	ctx := context.Background()
	actor := service.Actor{Username: "admin"}
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "7000", Username: "erin", IsAdmin: true,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	gid := step.User.ID

	if err := svc.ChangePassword(ctx, gid, "", "newpassword123", "", actor); err == nil {
		t.Fatal("飞牛账号不应允许在本应用修改密码")
	} else if !strings.Contains(err.Error(), "飞牛") {
		t.Fatalf("拒绝理由要指向飞牛，实际: %v", err)
	}
	if err := svc.UpdateUser(ctx, gid, model.RoleAdmin, 1, "newpassword123", actor); err == nil {
		t.Fatal("管理员为飞牛账号重置密码也应被拒")
	}

	// 角色与状态是本应用自己的权限，仍必须可管理——否则就无法停用一个飞牛账号
	if err := svc.UpdateUser(ctx, gid, model.RoleViewer, 1, "", actor); err != nil {
		t.Fatalf("飞牛账号的角色应仍可管理: %v", err)
	}
	if u, err := st.GetUser(ctx, gid); err != nil {
		t.Fatal(err)
	} else if u.Role != model.RoleViewer {
		t.Fatalf("角色未更新: %s", u.Role)
	}
	if err := svc.UpdateUser(ctx, gid, model.RoleViewer, 0, "", actor); err != nil {
		t.Fatalf("飞牛账号的停用应仍可管理: %v", err)
	}
}

// TestAuthenticateDecoratesGatewayUser 回归「登录后右上角仍显示 nas:1000」：
// 登录响应里的账号是带展示名的，但前端拿到后紧接着会调 /auth/me 刷新，
// 而 /auth/me 与 /auth/state 都走 Authenticate —— 它不补来源与展示名的话，
// 界面就会在刷新后从飞牛账号名退回内部的 nas:<uid>，正是用户看到的现象。
func TestAuthenticateDecoratesGatewayUser(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()
	if _, err := svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	step, err := svc.GatewayLogin(ctx, service.GatewayIdentity{
		UID: "9000", Username: "grace", IsAdmin: false,
	}, "ua", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	u, err := svc.Authenticate(ctx, step.Token)
	if err != nil {
		t.Fatal(err)
	}
	if u.Source != service.SourceGateway || u.DisplayName != "grace" || u.TrimUID != "9000" {
		t.Fatalf("会话账号必须带来源与展示名（否则界面会显示 nas:<uid>）: %+v", u)
	}
	// 本地账号同样要有展示名，且来源不能被误判成飞牛
	local, err := svc.CreateUser(ctx, "carol", "carolpassword1", model.RoleViewer, service.Actor{Username: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	lstep, err := svc.Login(ctx, service.LoginInput{Username: "carol", Password: "carolpassword1", UserAgent: "ua", SrcIP: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	lu, err := svc.Authenticate(ctx, lstep.Token)
	if err != nil {
		t.Fatal(err)
	}
	if lu.Source != service.SourceLocal || lu.DisplayName != "carol" || lu.ID != local.ID {
		t.Fatalf("本地账号的展示名应回落为用户名且来源为 local: %+v", lu)
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
