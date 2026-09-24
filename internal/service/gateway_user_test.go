// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service_test

import (
	"context"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// TestEnsureGatewayUserMapsAndSyncsRole 覆盖身份映射的三件要紧事：
// 按 UID 建号（不是按用户名）、同一 UID 只对应一个账号、角色每次跟随飞牛侧。
//
// 最后一条尤其重要：网关通道是**无状态**的（每次请求都靠身份头），
// 因此飞牛侧撤权必须立刻反映过来，不能像本地会话那样等 7 天过期。
func TestEnsureGatewayUserMapsAndSyncsRole(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	u, err := svc.EnsureGatewayUser(ctx, 1000, "fnnas", false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "fnnas" || u.Role != model.RoleViewer || u.TrimUID != 1000 || u.TrimName != "fnnas" {
		t.Fatalf("首次进入应按 UID 建号并映射为只读: %+v", u)
	}

	// 再来一次（用户名快照变了也不该另起一个账号）
	again, err := svc.EnsureGatewayUser(ctx, 1000, "fnnas-renamed", false)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != u.ID {
		t.Fatalf("同一个飞牛 UID 必须对应同一个账号: %d vs %d", again.ID, u.ID)
	}

	// 飞牛侧升权 → 立刻跟着升
	up, err := svc.EnsureGatewayUser(ctx, 1000, "fnnas", true)
	if err != nil {
		t.Fatal(err)
	}
	if up.Role != model.RoleAdmin {
		t.Fatalf("飞牛管理员应映射为管理员: %+v", up)
	}

	// 飞牛侧撤权 → 立刻降回来
	down, err := svc.EnsureGatewayUser(ctx, 1000, "fnnas", false)
	if err != nil {
		t.Fatal(err)
	}
	if down.Role != model.RoleViewer {
		t.Fatalf("飞牛侧撤权后必须立即降权: %+v", down)
	}
}

// TestGatewayUserCannotLoginWithPassword 飞牛身份账号永远不能走密码登录。
//
// 它的口令散列是一个**格式非法**的占位值，所以「验不过」这件事由校验逻辑本身保证，
// 不依赖「登录时记得多判断一次来源」这种容易漏的写法 —— 这条用例守的就是这个性质。
func TestGatewayUserCannotLoginWithPassword(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	u, err := svc.EnsureGatewayUser(ctx, 1001, "fnnas", false)
	if err != nil {
		t.Fatal(err)
	}

	for _, pw := range []string{"", "admin12345", u.Username, "!飞牛身份账号没有口令"} {
		if _, err := svc.Login(ctx, service.LoginInput{Username: u.Username, Password: pw, SrcIP: "127.0.0.1"}); err == nil {
			t.Fatalf("飞牛身份账号不应能用密码登录（试了 %q）", pw)
		}
	}
}

// TestGatewayUserDisabledIsRejected 管理员在本应用里停用一个飞牛账号，必须立刻生效。
func TestGatewayUserDisabledIsRejected(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	u, err := svc.EnsureGatewayUser(ctx, 1002, "fnnas", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.UpdateUser(ctx, u.ID, u.Role, 0, "", service.Actor{Username: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.EnsureGatewayUser(ctx, 1002, "fnnas", false); err == nil {
		t.Fatal("被停用的飞牛账号不应还能免密进入")
	}
}

// TestGatewayUsernamePrefixReserved 自建账号不能占用 nas: 前缀。
//
// 否则自建账号可以顶掉某个飞牛 UID 的位置，把免密登录引到一个不该进的地方。
func TestGatewayAccountNamePrefersFlyUsername(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	// 本地先有一个 admin：飞牛那边恰好也有个叫 admin 的普通用户
	if _, err := svc.CreateUser(ctx, "admin", "password12345", model.RoleAdmin, service.Actor{}); err != nil {
		t.Fatal(err)
	}
	u, err := svc.EnsureGatewayUser(ctx, 1000, "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username == "admin" {
		t.Fatal("重名时绝不能复用已有账号：那等于把本地管理员的权限交给这个飞牛用户")
	}
	if !strings.HasPrefix(u.Username, "admin-") {
		t.Fatalf("重名时应加后缀另起名字，实际 %q", u.Username)
	}
	if u.TrimUID != 1000 || u.TrimName != "admin" {
		t.Fatalf("身份键必须是 UID、展示名保留飞牛用户名：%+v", u)
	}
	if u.Role != model.RoleViewer {
		t.Fatalf("飞牛普通用户应映射为只读：%+v", u)
	}

	// 不重名时账号名就直接用飞牛用户名（不再出现 nas:<uid> 这种机器编号）
	u2, err := svc.EnsureGatewayUser(ctx, 1001, "xsz", false)
	if err != nil {
		t.Fatal(err)
	}
	if u2.Username != "xsz" {
		t.Fatalf("不重名时账号名应当就是飞牛用户名，实际 %q", u2.Username)
	}
	// 同一个 UID 再来一次（哪怕飞牛侧改了名）：还是同一个账号，名字不跟着变
	again, err := svc.EnsureGatewayUser(ctx, 1001, "xsz-改名了", false)
	if err != nil {
		t.Fatal(err)
	}
	if again.ID != u2.ID || again.Username != "xsz" {
		t.Fatalf("同一 UID 必须始终对应同一个账号：%+v", again)
	}
	if again.TrimName != "xsz-改名了" {
		t.Fatalf("展示名应跟着飞牛侧更新：%+v", again)
	}

	// 没有有效 UID 的身份必须拒绝
	if _, err := svc.EnsureGatewayUser(ctx, 0, "x", false); err == nil {
		t.Fatal("没有有效 UID 的身份必须拒绝")
	}
}

// TestDeleteGatewayAdminWhenAnotherAdminExists 真机反馈的回归：
// 删除飞牛账号被判成「最后一个管理员」，而用户明明还有自建管理员账号。
// 这条钉住语义：判据是「系统里还有几个**启用的管理员**」，与账号来源无关；
// 并且提示要把「数到了谁」说出来，否则用户只能对着一句结论猜。
func TestDeleteGatewayAdminWhenAnotherAdminExists(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	local, err := svc.CreateUser(ctx, "admin", "password12345", model.RoleAdmin, service.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := svc.EnsureGatewayUser(ctx, 1000, "飞牛管理员", true)
	if err != nil {
		t.Fatal(err)
	}
	if gw.Role != model.RoleAdmin {
		t.Fatalf("飞牛管理员应映射为管理员：%+v", gw)
	}

	// 还有另一个启用的管理员 → 删除飞牛账号必须放行
	if err := svc.DeleteUser(ctx, gw.ID, service.Actor{UserID: local.ID, Username: "admin"}); err != nil {
		t.Fatalf("还有另一个启用的管理员时就该允许删除，实际：%v", err)
	}

	// 反过来：只剩一个启用的管理员时，必须拒绝 —— 而且要说清是哪个账号撑着这个位置
	err = svc.DeleteUser(ctx, local.ID, service.Actor{UserID: 999, Username: "x"})
	if err == nil {
		t.Fatal("最后一个启用的管理员不能被删除")
	}
	if !strings.Contains(err.Error(), "启用的管理员") {
		t.Fatalf("拒绝时应说清判据（否则用户查不出原因）：%v", err)
	}
}

// TestDeleteDisabledGatewayAdminIsAllowed 真机反馈的第二种形状（也是判定里的真 bug）：
// 要删的那个账号**自己是停用**的，系统里另有一个启用的管理员 —— 删掉一个停用账号，
// 启用的管理员一个都不会少，所以必须直接放行。
// 旧写法把被删的账号自己也数进去，于是用户不得不先把它「启用」才删得掉，荒唐。
func TestDeleteDisabledGatewayAdminIsAllowed(t *testing.T) {
	svc, _ := newTestEnv(t)
	ctx := context.Background()

	local, err := svc.CreateUser(ctx, "admin", "password12345", model.RoleAdmin, service.Actor{})
	if err != nil {
		t.Fatal(err)
	}
	gw, err := svc.EnsureGatewayUser(ctx, 1000, "飞牛管理员", true)
	if err != nil {
		t.Fatal(err)
	}
	if gw.Role != model.RoleAdmin {
		t.Fatalf("飞牛管理员应映射为管理员：%+v", gw)
	}
	// 先停用它（不再需要这个飞牛账号时，管理员会先停用、再删除）
	if err := svc.UpdateUser(ctx, gw.ID, gw.Role, 0, "", service.Actor{UserID: local.ID, Username: "admin"}); err != nil {
		t.Fatal(err)
	}
	if err := svc.DeleteUser(ctx, gw.ID, service.Actor{UserID: local.ID, Username: "admin"}); err != nil {
		t.Fatalf("删除一个已停用的管理员账号不该被拦（它本来就没在撑管理员位）：%v", err)
	}
}
