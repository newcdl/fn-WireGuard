// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"context"
	"net/http"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// requestWithIdentity 造一个「上下文里已有某个身份」的请求，用于直接验闸门判定。
//
// 用内部包直接测判定，是因为这条闸门只在「会话来自飞牛免密身份」时才该生效，
// 而那种会话要经 Unix Socket + 对端身份核验才成立（只有 Linux 能构造）——
// 但闸门的判定本身与平台无关，必须能在任何机器上验。
func requestWithIdentity(u *model.User, token string) *http.Request {
	r, _ := http.NewRequest(http.MethodGet, "/api/v1/auth/security-code", nil)
	return r.WithContext(context.WithValue(r.Context(), ctxUser, &authUser{User: u, Token: token}))
}

// TestStepUpGateOnlyForGatewaySessions 闸门的四条边界：
// 默认不拦；开关打开后**只拦飞牛免密会话**的敏感操作；端口会话（账号密码登录）不拦；非敏感权限不拦。
//
// 「端口会话不拦」这条不是疏漏而是设计：端口登录本身就是一次凭据校验，
// 而且它是用户被自己开的开关挡住时的**退路**——把退路也堵上就等于自锁。
func TestStepUpGateOnlyForGatewaySessions(t *testing.T) {
	srv := newGatewayTestServer(t)
	ctx := context.Background()

	// 飞牛账号：没有本应用口令，所以它的会话必然是「以飞牛账号登录」换来的
	flyUser := &model.User{ID: 1, Username: "fnnas", Role: model.RoleAdmin, Status: 1, TrimUID: 1000}
	// 自建账号：走账号密码登录
	localUser := &model.User{ID: 2, Username: "admin", Role: model.RoleAdmin, Status: 1}
	gateway := requestWithIdentity(flyUser, "fly-session")
	port := requestWithIdentity(localUser, "local-session")

	if srv.stepUpNeeded(gateway, model.PermKeyReveal) {
		t.Fatal("开关默认关着，不该拦任何请求")
	}

	if err := srv.svc.SetSettings(ctx, map[string]string{service.SettingGatewayStepUp: "1"}, service.Actor{}); err != nil {
		t.Fatal(err)
	}
	if !srv.stepUpNeeded(gateway, model.PermKeyReveal) {
		t.Fatal("开关打开后，飞牛免密会话做敏感操作应先验证一次")
	}
	if srv.stepUpNeeded(port, model.PermKeyReveal) {
		t.Fatal("端口通道（账号密码登录）不该被拦：那是用户的退路")
	}
	if srv.stepUpNeeded(gateway, model.PermIfaceWrite) {
		t.Fatal("非敏感权限不该被拦，否则这个开关会变成打扰")
	}

	srv.svc.MarkStepUpVerified(flyUser.ID)
	if srv.stepUpNeeded(gateway, model.PermKeyReveal) {
		t.Fatal("刚验证过应当放行")
	}
}
