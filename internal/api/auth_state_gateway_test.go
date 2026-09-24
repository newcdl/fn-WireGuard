// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// unwrapData 取出统一响应外壳 {code,data,message} 里的 data。
func unwrapData(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var env struct {
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		t.Fatalf("响应不是 JSON：%v；body=%s", err, body)
	}
	if env.Data == nil {
		t.Fatalf("响应里没有 data：%s", body)
	}
	return env.Data
}

// TestAuthStateReportsGatewayIdentityBeforeSetup 是「初始化页看不到飞牛账号入口」的回归。
//
// 真机现象：全新安装时从飞牛桌面点开本应用，初始化页只给出「创建账号密码」，
// 连「用飞牛账号登录」这个选项都不给 —— 而这次请求明明就是从网关通道进来的，
// 页面上那句「飞牛账号可以直接登录」反而变成了自相矛盾。
//
// 成因：/auth/state 在「还没有任何账号」时提前 return，而上报飞牛身份的那一段写在它**后面**，
// 于是「未初始化」这个状态恰好永远拿不到身份 —— 而那正是初始化页唯一存在的状态。
//
// 这条用例把两端都钉住：未初始化 + 通道可信 → 必须上报；未初始化 + 通道不可信 → 不得上报。
func TestAuthStateReportsGatewayIdentityBeforeSetup(t *testing.T) {
	srv := newGatewayTestServer(t)

	// 还没有任何账号：这正是初始化页所处的状态。
	if has, err := srv.svc.HasUsers(context.Background()); err != nil || has {
		t.Fatalf("前置条件不成立：应当没有任何账号（has=%v err=%v）", has, err)
	}

	// 构造一次「确实由网关进程经 Unix Socket 递过来」的请求。
	// 信任与否取自连接阶段记下的对端信息（见 gatewayConnContext），这里直接把它放进上下文，
	// 因此不需要真的去开一条 Unix Socket —— 判据本身（通道是否可信）仍然是被测代码在判断。
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxGatewayPeerKey,
		GatewayPeer{Unix: true, Verified: true, UID: 0}))
	req.Header.Set("X-Trim-Userid", "1001")
	req.Header.Set("X-Trim-Username", "xiaoshizi")
	req.Header.Set("X-Trim-Isadmin", "true")

	rec := httptest.NewRecorder()
	srv.handleAuthState(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态码 = %d，期望 200；body=%s", rec.Code, rec.Body.String())
	}
	got := unwrapData(t, rec.Body.Bytes())
	if init, _ := got["initialized"].(bool); init {
		t.Fatalf("initialized 应为 false（还没有账号）；got=%v", got["initialized"])
	}
	gu, ok := got["gateway_user"].(map[string]any)
	if !ok {
		t.Fatalf("未初始化时也必须上报飞牛身份（初始化页要靠它决定是否给出「用飞牛账号登录」）；响应=%v", got)
	}
	if gu["username"] != "xiaoshizi" {
		t.Fatalf("gateway_user.username = %v，期望 xiaoshizi", gu["username"])
	}
	if gu["is_admin"] != true {
		t.Fatalf("gateway_user.is_admin = %v，期望 true", gu["is_admin"])
	}

	// 反面：同一条请求若**不是**来自可信通道，就不能上报身份 ——
	// 否则端口入口上任何人塞三个头就能让初始化页以为自己是飞牛管理员。
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)
	req2.Header.Set("X-Trim-Userid", "1001")
	req2.Header.Set("X-Trim-Username", "xiaoshizi")
	req2.Header.Set("X-Trim-Isadmin", "true")
	rec2 := httptest.NewRecorder()
	srv.handleAuthState(rec2, req2)
	got2 := unwrapData(t, rec2.Body.Bytes())
	if _, exists := got2["gateway_user"]; exists {
		t.Fatalf("端口通道上不得上报飞牛身份，却拿到了 gateway_user=%v", got2["gateway_user"])
	}
}
