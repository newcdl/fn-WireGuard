// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// TestForgedGatewayIdentityCannotEscalate 是这套功能的**命门**用例。
//
// 官方文档只写了「不要信任客户端传入的用户 ID」，却从没承诺网关会剥掉客户端伪造的同名头。
// 因此只要应用在端口通道上也认那几个头，任何人能访问该端口就能靠
// `X-Trim-Isadmin: true` 把自己变成管理员 —— 这一条必须从结构上不可能。
//
// 用例走的是真实链路：用一个只读账号正常登录（拿到会话），再带上伪造的身份头去敲
// 只有管理员能用的接口。预期是 403，且诊断接口能证明那些头已经被中间件删掉。
func TestForgedGatewayIdentityCannotEscalate(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()
	ctx := context.Background()

	if _, err := srv.svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.svc.CreateUser(ctx, "viewer1", "viewer12345", model.RoleViewer, service.Actor{}); err != nil {
		t.Fatal(err)
	}

	login, err := hs.Client().Post(hs.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"viewer1","password":"viewer12345"}`))
	if err != nil {
		t.Fatal(err)
	}
	login.Body.Close()
	cookie := ""
	for _, c := range login.Cookies() {
		if c.Name == "fnwg_token" {
			cookie = "fnwg_token=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatalf("只读账号登录应下发会话（HTTP %d）", login.StatusCode)
	}

	// 只读账号 + 伪造的管理员身份头 → 必须还是 403
	req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/auth/security-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("X-Trim-Isadmin", "true")
	req.Header.Set("X-Trim-Userid", "99999")
	req.Header.Set("X-Trim-Username", "admin")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("伪造的网关身份头不得提权，实际 HTTP %d: %s", res.StatusCode, body)
	}

	// 只读账号连诊断接口都进不去（探针要 user.manage）—— 权限判定走的是本应用的角色
	probe, err := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/auth/gateway-probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	probe.Header.Set("Cookie", cookie)
	probeRes, err := hs.Client().Do(probe)
	if err != nil {
		t.Fatal(err)
	}
	probeRes.Body.Close()
	if probeRes.StatusCode != http.StatusForbidden {
		t.Fatalf("只读账号不该能访问诊断接口，实际 HTTP %d", probeRes.StatusCode)
	}

	// 换成管理员会话再看诊断：要能证明这些头**确实到了应用**、且**已被中间件剥掉**
	// （排障与将来复核都靠这份证据；只报名字、不记取值）。
	adminLogin, err := hs.Client().Post(hs.URL+"/api/v1/auth/login", "application/json",
		strings.NewReader(`{"username":"admin","password":"admin12345"}`))
	if err != nil {
		t.Fatal(err)
	}
	adminLogin.Body.Close()
	adminCookie := ""
	for _, c := range adminLogin.Cookies() {
		if c.Name == "fnwg_token" {
			adminCookie = "fnwg_token=" + c.Value
		}
	}
	if adminCookie == "" {
		t.Fatal("管理员登录应下发会话")
	}
	adminProbe, err := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/auth/gateway-probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	adminProbe.Header.Set("Cookie", adminCookie)
	adminProbe.Header.Set("X-Trim-Isadmin", "true")
	adminProbe.Header.Set("X-Trim-Userid", "99999")
	adminRes, err := hs.Client().Do(adminProbe)
	if err != nil {
		t.Fatal(err)
	}
	defer adminRes.Body.Close()
	adminBody, _ := io.ReadAll(adminRes.Body)
	if adminRes.StatusCode != http.StatusOK {
		t.Fatalf("管理员应能访问诊断接口，实际 HTTP %d: %s", adminRes.StatusCode, adminBody)
	}
	for _, want := range []string{`"channel":"port"`, `"channel_trusted":false`, "X-Trim-Isadmin", "X-Trim-Userid"} {
		if !strings.Contains(string(adminBody), want) {
			t.Fatalf("诊断应报出 %s（这是「伪造的头到了应用、且被我们剥掉」的证据）: %s", want, adminBody)
		}
	}
	if strings.Contains(string(adminBody), `"gateway_identity"`) {
		t.Fatalf("端口通道上的头一律按伪造处理，绝不能当成身份回显: %s", adminBody)
	}
}

// TestIdentityKindIgnoresChannel 是真实故障的回归：用户从飞牛桌面进来（网关通道），
// 但用的是自己的账号密码登录 —— 升级后他发现退不了登录，界面说「本次身份来自飞牛账号」。
// 根因是判断依据用了**通道**（从哪进来的），而正确的是**这次身份是怎么来的**：
// 有本应用令牌就是会话（有东西可注销），没有令牌才是飞牛身份（没有会话可退）。
func TestIdentityKindIgnoresChannel(t *testing.T) {
	u := &model.User{ID: 1, Username: "admin", Role: model.RoleAdmin, Status: 1}
	// 关键：这条上下文与真机上完全一样 —— 请求确实来自网关进程经 socket（通道可信）
	peer := GatewayPeer{Unix: true, UID: 0, Verified: true}
	req := func(token string) *http.Request {
		r := requestWithIdentity(u, token)
		return r.WithContext(context.WithValue(r.Context(), ctxGatewayPeerKey, peer))
	}

	if got := identityKind(req("local-token")); got != "session" {
		t.Fatalf("网关通道上的本应用会话应判为 session（可以退出登录），实际判成 %q", got)
	}
	if got := identityKind(req("")); got != "gateway" {
		t.Fatalf("没有本应用令牌才是飞牛身份，实际判成 %q", got)
	}
}
