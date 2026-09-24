// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestGatewayProbeReportsChannel 是只读诊断的「不能骗人」用例。
//
// 这个接口存在的唯一理由是：飞牛网关注入的身份头在真机上到底有没有、端口通道上伪造的头到不到得了应用，
// 都只能实测。因此它的结论必须严格按通道区分 —— 一旦它在端口通道上也回显「身份」，
// 后面所有判断都会被它带偏（甚至可能据此写出一个可被伪造头冒充管理员的登录功能）。
func TestGatewayProbeReportsChannel(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	// 建管理员并拿到会话：探针只对管理员开放，走的是与初始化主干完全相同的那条路
	setup, err := hs.Client().Post(hs.URL+"/api/v1/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"admin12345"}`))
	if err != nil {
		t.Fatal(err)
	}
	setup.Body.Close()
	cookie := ""
	for _, c := range setup.Cookies() {
		if c.Name == "fnwg_token" {
			cookie = "fnwg_token=" + c.Value
		}
	}
	if cookie == "" {
		t.Fatal("初始化未下发会话 Cookie")
	}

	// ① 端口通道 + 伪造身份头：必须报「不可信」，且绝不把伪造值当身份回显
	req, err := http.NewRequest(http.MethodGet, hs.URL+"/api/v1/auth/gateway-probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", cookie)
	req.Header.Set("X-Trim-Isadmin", "true")
	req.Header.Set("X-Trim-Userid", "99999")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	portBody, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("管理员应能访问探针，实际 HTTP %d: %s", res.StatusCode, portBody)
	}
	if !strings.Contains(string(portBody), `"channel":"port"`) || !strings.Contains(string(portBody), `"channel_trusted":false`) {
		t.Fatalf("端口通道应报 port 且不可信: %s", portBody)
	}
	if !strings.Contains(string(portBody), "X-Trim-Isadmin") {
		t.Fatalf("端口通道上确实收到了伪造头，应如实报出名字（这是「我们自己必须剥掉」的证据）: %s", portBody)
	}
	if strings.Contains(string(portBody), "gateway_identity") || strings.Contains(string(portBody), "99999") {
		t.Fatalf("端口通道上的头只能是伪造的，绝不能当成身份回显: %s", portBody)
	}

	// ② 经 socket 通道：必须报「可信」，并把三个头的取值原样回显（P0 要的就是这份实测数据）
	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "app.sock")
	srv.SetGatewaySocket(sock)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keeper := srv.NewGatewayKeeper(sock, srv.Router(nil))
	done := make(chan error, 1)
	go func() { done <- keeper.Run(ctx) }()
	if !waitFor(3*time.Second, func() bool { return probeGatewaySocket(sock) == gatewaySocketOK }) {
		t.Fatal("入口未能在 3 秒内建立")
	}

	sockBody := getBodyViaGatewaySocket(t, sock, GatewayPrefix+"/api/v1/auth/gateway-probe", cookie, map[string]string{
		"X-Trim-Userid":   "1000",
		"X-Trim-Username": "admin",
		"X-Trim-Isadmin":  "true",
	})
	if !strings.Contains(sockBody, `"channel":"socket"`) {
		t.Fatalf("经 socket 到达的请求必须报 socket: %s", sockBody)
	}

	var parsed struct {
		Data struct {
			ChannelTrusted  bool              `json:"channel_trusted"`
			PeerDetail      string            `json:"peer_detail"`
			GatewayIdentity map[string]string `json:"gateway_identity"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(sockBody), &parsed); err != nil {
		t.Fatalf("响应不是预期的 JSON: %v / %s", err, sockBody)
	}

	// 对端身份要靠 getsockopt 读，只有 Linux 支持（与既有网关用例同一口径）。
	// 非 Linux 上不是「跳过不测」，而是换成断言「如实说不可信、并给出原因」——
	// 探针在任何平台上都不许把「读不到对端身份」说成「可信」。
	if runtime.GOOS != "linux" {
		if parsed.Data.ChannelTrusted || parsed.Data.GatewayIdentity != nil {
			t.Fatalf("本机读不到对端身份，就不能判为可信、也不能回显身份: %s", sockBody)
		}
		if parsed.Data.PeerDetail == "" {
			t.Fatalf("不可信时必须给出原因（否则用户只能猜）: %s", sockBody)
		}
		return
	}

	if !parsed.Data.ChannelTrusted {
		t.Fatalf("Linux 上经 socket 到达且对端可信时，通道应判为可信: %s", sockBody)
	}
	id := parsed.Data.GatewayIdentity
	if id["userid"] != "1000" || id["username"] != "admin" || id["isadmin"] != "true" {
		t.Fatalf("通道可信时应原样回显这三个头: %s", sockBody)
	}
}

// TestGatewayProbeNeedsLogin 探针是「看身份」的接口，未登录一律问不到。
//
// 管理员之外的角色由 requirePerm 的既有用例覆盖，这里只钉住「匿名不可用」这一条：
// 若它哪天漏成免登录接口，等于把一个能看到请求身份的窗口开在门外。
func TestGatewayProbeNeedsLogin(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	res, err := hs.Client().Get(hs.URL + "/api/v1/auth/gateway-probe")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("未登录访问探针应被拒绝，实际 HTTP %d", res.StatusCode)
	}
}

// getBodyViaGatewaySocket 像飞牛网关那样经 Unix Socket 发一个真实请求，并把响应体读回来。
//
// 与既有的 getViaGatewaySocket 只差两点：带上会话 Cookie（探针要登录）、返回响应体（要核对内容）。
func getBodyViaGatewaySocket(t *testing.T, sock, path, cookie string, headers map[string]string) string {
	t.Helper()
	cl := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}
	req, err := http.NewRequest(http.MethodGet, "http://gateway"+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Cookie", cookie)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := cl.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("经 socket 访问应成功，实际 HTTP %d: %s", res.StatusCode, body)
	}
	return string(body)
}
