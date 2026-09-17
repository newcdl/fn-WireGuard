package api

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fnwg/internal/core"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/service"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
)

func newGatewayTestServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "test.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	backend := wgback.NewMock(filepath.Join(dir, "netstate.json"))
	svc := service.New(st, core.NewLocal(reconcile.New(st, backend, logger)), logger, "test")
	return NewServer(svc, logger, "test", dir)
}

// TestStripGatewayHeaders 是防伪造的第一道防线：
// 端口通道上，网关注入类身份头必须在进入业务逻辑前就被删除。
// 只要这条成立，「在端口上伪造 X-Trim-Isadmin」就不可能有任何效果。
func TestStripGatewayHeaders(t *testing.T) {
	var seen struct{ uid, name, admin string }
	h := stripGatewayHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.uid = r.Header.Get(headerTrimUserID)
		seen.name = r.Header.Get(headerTrimUsername)
		seen.admin = r.Header.Get(headerTrimIsAdmin)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/gateway", nil)
	req.Header.Set(headerTrimUserID, "1000")
	req.Header.Set(headerTrimUsername, "admin")
	req.Header.Set(headerTrimIsAdmin, "true")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if seen.uid != "" || seen.name != "" || seen.admin != "" {
		t.Fatalf("端口通道上的网关注入头必须被删除，实际读到 uid=%q name=%q admin=%q",
			seen.uid, seen.name, seen.admin)
	}
}

// TestGatewayLoginRejectedOnTCPPort 是最高风险点的端到端回归：
// 直接访问端口并伪造身份头，绝不能换到管理员会话。
func TestGatewayLoginRejectedOnTCPPort(t *testing.T) {
	srv := newGatewayTestServer(t)

	hs := httptest.NewServer(srv.TCPRouter(nil))
	defer hs.Close()

	req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth/gateway", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTrimUserID, "1000")
	req.Header.Set(headerTrimUsername, "admin")
	req.Header.Set(headerTrimIsAdmin, "true")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("端口上伪造网关身份必须被拒绝，实际 HTTP %d", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "fnwg_token" && c.Value != "" {
			t.Fatal("被拒绝的请求不应拿到会话 Cookie")
		}
	}
}

// TestGatewayLoginOverUnixSocket 覆盖正常路径：
// 经 Unix Socket 到达的请求（对端就是本进程）可以按网关注入的身份免密登录。
//
// 仅在 Linux 上跑：对端身份校验依赖 SO_PEERCRED，其它平台取不到凭据，
// 而「取不到就拒绝」正是我们刻意选择的行为（见 peercred_other.go）。
func TestGatewayLoginOverUnixSocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix Socket 对端身份校验仅在 Linux 上可用")
	}
	srv := newGatewayTestServer(t)
	sock := filepath.Join(t.TempDir(), "app.sock")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw, err := srv.ListenGateway(sock, srv.Router(nil))
	if err != nil {
		t.Fatalf("监听网关 socket 失败: %v", err)
	}
	go func() { _ = gw.Serve(ctx) }()
	defer func() { _ = gw.Close() }()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			},
		},
	}

	req, err := http.NewRequest(http.MethodPost, "http://unix/api/v1/auth/gateway", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(headerTrimUserID, "1234")
	req.Header.Set(headerTrimUsername, "alice")
	req.Header.Set(headerTrimIsAdmin, "true")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求网关 socket 失败: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		t.Fatalf("网关通道上的免密登录应成功，实际 HTTP %d: %s", res.StatusCode, body)
	}
	var token string
	for _, c := range res.Cookies() {
		if c.Name == "fnwg_token" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("网关登录应下发会话 Cookie")
	}
	// 拿到的会话必须真的能用，且角色随飞牛管理员身份
	u, err := srv.svc.Authenticate(ctx, token)
	if err != nil {
		t.Fatalf("网关登录签发的会话应可用: %v", err)
	}
	if u.Role != "admin" || !strings.HasPrefix(u.Username, "nas:") {
		t.Fatalf("网关登录账号不符合预期: %+v", u)
	}
}

// TestGatewayStateExposedForLoginPage 登录页需要在不登录的情况下知道
// 「当前是不是飞牛桌面打开的」，据此决定是否展示一键免密登录。
func TestGatewayStateExposedForLoginPage(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.TCPRouter(nil))
	defer hs.Close()

	res, err := hs.Client().Get(hs.URL + "/api/v1/auth/state")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("auth/state 应可匿名访问: HTTP %d", res.StatusCode)
	}
	// 端口通道上不能出现可用的网关身份
	if strings.Contains(string(body), `"available":true`) {
		t.Fatalf("端口通道不应上报可用的网关身份: %s", body)
	}
	if !strings.Contains(string(body), `"login_mode"`) || !strings.Contains(string(body), `"gateway"`) {
		t.Fatalf("auth/state 应包含登录方式与网关入口信息: %s", body)
	}
	// socket_ready 必须和 entry 一起给登录页：只有这两个布尔值同时成立，
	// 页面才能把「入口没建起来」与「请求没走网关通道」分开说。
	// 真机故障里两者被混成一句「请从飞牛桌面打开」，而用户本来就是从桌面打开的。
	if !strings.Contains(string(body), `"socket_ready"`) {
		t.Fatalf("auth/state 应上报网关入口 socket 是否就绪: %s", body)
	}
}

// TestGatewayStateSocketReadyTracksListener 覆盖上面那条断言的取值语义：
// socket_ready 说的是「本进程有没有在监听网关入口」，与这一次请求怎么来的无关。
func TestGatewayStateSocketReadyTracksListener(t *testing.T) {
	srv := newGatewayTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/state", nil)

	got := srv.gatewayState(req)
	if got["socket_ready"] != false {
		t.Fatalf("入口未就绪时 socket_ready 应为 false，实际 %v", got["socket_ready"])
	}
	if got["entry"] != false {
		t.Fatalf("TCP 请求上 entry 应为 false，实际 %v", got["entry"])
	}

	// 入口就绪，但这条请求仍然来自端口：这正是真机上「从桌面打开却拿不到身份」的形态，
	// 页面必须据此说出「入口是好的，是这次请求没走到它上面」。
	srv.SetGatewaySocket("/vol1/@appstore/fn-wireguard/target/app.sock", "")
	got = srv.gatewayState(req)
	if got["socket_ready"] != true {
		t.Fatalf("入口就绪后 socket_ready 应为 true，实际 %v", got["socket_ready"])
	}
	if got["entry"] != false {
		t.Fatalf("TCP 请求上 entry 仍应为 false，实际 %v", got["entry"])
	}
}

// TestLoginModeStateReportsGatewaySocket 是「提示必须说实话」的回归。
//
// 设置页要靠 gateway_socket 区分两种截然不同的失败：入口本身没起来（环境问题，
// 去点多少次飞牛桌面图标都没用），与入口正常但还没走过（确实该去点一次）。
// 真机故障里两者被混为一谈，用户于是在两个入口之间反复来回、拿到的却是同一句提示。
func TestLoginModeStateReportsGatewaySocket(t *testing.T) {
	srv := newGatewayTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/login-mode", nil)

	// 启动方还没上报（例如 socket 没建起来）：必须按「未就绪」告知界面
	got := srv.loginModeState(req)
	if got["gateway_socket"] != false {
		t.Fatalf("未上报网关 socket 时 gateway_socket 应为 false，实际 %v", got["gateway_socket"])
	}
	if got["gateway_proven"] != false {
		t.Fatalf("从未成功免密登录过时 gateway_proven 应为 false，实际 %v", got["gateway_proven"])
	}

	// socket 就绪：界面应改回「去飞牛桌面打开一次」的指引
	srv.SetGatewaySocket("/vol1/@appstore/fn-wireguard/target/app.sock", "")
	got = srv.loginModeState(req)
	if got["gateway_socket"] != true {
		t.Fatalf("socket 就绪后 gateway_socket 应为 true，实际 %v", got["gateway_socket"])
	}
	if got["gateway_diagnosis"] != "" {
		t.Fatalf("入口正常时不应带诊断信息，实际 %q", got["gateway_diagnosis"])
	}
}

// TestGatewayDiagnosisRecorded 覆盖「入口通了但身份不被信任」这类静默失败：
// 前端自动免密登录是静默失败的，不在这里留痕，用户在界面上就完全看不到原因。
func TestGatewayDiagnosisRecorded(t *testing.T) {
	srv := newGatewayTestServer(t)
	srv.noteGatewayDiag("连接方身份未被信任：uid=1234 不在放行名单内")

	diag := srv.gatewayDiagnosis()
	if !strings.Contains(diag, "1234") {
		t.Fatalf("诊断信息应被记录并可展示给用户，实际 %q", diag)
	}
	// 启动方给出「已就绪」时不带原因，等于把上一轮的失败线索清掉
	srv.SetGatewaySocket("/vol1/@appstore/fn-wireguard/target/app.sock", "")
	if srv.gatewayDiagnosis() != "" {
		t.Fatalf("入口重新就绪后不应保留旧诊断，实际 %q", srv.gatewayDiagnosis())
	}
}

// TestSPAServedUnderGatewayPrefix 覆盖子路径部署：
// 网关下静态资源与页面都挂在 /app/fn-wireguard/ 前缀之后。
func TestSPAServedUnderGatewayPrefix(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.TCPRouter(nil))
	defer hs.Close()

	client := &http.Client{
		// 不自动跟随跳转，才能断言「不带斜杠会被规范化」
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	res, err := client.Get(hs.URL + GatewayPrefix)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusTemporaryRedirect {
		t.Fatalf("网关前缀根路径应重定向补斜杠，实际 HTTP %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != GatewayPrefix+"/" {
		t.Fatalf("重定向目标不正确: %s", loc)
	}
}
