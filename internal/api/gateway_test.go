// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
	// 计划备份执行器：这些用例不碰它，给一个开发模式的最小实例即可
	// （Dev 表示不做「必须在飞牛授权目录里」的校验——测试环境没有飞牛注入的环境变量）。
	planRunner := service.NewBackupPlanRunner(st, "test", service.BackupPlanEnv{OwnDir: dir, Dev: true}, logger)
	return NewServer(svc, logger, "test", dir, planRunner)
}

// TestCheckWSOriginAllowsFnOSDesktop 是「飞牛桌面实时状态永远连不上」的回归。
//
// 用户实际遇到的组合：页面由飞牛统一网关按 gatewayPrefix 打开，
// 浏览器发来的 Origin 是网关地址，而请求经应用目录下的 Unix Socket 到达本进程时
// Host 已被代理改写。旧实现只比 r.Host，于是每次握手都被判成跨站，
// 日志里只剩每 10 秒一条「origin not allowed」—— 既看不出成因，也看不出该改哪里。
//
// 注意这条放行只说明「这不是一次跨站握手」，与权限无关：网关通道上的请求
// 照样必须自己登录，本应用不认任何网关注入的身份。
func TestCheckWSOriginAllowsFnOSDesktop(t *testing.T) {
	srv := newGatewayTestServer(t)

	// newReq 模拟网关转发：Host 已被改写成后端地址，Origin 仍是浏览器地址栏里的那个。
	newReq := func(origin string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ws", nil)
		req.Host = "localhost"
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		return req
	}

	// 1) 直接访问端口：Origin 与 Host 一致，放行
	same := httptest.NewRequest(http.MethodGet, "http://192.168.1.10:34567/api/v1/ws", nil)
	same.Host = "192.168.1.10:34567"
	same.Header.Set("Origin", "http://192.168.1.10:34567")
	if !srv.checkWSOrigin(same) {
		t.Fatal("同源握手必须放行")
	}

	// 2) 端口通道上来自其它网站：必须拒绝，这是这层检查存在的全部意义
	if srv.checkWSOrigin(newReq("http://evil.example")) {
		t.Fatal("端口通道上来自其它网站的握手必须拒绝")
	}
	if srv.checkWSOrigin(newReq("null")) {
		t.Fatal("Origin: null 必须拒绝")
	}
	if !srv.checkWSOrigin(newReq("")) {
		t.Fatal("不带 Origin 的非浏览器客户端应放行")
	}

	// 3) 代理透传原始主机名时也放行（浏览器无法自定义握手请求头，不可伪造）
	xdh := newReq("http://nas.local:8000")
	xdh.Header.Set("X-Forwarded-Host", "nas.local:8000, proxy.internal")
	if !srv.checkWSOrigin(xdh) {
		t.Fatal("带 X-Forwarded-Host 的代理场景必须放行")
	}

	// 4) 飞牛统一网关通道：来源与 Host 都对不上，但连接方身份已核验 → 放行
	gwReq := newReq("http://192.168.1.10:8000")
	if srv.checkWSOrigin(gwReq) {
		t.Fatal("未经核验的通道不该仅因 Host 不同就被放行")
	}
	trusted := gwReq.WithContext(context.WithValue(gwReq.Context(), ctxGatewayPeerKey,
		GatewayPeer{Unix: true, UID: 0, Verified: true}))
	if !srv.checkWSOrigin(trusted) {
		t.Fatal("飞牛网关通道上的握手必须放行，否则前端实时状态永远连不上")
	}
	// 同一通道但连接方身份未获信任时，「来自 socket」本身不能成为放行理由
	untrusted := gwReq.WithContext(context.WithValue(gwReq.Context(), ctxGatewayPeerKey,
		GatewayPeer{Unix: true, UID: 1234, Verified: false, Detail: "不在允许列表内"}))
	if srv.checkWSOrigin(untrusted) {
		t.Fatal("连接方身份未核验的 Unix Socket 请求不得放行")
	}
}

// TestWSHandshakeOverGatewaySocket 端到端复现用户日志里的那条报错：
// 经网关 socket 到达、Host 被改写、Origin 是网关地址的握手必须升级成功。
//
// 这里手写握手报文而不是用 websocket 客户端：Origin 与 Host 完全由测试决定，
// 不会被客户端库的默认行为掩盖 —— 而这次的毛病恰恰出在这两个头上。
func TestWSHandshakeOverGatewaySocket(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix Socket 对端身份校验仅在 Linux 上可用")
	}
	srv := newGatewayTestServer(t)
	ctx := context.Background()
	if _, err := srv.svc.Setup(ctx, "admin", "admin12345"); err != nil {
		t.Fatal(err)
	}
	step, err := srv.svc.Login(ctx, service.LoginInput{
		Username: "admin", Password: "admin12345", UserAgent: "test", SrcIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}

	sock := filepath.Join(t.TempDir(), "app.sock")
	serveCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw, err := srv.ListenGateway(sock, srv.Router(nil))
	if err != nil {
		t.Fatalf("监听网关 socket 失败: %v", err)
	}
	go func() { _ = gw.Serve(serveCtx) }()
	defer func() { _ = gw.Close() }()

	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("连接网关 socket 失败: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	handshake := fmt.Sprintf("GET /api/v1/ws?token=%s HTTP/1.1\r\n"+
		"Host: localhost\r\n"+ // 网关改写后的 Host
		"Origin: http://192.168.1.10:8000\r\n"+ // 浏览器地址栏里的来源
		"Upgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n",
		step.Token)
	if _, err := conn.Write([]byte(handshake)); err != nil {
		t.Fatalf("发送握手请求失败: %v", err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("读取握手响应失败: %v", err)
	}
	if !strings.Contains(line, "101") {
		t.Fatalf("网关通道上的握手应升级成功，实际响应: %q", strings.TrimSpace(line))
	}
}

// TestGatewaySocketServesLoginPage 确认网关入口本身仍然可用：
// 从飞牛桌面点图标进来，拿到的是本应用页面（而不是 502），
// 只是页面里不再有任何免密入口 —— 要进去必须先登录。
func TestGatewaySocketServesLoginPage(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	res, err := hs.Client().Get(hs.URL + GatewayPrefix + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("未内嵌前端资源时应为 404（而不是 5xx），实际 HTTP %d", res.StatusCode)
	}
}

// TestSPAServedUnderGatewayPrefix 覆盖子路径部署：
// 网关下静态资源与页面都挂在 /app/fn-wireguard/ 前缀之后。
func TestSPAServedUnderGatewayPrefix(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
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

// TestAuthSetupCreatesAccountAndSession 是初始化主干：
// 建号、签发会话、下发安全码，全程不依赖任何登录方式选择。
func TestAuthSetupCreatesAccountAndSession(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	res, err := hs.Client().Post(hs.URL+"/api/v1/auth/setup", "application/json",
		strings.NewReader(`{"username":"admin","password":"admin12345"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("初始化应成功，实际 HTTP %d: %s", res.StatusCode, body)
	}
	if !strings.Contains(string(body), `"security_code"`) {
		t.Fatalf("初始化必须一并下发安全码: %s", body)
	}
	// 初始化响应里不该再出现任何登录方式字段
	if strings.Contains(string(body), "login_mode") {
		t.Fatalf("初始化响应不应再包含登录方式: %s", body)
	}
	var token string
	for _, c := range res.Cookies() {
		if c.Name == "fnwg_token" {
			token = c.Value
		}
	}
	if token == "" {
		t.Fatal("初始化成功后应下发会话 Cookie")
	}
}

// TestAuthStateNoLongerExposesLoginMode 登录前就能读到的那份状态里，
// 不该再有任何「登录方式 / 网关身份」字段：登录页只有账号密码一条路。
//
// 但 version 与 socket_ready 必须留下 —— 它们不是登录信息，
// 而是安装/升级脚本的自查依据（核对跑的是新版、确认桌面入口可用）。
func TestAuthStateNoLongerExposesLoginMode(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
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
	for _, gone := range []string{"login_mode", "gateway", "gateway_proven", "gateway_diagnosis"} {
		if strings.Contains(string(body), `"`+gone+`"`) {
			t.Fatalf("auth/state 不应再上报 %s: %s", gone, body)
		}
	}
	// 版本号必须保留：安装/升级脚本靠它核对「跑的就是刚装上去的版本」
	if !strings.Contains(string(body), `"version"`) {
		t.Fatalf("auth/state 应包含正在运行的版本: %s", body)
	}
	// socket_ready 必须保留：脚本靠它判断桌面入口是否就绪（0.8.16 的 502 自查）
	if !strings.Contains(string(body), `"socket_ready"`) {
		t.Fatalf("auth/state 应包含网关入口就绪状态: %s", body)
	}
}

// TestGatewaySocketReadyTracksListener 确认 socket_ready 说的是实话：
// 入口没监听时为 false，监听上了才为 true。
// 脚本据此在升级收尾时报错，所以它不能是一个恒定的值。
func TestGatewaySocketReadyTracksListener(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	// 尚未监听：必须是 false，否则脚本会把「入口没起来」当成成功放过去
	body := func() string {
		res, err := hs.Client().Get(hs.URL + "/api/v1/auth/state")
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return string(b)
	}
	if strings.Contains(body(), `"socket_ready":true`) {
		t.Fatal("没有监听网关入口时 socket_ready 不能为 true")
	}

	// 用短路径：socket 路径有长度上限（macOS 约 104 字节），
	// t.TempDir() 会带上很长的用例名，开发机上会直接 bind 失败。
	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "app.sock")
	serveCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw, err := srv.ListenGateway(sock, srv.Router(nil))
	if err != nil {
		t.Fatalf("监听网关 socket 失败: %v", err)
	}
	go func() { _ = gw.Serve(serveCtx) }()
	defer func() { _ = gw.Close() }()
	srv.SetGatewaySocket(gw.Path)

	if !strings.Contains(body(), `"socket_ready":true`) {
		t.Fatal("监听网关入口后 socket_ready 应为 true")
	}

	// 真机 502 的回归点：socket 文件被外部删掉后，进程还在、端口还在、日志也正常，
	// 但入口已经没有人监听了。这时必须如实变成 false —— 否则脚本的入口自查会被
	// 「进程启动时绑过一次」这个记忆骗过，它那套「自动修一次再判」的兜底永远不会触发，
	// 而用户从飞牛桌面点图标只能看到 502。
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body(), `"socket_ready":true`) {
		t.Fatal("socket 文件已被删除，socket_ready 不能仍报 true")
	}
}

// TestGatewayLoginEndpointGone 免密登录接口必须彻底消失，
// 而不是只把前端入口藏起来：直连接口仍能登进来等于没删。
func TestGatewayLoginEndpointGone(t *testing.T) {
	srv := newGatewayTestServer(t)
	hs := httptest.NewServer(srv.Router(nil))
	defer hs.Close()

	req, err := http.NewRequest(http.MethodPost, hs.URL+"/api/v1/auth/gateway", nil)
	if err != nil {
		t.Fatal(err)
	}
	// 照旧伪造一套网关注入头：现在它们连被读取的机会都没有
	req.Header.Set("X-Trim-Userid", "1000")
	req.Header.Set("X-Trim-Username", "admin")
	req.Header.Set("X-Trim-Isadmin", "true")
	res, err := hs.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotFound {
		t.Fatalf("免密登录接口应已不存在，实际 HTTP %d", res.StatusCode)
	}
	for _, c := range res.Cookies() {
		if c.Name == "fnwg_token" && c.Value != "" {
			t.Fatal("该请求不应拿到会话 Cookie")
		}
	}
}

// TestGatewayKeeperRebindsAfterSocketRemoved 是那道真机 502 的加固回归。
//
// 现场是这样的：socket 文件被外部删掉，而进程一直在跑、端口一切正常、
// 日志里只有一次启动记录 —— 在安装/升级/重启发生之前，用户点一次图标就是一次 502。
// 守护者必须自己发现并就地重建，而不是等下一次启动。
func TestGatewayKeeperRebindsAfterSocketRemoved(t *testing.T) {
	srv := newGatewayTestServer(t)
	// 用短路径：socket 路径有长度上限（macOS 约 104 字节），t.TempDir() 会带上很长的用例名
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

	// 首次绑定
	if !waitFor(3*time.Second, func() bool { return probeGatewaySocket(sock) == gatewaySocketOK }) {
		t.Fatal("入口未能在 3 秒内建立")
	}
	if code := getViaGatewaySocket(t, sock, GatewayPrefix+"/api/v1/auth/state"); code != http.StatusOK {
		t.Fatalf("入口建立后应能正常服务，实际 HTTP %d", code)
	}
	if !srv.gatewaySocketReady() {
		t.Fatal("入口已建立，socket_ready 应为 true")
	}

	// 外部把 socket 文件删掉 —— 真机上就是这一步让桌面图标开始报 502。
	// 注意此时进程还活着、端口还通，因此这个状态必须能被探测出来。
	if err := os.Remove(sock); err != nil {
		t.Fatal(err)
	}
	if srv.gatewaySocketReady() {
		t.Fatal("socket 文件已被删除，socket_ready 不能仍为 true")
	}

	// 一次巡检就应当就地重建（不必真等 15 秒的巡检周期）
	keeper.patrol(ctx)
	if st := probeGatewaySocket(sock); st != gatewaySocketOK {
		t.Fatalf("巡检后入口应被重建，实际状态=%d", st)
	}
	if code := getViaGatewaySocket(t, sock, GatewayPrefix+"/api/v1/auth/state"); code != http.StatusOK {
		t.Fatalf("重建后应能正常服务，实际 HTTP %d", code)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("守护者应正常退出: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ctx 结束后守护者应退出")
	}
}

// TestGatewayEntryStatusReportsMissingSocket 自检项必须说清「哪条通道、为什么」，
// 而不是把「端口能打开」当成一切正常 —— 那正是 502 被误判的根源。
func TestGatewayEntryStatusReportsMissingSocket(t *testing.T) {
	srv := newGatewayTestServer(t)
	// 未配置落点：不作断言（这台机器可能根本不走这条通道）
	if st := srv.gatewayEntryStatus(); st.Configured || st.Ready {
		t.Fatalf("未配置入口时不应断言：%+v", st)
	}

	dir, err := os.MkdirTemp("", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "app.sock")
	srv.SetGatewaySocket(sock)

	// 配置了落点但文件不在：必须明确报「不可用」并给出处置办法
	st := srv.gatewayEntryStatus()
	if !st.Configured || st.Ready {
		t.Fatalf("文件不存在时应报不可用：%+v", st)
	}
	if !strings.Contains(st.Detail, "502") || st.Fix == "" {
		t.Fatalf("必须说清后果与处置办法：%+v", st)
	}
}

// waitFor 轮询等待条件成立，用于等异步的监听建立。
func waitFor(d time.Duration, ok func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ok() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return ok()
}

// getViaGatewaySocket 像飞牛网关那样，经 Unix Socket 发一个真实请求。
func getViaGatewaySocket(t *testing.T, sock, path string) int {
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
	res, err := cl.Get("http://localhost" + path)
	if err != nil {
		t.Fatalf("经网关 socket 请求失败: %v", err)
	}
	defer res.Body.Close()
	return res.StatusCode
}
