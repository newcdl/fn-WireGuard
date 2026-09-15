package reconcile_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
	"fnwg/internal/wgkey"
)

// 本文件回归「事件通知」中由收敛引擎判定的那几类事件：
// 连接中断/恢复、配置下发失败、残留网络自愈。
//
// 这里刻意走完整的投递链路（判定 → 入队 → HTTP 投递），而不是只断言
// 「调用了某个函数」：通知最容易出问题的环节恰恰是「判定出来了但没发出去」，
// 而这类缺陷用桩函数断言是发现不了的。

// hookPayload 是 JSON 格式的通知载荷（与 internal/notify 的字段对应）。
type hookPayload struct {
	Event   string `json:"event"`
	Title   string `json:"title"`
	Message string `json:"message"`
	Peer    string `json:"peer"`
	Iface   string `json:"interface"`
}

// hookServer 收集投递过来的通知。
type hookServer struct {
	*httptest.Server
	mu  sync.Mutex
	got []hookPayload
	raw []string
}

func newHookServer(t *testing.T) *hookServer {
	t.Helper()
	h := &hookServer{}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p hookPayload
		_ = json.Unmarshal(body, &p)
		h.mu.Lock()
		h.got = append(h.got, p)
		h.raw = append(h.raw, string(body))
		h.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(h.Close)
	return h
}

// waitEvent 等待某类事件送达，返回该事件的原始载荷。
func (h *hookServer) waitEvent(t *testing.T, kind string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		for i, p := range h.got {
			if p.Event == kind {
				raw := h.raw[i]
				h.mu.Unlock()
				return raw
			}
		}
		h.mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}
	h.mu.Lock()
	kinds := []string{}
	for _, p := range h.got {
		kinds = append(kinds, p.Event)
	}
	h.mu.Unlock()
	t.Fatalf("等待事件 %s 超时，已收到: %v", kind, kinds)
	return ""
}

// mockControls 是内存后端额外提供的测试开关（真实后端没有这些方法）。
type mockControls interface {
	SetLinkDown(name string, down bool) bool
	SetApplyError(err error)
	SetHealActions(actions []string)
}

// engineEnv 是引擎测试环境。
type engineEnv struct {
	store  *store.Store
	engine *reconcile.Engine
	back   wgback.Backend
	ctl    mockControls
	ctx    context.Context
	hook   *hookServer
}

func newEngineEnv(t *testing.T, hookURL string) *engineEnv {
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

	ctx := context.Background()
	if hookURL != "" {
		if err := st.SetSetting(ctx, "notify_webhook", hookURL); err != nil {
			t.Fatal(err)
		}
	}

	back := wgback.NewMock(filepath.Join(dir, "netstate.json"))
	ctl, ok := back.(mockControls)
	if !ok {
		t.Fatal("内存后端应提供测试开关（SetLinkDown / SetApplyError / SetHealActions）")
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &engineEnv{store: st, engine: reconcile.New(st, back, logger), back: back, ctl: ctl}
}

// start 启动引擎循环（含通知投递协程），测试结束时自动停止。
func (e *engineEnv) start(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	e.ctx = ctx
	go e.engine.Run(ctx)
}

// createInterface 在库里创建一条「已启用且开机自启」的连接。
//
// 必须在 start 之前调用：收敛引擎启动时会立刻跑一轮，
// 之后再建连接就得等下一个 10 秒周期，测试会变慢且不稳定。
func (e *engineEnv) createInterface(t *testing.T, name string) *model.Interface {
	t.Helper()
	priv, _, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	it := &model.Interface{
		Name: name, UUID: name + "-uuid", PrivateKey: priv,
		ListenPort: 51820, MTU: 1420,
		Addresses:  []string{"10.10.0.1/24"},
		RouteTable: model.RouteTableOff,
		Enabled:    true, Autostart: true,
	}
	if err := e.store.CreateInterface(context.Background(), it); err != nil {
		t.Fatal(err)
	}
	return it
}

// waitInterfaceUp 等待连接被真正下发到数据面。
func (e *engineEnv) waitInterfaceUp(t *testing.T, name string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		list, err := e.back.Snapshot([]string{name})
		if err == nil {
			for _, st := range list {
				if st.Name == name && st.Up {
					return
				}
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待连接 %s 就绪超时", name)
}

// TestEngineNotifiesInterfaceDownAndUp 连接掉线与恢复都要通知：
// 界面上的红点只有主动打开界面才看得到，而用户往往在「连不上」时才发现。
func TestEngineNotifiesInterfaceDownAndUp(t *testing.T) {
	hook := newHookServer(t)
	env := newEngineEnv(t, hook.URL)
	env.hook = hook
	env.createInterface(t, "wg0")
	env.start(t)

	// 先让连接真正工作起来，再模拟掉线
	env.waitInterfaceUp(t, "wg0", 5*time.Second)

	if !env.ctl.SetLinkDown("wg0", true) {
		t.Fatal("应能控制该连接的链路状态")
	}
	env.engine.Sample(env.ctx)
	raw := hook.waitEvent(t, "iface_down", 5*time.Second)
	if !strings.Contains(raw, "wg0") {
		t.Fatalf("中断通知应点名是哪条连接，实际: %s", raw)
	}
	if !strings.Contains(raw, "无法连接") {
		t.Fatalf("中断通知应说明后果与下一步，实际: %s", raw)
	}
	// 通知里不应出现任何密钥材料
	if strings.Contains(raw, "PrivateKey") || strings.Contains(raw, "private") {
		t.Fatalf("通知载荷不应包含密钥相关内容: %s", raw)
	}

	// 恢复：同一个连接重新工作
	env.ctl.SetLinkDown("wg0", false)
	env.engine.Sample(env.ctx)
	raw = hook.waitEvent(t, "iface_up", 5*time.Second)
	if !strings.Contains(raw, "wg0") {
		t.Fatalf("恢复通知应点名是哪条连接，实际: %s", raw)
	}
}

// TestEngineNotifiesApplyFailure 配置没写进内核时，用户却以为改好了 ——
// 这类「以为生效了」必须主动说出去。
func TestEngineNotifiesApplyFailure(t *testing.T) {
	hook := newHookServer(t)
	env := newEngineEnv(t, hook.URL)
	env.start(t)
	env.createInterface(t, "wg0")

	// 让数据面在写入时报错（真实环境里对应权限不足、设备名冲突等）
	env.ctl.SetApplyError(errors.New("模拟：写入内核失败"))

	// 触发一次收敛：引擎启动时已收敛过一轮，这里再手动触发
	if _, err := env.engine.Reconcile(env.ctx); err == nil {
		t.Fatal("数据面报错时 Reconcile 应返回错误")
	}
	raw := hook.waitEvent(t, "apply_failed", 5*time.Second)
	if !strings.Contains(raw, "模拟：写入内核失败") {
		t.Fatalf("失败通知应带上原始原因，否则用户无从查起，实际: %s", raw)
	}
	if !strings.Contains(raw, "运行记录") {
		t.Fatalf("失败通知应给出下一步去处，实际: %s", raw)
	}
}

// TestEngineNotifiesNetHealed 本应用清理了自己留下的残留网络设置时，
// 即使自动修好了也要让用户知道：这是唯一会动到系统网络的路径。
//
// 这里覆盖的是真实的启动顺序：Run 启动投递协程 → 立刻做一次自愈。
func TestEngineNotifiesNetHealed(t *testing.T) {
	hook := newHookServer(t)
	env := newEngineEnv(t, hook.URL)
	env.ctl.SetHealActions([]string{"删除残留的默认路由 default dev wg0"})
	env.start(t)

	raw := hook.waitEvent(t, "net_healed", 5*time.Second)
	if !strings.Contains(raw, "残留") || !strings.Contains(raw, "清理") {
		t.Fatalf("自愈通知应说明发现了什么残留并已清理，实际: %s", raw)
	}
	if !strings.Contains(raw, "wg0") {
		t.Fatalf("自愈通知应带上被清理的具体内容，实际: %s", raw)
	}
}

// TestEngineNoEventOnFirstSight 应用刚启动时看到的状态不算「变化」：
// 否则每次重启都会给用户发一轮「设备上线 / 连接中断」。
func TestEngineNoEventOnFirstSight(t *testing.T) {
	hook := newHookServer(t)
	env := newEngineEnv(t, hook.URL)
	env.createInterface(t, "wg0")
	env.start(t)
	env.waitInterfaceUp(t, "wg0", 5*time.Second)

	// 连接一直是好的：不该有任何通知
	env.engine.Sample(env.ctx)
	env.engine.Sample(env.ctx)
	time.Sleep(200 * time.Millisecond)
	hook.mu.Lock()
	n := len(hook.got)
	kinds := []string{}
	for _, p := range hook.got {
		kinds = append(kinds, p.Event)
	}
	hook.mu.Unlock()
	if n != 0 {
		t.Fatalf("正常状态下不应产生通知，实际收到: %v", kinds)
	}
}
