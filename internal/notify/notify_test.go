// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"fnwg/internal/secretbox"
	"fnwg/internal/store"
)

func testStore(t *testing.T) *store.Store {
	t.Helper()
	box, err := secretbox.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(t.TempDir(), "notify.db"), box)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

// waitFor 轮询等待条件成立，避免用固定 sleep 制造偶发失败。
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

// TestMaskURLHidesToken 通知地址里的令牌绝不能出现在界面或日志里。
// 企业机器人的 hook token、ntfy 的主题名都藏在路径中，只保留主机名才算安全。
func TestMaskURLHidesToken(t *testing.T) {
	const secret = "a1b2c3d4-secret-token"
	got := MaskURL("https://hook.example.com/services/" + secret + "?k=" + secret)
	if strings.Contains(got, secret) {
		t.Fatalf("脱敏结果仍包含令牌: %s", got)
	}
	if !strings.HasPrefix(got, "https://hook.example.com") {
		t.Fatalf("应保留协议与主机名以便辨认，实际: %s", got)
	}
	if MaskURL("") != "" {
		t.Fatal("空地址应返回空字符串")
	}
	if MaskURL("::://坏地址") == "" {
		t.Fatal("无法识别的地址也应返回可展示的占位文本")
	}
}

// TestValidateURLRejectsBadScheme 只允许 http/https：
// 放行 file:// 之类的协议会让配置项变成一个本机文件读取入口。
func TestValidateURLRejectsBadScheme(t *testing.T) {
	for _, bad := range []string{"", "   ", "hook.example.com/x", "ftp://hook.example.com", "file:///etc/passwd"} {
		if _, err := ValidateURL(bad); err == nil {
			t.Fatalf("非法地址应被拒绝: %q", bad)
		}
	}
	if got, err := ValidateURL("  https://hook.example.com/x  "); err != nil || got != "https://hook.example.com/x" {
		t.Fatalf("合法地址应被归一化，实际: %q / %v", got, err)
	}
}

// TestEventSwitchSemantics 事件开关存的是「被明确关闭的事件」。
//
// 这个方向不能反：若存「开启集」，以后新增事件类型时老用户永远收不到，
// 而「新加的事件静默不生效」是最难被发现的一类问题。
func TestEventSwitchSemantics(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)

	// 全新安装（该项从未写过）：全部开启
	on := LoadEvents(ctx, st)
	for _, k := range Kinds() {
		if !on[k.Kind] {
			t.Fatalf("全新安装时 %s 应默认开启", k.Kind)
		}
	}

	// 关掉其中一类：只有它关闭，其余（含后来新增的类型）仍开启
	if err := st.SetSetting(ctx, SettingEventsOff, KindOffline); err != nil {
		t.Fatal(err)
	}
	on = LoadEvents(ctx, st)
	if on[KindOffline] {
		t.Fatal("明确关闭的事件不应开启")
	}
	if !on[KindQuota] || !on[KindIfaceDown] || !on[KindApplyFailed] {
		t.Fatalf("未提及的事件应保持开启，实际: %+v", on)
	}

	// 归一化：丢掉不认识的名字、去重、排序
	if got := FormatDisabled([]string{KindOffline, "不认识", KindOffline, KindQuota}); got != KindOffline+","+KindQuota {
		t.Fatalf("关闭集应去重并丢掉未知项，实际: %q", got)
	}
	if got := FormatDisabled(nil); got != "" {
		t.Fatalf("空关闭集应写成空串（表示全部开启），实际: %q", got)
	}
}

// TestLoadEventsMigratesLegacy 0.7.0 存的是「开启的事件」，升级后必须等价换算：
// 直接丢弃会让老用户突然收到他们当初特意关掉的事件。
func TestLoadEventsMigratesLegacy(t *testing.T) {
	ctx := context.Background()
	st := testStore(t)
	if err := st.SetSetting(ctx, SettingEventsLegacy, KindOnline+","+KindOffline); err != nil {
		t.Fatal(err)
	}
	on := LoadEvents(ctx, st)
	if !on[KindOnline] || !on[KindOffline] {
		t.Fatal("旧配置里开启的事件应保持开启")
	}
	if on[KindQuota] || on[KindIfaceDown] || on[KindApplyFailed] {
		t.Fatalf("旧配置里没有的事件应保持关闭，实际: %+v", on)
	}

	// 旧哨兵值 "none" 表示当时全部关闭，换算后同样全部关闭
	if err := st.SetSetting(ctx, SettingEventsLegacy, eventsNoneLegacy); err != nil {
		t.Fatal(err)
	}
	if on := LoadEvents(ctx, st); on[KindOnline] || on[KindQuota] {
		t.Fatalf("旧的全部关闭应换算为仍然全部关闭，实际: %+v", on)
	}

	// 新键一旦写入就以它为准（旧键不再影响结果）
	if err := st.SetSetting(ctx, SettingEventsOff, ""); err != nil {
		t.Fatal(err)
	}
	if on := LoadEvents(ctx, st); !on[KindOnline] || !on[KindApplyFailed] {
		t.Fatalf("新键存在时应以新键为准（空串=全部开启），实际: %+v", on)
	}
}

// TestEventKindsMetadata 事件清单是「哪些事件可以配置通知」的唯一来源：
// 每个类型都必须带分组、开关名、触发说明与级别，否则界面上会出现空白项。
func TestEventKindsMetadata(t *testing.T) {
	groups := map[string]bool{}
	for _, g := range Groups() {
		groups[g.Key] = true
	}
	if len(groups) == 0 {
		t.Fatal("应至少有一个事件分组")
	}
	seen := map[string]bool{}
	for _, k := range Kinds() {
		if seen[k.Kind] {
			t.Fatalf("事件类型重复: %s", k.Kind)
		}
		seen[k.Kind] = true
		if k.Label == "" || k.Detail == "" {
			t.Fatalf("%s 缺少开关名或触发说明: %+v", k.Kind, k)
		}
		if !groups[k.Group] {
			t.Fatalf("%s 的分组 %q 不在 Groups() 里", k.Kind, k.Group)
		}
		if k.Level != "info" && k.Level != "warn" {
			t.Fatalf("%s 的级别应为 info 或 warn，实际: %s", k.Kind, k.Level)
		}
		if Level(k.Kind) != k.Level {
			t.Fatalf("Level(%s) 应与清单里的级别一致", k.Kind)
		}
	}
	// 设备、连接、系统三类都要有事件，否则界面上会出现空分组
	for _, g := range Groups() {
		found := false
		for _, k := range Kinds() {
			if k.Group == g.Key {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("分组 %s 下没有任何事件", g.Key)
		}
	}
}

// TestDeliverPostsJSONAndRecordsResult 投递成功时应如实记录结果，
// 界面就靠这条记录回答「到底发出去了没有」。
func TestDeliverPostsJSONAndRecordsResult(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	var gotBody payload
	var gotCT, gotUA string
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotCT = r.Header.Get("Content-Type")
		gotUA = r.Header.Get("User-Agent")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := st.SetSetting(ctx, SettingWebhook, srv.URL); err != nil {
		t.Fatal(err)
	}

	s := New(st, nil)
	res := s.deliver(ctx, Event{Kind: KindOffline, Title: "设备「手机」已离线", Body: "已连续 3 分钟没有握手。", Peer: "手机", Iface: "wg0", At: time.Now()})
	if !res.OK {
		t.Fatalf("投递应成功，实际: %+v", res)
	}
	if hits != 1 {
		t.Fatalf("应恰好投递一次，实际 %d 次", hits)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Fatalf("默认格式应为 JSON，实际 Content-Type: %s", gotCT)
	}
	if !strings.Contains(gotUA, Source) {
		t.Fatalf("应带来源标识，实际: %s", gotUA)
	}
	if gotBody.Event != KindOffline || gotBody.Peer != "手机" || gotBody.Message == "" {
		t.Fatalf("载荷内容不完整: %+v", gotBody)
	}
	if gotBody.Level != "warn" {
		t.Fatalf("离线事件应为 warn 级别，实际: %s", gotBody.Level)
	}

	last := s.Status(ctx).Last
	if last == nil || !last.OK {
		t.Fatalf("应记录最近一次成功结果，实际: %+v", last)
	}
	if !strings.Contains(last.Message, "200") {
		t.Fatalf("结果里应带上 HTTP 状态码，实际: %s", last.Message)
	}
}

// TestDeliverTextFormatForPlainReceivers 纯文本格式是给只认纯文本的接收端留的出口。
func TestDeliverTextFormatForPlainReceivers(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	var body, ct string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ct = r.Header.Get("Content-Type")
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL)
	_ = st.SetSetting(ctx, SettingFormat, FormatText)

	s := New(st, nil)
	if res := s.deliver(ctx, Event{Kind: KindOnline, Title: "设备「平板」已上线", Body: "连接：wg0。", Peer: "平板", Iface: "wg0", At: time.Now()}); !res.OK {
		t.Fatalf("纯文本投递应成功，实际: %+v", res)
	}
	if !strings.Contains(ct, "text/plain") {
		t.Fatalf("应为纯文本类型，实际: %s", ct)
	}
	if !strings.Contains(body, "设备「平板」已上线") || !strings.Contains(body, "设备：平板") {
		t.Fatalf("纯文本应包含标题与对象，实际: %s", body)
	}
}

// TestDeliverFailureIsReadable 失败原因必须可读，且**我们自己**不能把带令牌的地址回显出去。
func TestDeliverFailureIsReadable(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	const token = "top-secret-token"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("unauthorized"))
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL+"/"+token)

	s := New(st, nil)
	res := s.deliver(ctx, Event{Kind: KindQuota, Title: "设备「旧手机」流量用尽，已自动停用", Peer: "旧手机", Iface: "wg0", At: time.Now()})
	if res.OK {
		t.Fatal("非 2xx 不应算成功")
	}
	if !strings.Contains(res.Message, "401") || !strings.Contains(res.Message, "unauthorized") {
		t.Fatalf("失败原因应包含状态码与接收端说明，实际: %s", res.Message)
	}
	if strings.Contains(res.Message, token) {
		t.Fatalf("失败原因不能回显地址里的令牌，实际: %s", res.Message)
	}

	// 连接失败时也不能把完整 URL 回显：url.Error.Error() 默认会带上它
	_ = st.SetSetting(ctx, SettingWebhook, "http://127.0.0.1:1/"+token)
	s2 := New(st, nil)
	res2 := s2.deliver(ctx, Event{Kind: KindQuota, Title: "x", At: time.Now()})
	if res2.OK || strings.Contains(res2.Message, token) {
		t.Fatalf("连接失败原因不能含令牌，实际: %+v", res2)
	}

	// 失败必须在应用日志里留痕（界面只显示最近一次，历史要靠日志）
	logs, total, err := st.ListLogs(ctx, "warn", "notify", "", 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total == 0 || len(logs) == 0 {
		t.Fatalf("失败应写入应用日志，实际 total=%d", total)
	}
	if strings.Contains(logs[0].Message, token) {
		t.Fatalf("日志不能含令牌，实际: %s", logs[0].Message)
	}
}

// TestDeliverTruncatesHugeErrorBody 接收端可能返回一整个 HTML 错误页，
// 原样记录会把状态与日志写爆，必须截断。
func TestDeliverTruncatesHugeErrorBody(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", 100000)))
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL)

	res := New(st, nil).deliver(ctx, Event{Kind: KindOnline, Title: "x", At: time.Now()})
	if res.OK {
		t.Fatal("502 不应算成功")
	}
	if len(res.Message) > respSnippet+64 {
		t.Fatalf("失败原因应被截断，实际长度 %d", len(res.Message))
	}
}

// TestSendTestRejectsEmptyURL 没填地址就点测试，应给出可操作的提示而不是静默失败。
func TestSendTestRejectsEmptyURL(t *testing.T) {
	st := testStore(t)
	if _, err := New(st, nil).SendTest(context.Background()); err == nil {
		t.Fatal("未配置地址时应返回错误")
	}
}

// TestNotifyReturnsImmediately 收敛循环每 10 秒一轮，投递必须完全不占用它的时间。
func TestNotifyReturnsImmediately(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		time.Sleep(1500 * time.Millisecond) // 模拟慢接收端（仍小于 3 秒超时）
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL)

	s := New(st, nil)
	go s.Start(ctx)

	start := time.Now()
	s.Notify(ctx, Event{Kind: KindOnline, Title: "设备「手机」已上线", Peer: "手机", Iface: "wg0"})
	elapsed := time.Since(start)
	if elapsed > 100*time.Millisecond {
		t.Fatalf("入队必须立刻返回（目标耗时上限 100ms），实际 %v", elapsed)
	}
	if !waitFor(t, 3*time.Second, func() bool { return atomic.LoadInt32(&hits) == 1 }) {
		t.Fatal("事件最终应被投递出去")
	}
}

// TestNotifyDedupeAndFilter 静默窗口内同类同对象只发一次；关闭的事件类型不发。
func TestNotifyDedupeAndFilter(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var online, offline int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var p payload
		_ = json.Unmarshal(raw, &p)
		switch p.Event {
		case KindOnline:
			atomic.AddInt32(&online, 1)
		case KindOffline:
			atomic.AddInt32(&offline, 1)
		}
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL)
	// 只开启「上线」：把其余事件全部写进关闭集，验证关闭的事件不会发出
	off := []string{}
	for _, k := range Kinds() {
		if k.Kind != KindOnline {
			off = append(off, k.Kind)
		}
	}
	_ = st.SetSetting(ctx, SettingEventsOff, FormatDisabled(off))

	s := New(st, nil)
	go s.Start(ctx)

	for i := 0; i < 3; i++ {
		s.Notify(ctx, Event{Kind: KindOnline, Title: "设备「手机」已上线", Peer: "手机", Iface: "wg0"})
	}
	s.Notify(ctx, Event{Kind: KindOffline, Title: "设备「手机」已离线", Peer: "手机", Iface: "wg0"})

	if !waitFor(t, 2*time.Second, func() bool { return atomic.LoadInt32(&online) >= 1 }) {
		t.Fatal("开启的事件应被投递")
	}
	time.Sleep(200 * time.Millisecond)
	if n := atomic.LoadInt32(&online); n != 1 {
		t.Fatalf("静默窗口内同类同对象只应投递一次，实际 %d 次", n)
	}
	if n := atomic.LoadInt32(&offline); n != 0 {
		t.Fatalf("关闭的事件不应投递，实际 %d 次", n)
	}

	// 换一台设备属于不同对象，应当照常投递
	s.Notify(ctx, Event{Kind: KindOnline, Title: "设备「平板」已上线", Peer: "平板", Iface: "wg0"})
	if !waitFor(t, 2*time.Second, func() bool { return atomic.LoadInt32(&online) == 2 }) {
		t.Fatalf("不同设备不应被去重掉，实际 %d 次", atomic.LoadInt32(&online))
	}
}

// TestNotifySkipsWhenUnconfigured 没配地址时静默跳过：这是正常状态，不是错误。
func TestNotifySkipsWhenUnconfigured(t *testing.T) {
	st := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := New(st, nil)
	go s.Start(ctx)
	s.Notify(ctx, Event{Kind: KindOnline, Title: "x", Peer: "手机", Iface: "wg0"})
	time.Sleep(100 * time.Millisecond)
	if st2 := s.Status(ctx); st2.Configured || st2.Last != nil {
		t.Fatalf("未配置时不应产生任何投递记录，实际: %+v", st2)
	}
}

// TestStatusCarriesKindsAndProblem 界面靠 Status 渲染开关，事件清单必须与后端一致；
// 地址非法时要给出问题描述，而不是只说「已配置」。
func TestStatusCarriesKindsAndProblem(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	s := New(st, nil)
	_ = st.SetSetting(ctx, SettingWebhook, "https://hook.example.com/secret-token")
	off := []string{}
	for _, k := range Kinds() {
		if k.Kind != KindOffline {
			off = append(off, k.Kind)
		}
	}
	_ = st.SetSetting(ctx, SettingEventsOff, FormatDisabled(off))

	got := s.Status(ctx)
	if len(got.AllKinds) != len(Kinds()) {
		t.Fatalf("事件清单应与 Kinds() 一致，实际 %d 项", len(got.AllKinds))
	}
	if len(got.Groups) != len(Groups()) {
		t.Fatalf("分组应与 Groups() 一致，实际 %d 项", len(got.Groups))
	}
	if !got.Configured || strings.Contains(got.URL, "secret-token") {
		t.Fatalf("地址应已配置且脱敏，实际: %+v", got)
	}
	if len(got.Events) != 1 || got.Events[0] != KindOffline {
		t.Fatalf("应只开启离线事件，实际: %v", got.Events)
	}
	if got.Problem != "" {
		t.Fatalf("合法地址不应报问题，实际: %s", got.Problem)
	}

	_ = st.SetSetting(ctx, SettingWebhook, "ftp://hook.example.com")
	if got := s.Status(ctx); got.Problem == "" {
		t.Fatal("非法地址应给出问题描述")
	}

	// 选了 Markdown 但地址不是已知的机器人地址：必须当场说清，而不是等到发消息时静默失败
	_ = st.SetSetting(ctx, SettingWebhook, "https://my-proxy.example.com/hook")
	_ = st.SetSetting(ctx, SettingFormat, FormatMarkdown)
	if got := s.Status(ctx); !strings.Contains(got.Problem, "Markdown") {
		t.Fatalf("Markdown 格式配了无法识别的地址时应给出问题描述，实际: %+v", got)
	}
}

// TestMarkdownPayloadPerVendor 钉钉与企业微信的 Markdown 报文结构不同。
// 发错结构时对方同样返回 HTTP 200，只有 errcode 非 0 ——
// 用户看到的现象是「配好了但群里没消息」，几乎没有线索可查。
func TestMarkdownPayloadPerVendor(t *testing.T) {
	ev := Event{
		Kind:  KindIfaceDown,
		Title: "连接「wg0」已中断",
		Body:  "这条连接本应处于工作状态，但当前没有工作，设备将无法连接。",
		Iface: "wg0",
		At:    time.Date(2026, 9, 15, 21, 30, 5, 0, time.Local),
	}
	decode := func(t *testing.T, body []byte, err error) map[string]any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("载荷不是合法 JSON: %s", body)
		}
		return out
	}

	dingBody, err := renderMarkdown(VendorDingtalk, ev)
	ding := decode(t, dingBody, err)
	if ding["msgtype"] != "markdown" {
		t.Fatalf("钉钉应发 markdown 消息，实际: %v", ding["msgtype"])
	}
	dmd, _ := ding["markdown"].(map[string]any)
	if dmd == nil || dmd["title"] == "" || dmd["text"] == "" {
		t.Fatalf("钉钉需要 title 与 text，实际: %v", dmd)
	}
	if _, has := dmd["content"]; has {
		t.Fatalf("钉钉结构里不应出现企业微信的 content 字段: %v", dmd)
	}
	if !strings.Contains(dmd["text"].(string), ev.Title) {
		t.Fatalf("正文应含标题，实际: %v", dmd["text"])
	}

	wecomBody, err := renderMarkdown(VendorWeCom, ev)
	wecom := decode(t, wecomBody, err)
	wmd, _ := wecom["markdown"].(map[string]any)
	if wmd == nil || wmd["content"] == "" {
		t.Fatalf("企业微信需要 content，实际: %v", wmd)
	}
	if _, has := wmd["text"]; has {
		t.Fatalf("企业微信结构里不应出现钉钉的 text 字段: %v", wmd)
	}

	// 未支持的接收端要报错，而不是发一个两边都不认的结构
	if _, err := renderMarkdown("unknown", ev); err == nil {
		t.Fatal("未知接收端应报错")
	}
}

// TestFeishuCardPayload 飞书用交互式卡片：标题放卡片头部（按级别上色），
// 正文放 markdown 元素。异常红色、正常绿色 —— 群里一眼能分辨要不要立刻处理。
func TestFeishuCardPayload(t *testing.T) {
	at := time.Date(2026, 9, 15, 21, 30, 5, 0, time.Local)
	decodeCard := func(t *testing.T, ev Event) (header map[string]any, text string) {
		t.Helper()
		body, err := renderMarkdown(VendorFeishu, ev)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]any
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("载荷不是合法 JSON: %s", body)
		}
		if out["msg_type"] != "interactive" {
			t.Fatalf("飞书应发交互式卡片，实际: %v", out["msg_type"])
		}
		card, _ := out["card"].(map[string]any)
		if card == nil {
			t.Fatalf("缺少 card 结构: %v", out)
		}
		elems, _ := card["elements"].([]any)
		if len(elems) != 1 {
			t.Fatalf("卡片应只有一个 markdown 元素，实际: %v", elems)
		}
		el, _ := elems[0].(map[string]any)
		if el["tag"] != "markdown" || el["content"] == "" {
			t.Fatalf("正文应是 markdown 元素，实际: %v", el)
		}
		h, _ := card["header"].(map[string]any)
		return h, el["content"].(string)
	}

	// 异常级别：红色头部
	header, text := decodeCard(t, Event{
		Kind: KindIfaceDown, Title: "连接「wg0」已中断", Body: "设备将无法连接。", Iface: "wg0", At: at,
	})
	if header["template"] != "red" {
		t.Fatalf("异常事件应用红色头部，实际: %v", header["template"])
	}
	title, _ := header["title"].(map[string]any)
	if title == nil || title["content"] != "连接「wg0」已中断" {
		t.Fatalf("标题应在卡片头部，实际: %v", header["title"])
	}
	if !strings.Contains(text, "**异常**") || !strings.Contains(text, "wg0") {
		t.Fatalf("正文应含级别标记与对象，实际: %s", text)
	}
	// 标题已经进了卡片头部，正文里不该再重复一遍
	if strings.Contains(text, "## ") {
		t.Fatalf("飞书正文不应重复一级标题（标题已在卡片头部）: %s", text)
	}

	// 正常级别：绿色头部
	header, text = decodeCard(t, Event{
		Kind: KindIfaceUp, Title: "连接「wg0」已恢复", Body: "设备可以正常连接了。", Iface: "wg0", At: at,
	})
	if header["template"] != "green" {
		t.Fatalf("正常事件应用绿色头部，实际: %v", header["template"])
	}
	if !strings.Contains(text, "**通知**") {
		t.Fatalf("正常事件的正文标记应为「通知」，实际: %s", text)
	}
}

// TestVendorOfDetectsOfficialHosts 只认官方的机器人地址；识别不出来时明确报错，
// 让用户改用 JSON 或纯文本。猜错结构比不发送更难排查。
func TestVendorOfDetectsOfficialHosts(t *testing.T) {
	ok := []struct{ url, want string }{
		{"https://oapi.dingtalk.com/robot/send?access_token=x", VendorDingtalk},
		{"https://robot.dingtalk.com/send", VendorDingtalk},
		{"https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=x", VendorWeCom},
		{"https://QYAPI.WEIXIN.QQ.COM/cgi-bin/webhook/send", VendorWeCom},
		{"https://open.feishu.cn/open-apis/bot/v2/hook/xxx", VendorFeishu},
		{"https://open.larksuite.com/open-apis/bot/v2/hook/xxx", VendorFeishu},
	}
	for _, c := range ok {
		got, err := VendorOf(c.url)
		if err != nil || got != c.want {
			t.Fatalf("%s 应识别为 %s，实际: %s / %v", c.url, c.want, got, err)
		}
	}
	bad := []string{
		"",
		"::://坏地址",
		"https://my-proxy.example.com/hook",
		"https://dingtalk.com.evil.example.com/hook",
	}
	for _, u := range bad {
		if _, err := VendorOf(u); err == nil {
			t.Fatalf("%q 不该被识别为已知接收端", u)
		}
	}
}

// TestResponseErrorDetectsVendorFailure 群机器人的业务失败藏在 HTTP 200 里，
// 只有解析错误码才看得见；否则会把「没送到」记成「已送达」。
func TestResponseErrorDetectsVendorFailure(t *testing.T) {
	if got := responseError([]byte(`{"errcode":0,"errmsg":"ok"}`), ""); got != "" {
		t.Fatalf("成功响应不应报错，实际: %s", got)
	}
	// errcode 是钉钉/企业微信的约定，语义明确：不论什么格式都检查
	got := responseError([]byte(`{"errcode":93000,"errmsg":"invalid webhook url, hint: [abc]"}`), "")
	if !strings.Contains(got, "93000") || !strings.Contains(got, "invalid webhook url") {
		t.Fatalf("应同时给出错误码与原因，实际: %s", got)
	}
	if got := responseError([]byte(`{"errcode":301000}`), ""); !strings.Contains(got, "未给出原因") {
		t.Fatalf("缺原因时应给出兜底说明，实际: %s", got)
	}
	// 非 JSON、纯文本、嵌套结构都不应误判为失败
	for _, body := range []string{"", "OK", "success", `<html></html>`, `{"data":{"errcode":5}}`} {
		if got := responseError([]byte(body), ""); got != "" {
			t.Fatalf("%q 不应被判为业务失败，实际: %s", body, got)
		}
	}
}

// TestResponseErrorHandlesFeishuCode 飞书用顶层 code 表示成功与否。
//
// 这里必须分接收端对待：通用 JSON 接收端惯用 code=200 表示成功，
// 若一律按「非 0 即失败」处理，会把成功记成失败 —— 那同样是说假话。
func TestResponseErrorHandlesFeishuCode(t *testing.T) {
	if got := responseError([]byte(`{"code":0,"msg":"success"}`), VendorFeishu); got != "" {
		t.Fatalf("飞书 code=0 表示成功，实际: %s", got)
	}
	got := responseError([]byte(`{"code":19024,"msg":"Key Words Not Found"}`), VendorFeishu)
	if !strings.Contains(got, "19024") || !strings.Contains(got, "Key Words Not Found") {
		t.Fatalf("飞书失败应给出错误码与原因，实际: %s", got)
	}
	// 通用接收端返回 code=200（常见的成功约定）不能算失败
	if got := responseError([]byte(`{"code":200,"message":"ok"}`), ""); got != "" {
		t.Fatalf("非飞书接收端的 code 不应被当作业务错误码，实际: %s", got)
	}
	// 没给原因时也要能读懂
	if got := responseError([]byte(`{"code":9499}`), VendorFeishu); !strings.Contains(got, "未给出原因") {
		t.Fatalf("缺原因时应给出兜底说明，实际: %s", got)
	}
}

// TestDeliverRecordsVendorFailureAsFailure 端到端确认：接收端返回非 0 errcode 时，
// 界面看到的必须是「失败 + 原因」，而不是「已送达」。
func TestDeliverRecordsVendorFailureAsFailure(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"errcode":93000,"errmsg":"invalid webhook url"}`))
	}))
	defer srv.Close()
	_ = st.SetSetting(ctx, SettingWebhook, srv.URL)

	res := New(st, nil).deliver(ctx, Event{Kind: KindIfaceDown, Title: "连接「wg0」已中断", At: time.Now()})
	if res.OK {
		t.Fatal("errcode 非 0 不应算成功")
	}
	if !strings.Contains(res.Message, "93000") {
		t.Fatalf("失败原因应包含错误码，实际: %s", res.Message)
	}
	if !strings.Contains(res.Payload, KindIfaceDown) {
		t.Fatalf("应记录实际发出的内容以便排障，实际: %s", res.Payload)
	}
}

// TestTruncateKeepsUTF8 记录「实际发出的内容」时会截断，但不能把多字节字符切坏 ——
// 切坏的结果是排障时看到一堆乱码，反而更难定位问题。
func TestTruncateKeepsUTF8(t *testing.T) {
	body := []byte(`{"title":"` + strings.Repeat("设备名称", 300) + `"}`)
	got := truncate(body)
	if !strings.HasSuffix(got, "…（已截断）") {
		t.Fatalf("超长内容应标注已截断，实际尾部: %s", got[len(got)-20:])
	}
	if !utf8.ValidString(got) {
		t.Fatal("截断后必须是合法的 UTF-8")
	}
	if short := truncate([]byte(`{"a":1}`)); short != `{"a":1}` {
		t.Fatalf("短内容不应被改动，实际: %s", short)
	}
}

// TestClampTitle 钉钉的标题有长度上限，超长会让整条消息被拒 ——
// 主动截断，避免用户去猜「为什么偏偏这条发不出去」。
func TestClampTitle(t *testing.T) {
	long := strings.Repeat("连接中断", 30)
	got := clampTitle(long)
	if r := []rune(got); len(r) > 61 || !strings.HasSuffix(got, "…") {
		t.Fatalf("超长标题应被截断并加省略号，实际长度 %d", len([]rune(got)))
	}
	if got := clampTitle("  短标题  "); got != "短标题" {
		t.Fatalf("短标题应只做去空格处理，实际: %q", got)
	}
}
