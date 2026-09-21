// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package notify 把关键事件异步推送到用户配置的 Webhook 地址。
//
// 三条硬约束（来自 docs/ROADMAP.md R3），实现时不能让步：
//  1. **绝不阻塞收敛循环**：收敛 10 秒一轮，Webhook 目标可能超时，
//     因此投递走独立队列 + 独立 goroutine，入队立刻返回；
//  2. **单次投递超时 3 秒**，失败只记日志与状态，不影响收敛结果；
//  3. **同类同对象在静默窗口内不重复推送**：设备在网络抖动时会反复上下线，
//     没有静默窗口的话用户会被几十条重复消息淹没，反而不再看告警。
//
// 刻意不做重试：Webhook 目标长期不可达时，重试只会让队列越堆越多，
// 而失败原因并未因此更清楚。本包的选择是把失败如实写进状态，
// 由界面直接显示「最近一次发送时间 + 结果 + 实际发出的内容」，让问题被看见。
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"fnwg/internal/store"
)

// 事件类型。
//
// 这里是「哪些事件可以配置通知」的唯一清单：界面上的开关、
// 投递时的过滤、设置项的解析全部由本清单驱动，不存在第二份。
const (
	// KindOnline 设备上线（本应用视角下重新连通）。
	KindOnline = "peer_online"
	// KindOffline 设备离线。
	KindOffline = "peer_offline"
	// KindExpired 设备到期并被自动停用。
	KindExpired = "peer_expired"
	// KindQuota 设备流量达到配额并被自动停用。
	KindQuota = "peer_quota"
	// KindIfaceDown 已启用且开机自启的连接不再工作（设备会连不上）。
	KindIfaceDown = "iface_down"
	// KindIfaceUp 中断过的连接重新工作。
	KindIfaceUp = "iface_up"
	// KindApplyFailed 配置写入内核失败。
	KindApplyFailed = "apply_failed"
	// KindNetHealed 本应用发现并清理了自己的残留网络设置。
	KindNetHealed = "net_healed"
	// KindBackupFailed 计划备份执行失败（写不进目标目录、目标目录不可写等）。
	//
	// 备份失败特别值得推送：它不痛不痒，界面不看就发现不了，
	// 而等到需要备份那天才发现「已经三个月没备份成功」，代价太大。
	KindBackupFailed = "backup_failed"
	// KindInspectProblem 配置漂移巡检发现了需要处理的问题。
	//
	// 巡检报出来的都是「安静地不工作」这一类：开关还是开的、界面看着正常，
	// 直到真的需要它那天才发现早就失效了 —— 正是最值得主动说一声的故障。
	// 只推错误级结论：警告（如「疑似残留网卡」）不推，免得每天一条同样的提醒被屏蔽。
	KindInspectProblem = "inspect_problem"
	// KindTest 测试消息，由用户在界面上主动触发。
	KindTest = "test"
)

// 事件分组，供界面分节展示（8 个开关平铺会很难扫）。
const (
	GroupPeer   = "peer"
	GroupIface  = "iface"
	GroupSystem = "system"
)

// 设置项键名。
//
// 前三个由用户在界面上配置；SettingLast 是运行时状态，由本包写入。
// 状态之所以也放设置表：代理进程（收敛、判定事件）与 Web 进程（提供界面）
// 是两个独立进程，只有落库，「最近一次发送结果」才对用户可见。
const (
	// SettingWebhook 通知地址。
	SettingWebhook = "notify_webhook"
	// SettingEventsOff 被明确关闭的事件（逗号分隔；空串表示全部开启）。
	//
	// 语义是**关闭集**而不是开启集，这一点很关键：以后新增事件类型时，
	// 老用户默认就能收到（不想要再关掉）。若反过来存「开启集」，
	// 新加的事件会静默地永远不生效 —— 那类失效最难被发现。
	SettingEventsOff = "notify_off"
	// SettingEventsLegacy 是 0.7.0 的「开启集」设置项，只用于一次性兼容换算。
	SettingEventsLegacy = "notify_events"
	// SettingFormat 推送格式：json（默认）、text 或 markdown。
	SettingFormat = "notify_format"
	// SettingLast 最近一次投递结果（JSON）。
	SettingLast = "notify_last"
)

// 推送格式。
const (
	// FormatJSON 以 JSON 对象投递，便于脚本与自动化平台消费。
	FormatJSON = "json"
	// FormatText 以纯文本投递，兼容只认纯文本的接收端。
	FormatText = "text"
	// FormatMarkdown 按接收端（钉钉 / 企业微信）的报文结构投递 Markdown，
	// 在群聊里能显示标题、加粗与分点，比一长串 JSON 可读得多。
	FormatMarkdown = "markdown"
)

// 可识别的 Markdown 接收端。
//
// 三家都用 HTTP 200 + JSON 里的错误码表达业务失败，报文结构与错误码字段却各不相同，
// 因此必须区分；区分不出来时明确报错，绝不猜（见 VendorOf）。
const (
	// VendorDingtalk 钉钉群机器人：markdown.title + markdown.text，错误码字段 errcode。
	VendorDingtalk = "dingtalk"
	// VendorWeCom 企业微信群机器人：markdown.content，错误码字段 errcode。
	VendorWeCom = "wecom"
	// VendorFeishu 飞书（含国际版 Lark）机器人：交互式卡片，错误码字段 code。
	VendorFeishu = "feishu"
)

// Source 是投递载荷里的来源标识。
const Source = "fn-wireguard"

// 投递约束。
const (
	// DeliverTimeout 单次投递超时。
	DeliverTimeout = 3 * time.Second
	// DedupeWindow 同类同对象事件的默认静默窗口。
	DedupeWindow = 5 * time.Minute
	// queueSize 队列长度：一次网络抖动最多堆积这么多事件，再多丢弃并计数。
	queueSize = 64
	// respSnippet 失败时最多记录多少响应体，够看清原因又不会写爆日志。
	respSnippet = 512
	// payloadTrunc 记录「实际发出的内容」时保留多少字符。
	payloadTrunc = 600
	// eventsNoneLegacy 是 0.7.0 存下的「全部关闭」哨兵值，仅用于兼容换算。
	eventsNoneLegacy = "none"
)

// quietWindows 是少数事件的专用静默窗口。
//
// 「配置下发失败」这类故障会持续存在，而收敛循环每 10 秒就重试一次；
// 用默认窗口的话一小时会推 12 条同样的消息，用户会直接屏蔽这个渠道 ——
// 那比不推更糟。这类事件用更长的窗口：既提醒「还没好」，又不刷屏。
var quietWindows = map[string]time.Duration{
	KindApplyFailed: 30 * time.Minute,
	KindNetHealed:   30 * time.Minute,
}

// GroupInfo 描述一个事件分组。
type GroupInfo struct {
	Key   string `json:"key"`
	Label string `json:"label"`
}

// Groups 返回全部分组，顺序固定。
func Groups() []GroupInfo {
	return []GroupInfo{
		{Key: GroupPeer, Label: "设备"},
		{Key: GroupIface, Label: "连接"},
		{Key: GroupSystem, Label: "系统"},
	}
}

// KindInfo 描述一类事件，供界面渲染开关与说明。
type KindInfo struct {
	Kind string `json:"kind"`
	// Group 所属分组，取值见 Group* 常量。
	Group string `json:"group"`
	// Label 界面上的开关名。
	Label string `json:"label"`
	// Detail 一句话说清「什么时候会收到它」。
	Detail string `json:"detail"`
	// Level 事件的默认级别，info 或 warn。
	Level string `json:"level"`
}

// Kinds 返回全部可配置的事件类型，顺序固定（界面按此顺序渲染）。
//
// 新增事件只需在这里加一行：设置项的解析、界面的开关、投递过滤都会自动跟上。
func Kinds() []KindInfo {
	return []KindInfo{
		{Kind: KindOnline, Group: GroupPeer, Label: "设备上线", Level: "info",
			Detail: "设备重新连通时推送一次（应用重启后第一次见到设备不算）"},
		{Kind: KindOffline, Group: GroupPeer, Label: "设备离线", Level: "warn",
			Detail: "设备超过 3 分钟没有握手时推送一次"},
		{Kind: KindExpired, Group: GroupPeer, Label: "设备到期", Level: "warn",
			Detail: "设备到达设定的到期时间、被自动停用时推送"},
		{Kind: KindQuota, Group: GroupPeer, Label: "流量用尽", Level: "warn",
			Detail: "设备流量达到配额、被自动停用时推送"},
		{Kind: KindIfaceDown, Group: GroupIface, Label: "连接中断", Level: "warn",
			Detail: "已启用且开机自动启用的连接停止工作时推送（此时设备连不上）"},
		{Kind: KindIfaceUp, Group: GroupIface, Label: "连接恢复", Level: "info",
			Detail: "中断过的连接重新工作时推送"},
		{Kind: KindApplyFailed, Group: GroupSystem, Label: "配置下发失败", Level: "warn",
			Detail: "配置写入内核失败时推送；持续失败每 30 分钟提醒一次，不会刷屏"},
		{Kind: KindNetHealed, Group: GroupSystem, Label: "残留网络自愈", Level: "warn",
			Detail: "本应用发现并清理了自己遗留的路由或规则时推送（通常出现在升级、异常退出之后）"},
		{Kind: KindBackupFailed, Group: GroupSystem, Label: "计划备份失败", Level: "warn",
			Detail: "计划备份没写成功时推送（目标目录不可写、磁盘满、目录被删等）；同一天只推一次"},
		{Kind: KindInspectProblem, Group: GroupSystem, Label: "巡检发现问题", Level: "warn",
			Detail: "定期巡检查出「需要处理」的问题时推送（连接没工作、上网路线异常、计划备份失败等）；" +
				"只是「待确认」的提示不推送，避免刷屏"},
	}
}

// Level 返回事件级别，取自 Kinds() 中的同一条定义。
func Level(kind string) string {
	for _, k := range Kinds() {
		if k.Kind == kind {
			return k.Level
		}
	}
	return "info"
}

// Event 是一条待投递的事件。
type Event struct {
	// Kind 事件类型，取值见 Kind* 常量。
	Kind string
	// Title 一句话摘要（推送内容的第一行）。
	Title string
	// Body 具体事实：哪个设备、什么原因、建议做什么。
	Body string
	// Peer 相关设备名，可为空。
	Peer string
	// Iface 相关连接名，可为空。
	Iface string
	// At 事件发生时间，零值表示取当前时间。
	At time.Time
}

// Config 是从设置项读出的通知配置。
type Config struct {
	// URL 用户填写的通知地址（原样，未脱敏）。
	URL string
	// Format 推送格式。
	Format string
	// events 开启的事件集合。
	events map[string]bool
}

// Enabled 判断某类事件是否已开启。
func (c Config) Enabled(kind string) bool { return c.events[kind] }

// EnabledKinds 返回已开启的事件类型，按 Kinds() 的顺序。
func (c Config) EnabledKinds() []string {
	out := []string{}
	for _, k := range Kinds() {
		if c.events[k.Kind] {
			out = append(out, k.Kind)
		}
	}
	return out
}

// knownKinds 返回全部事件类型名。
func knownKinds() []string {
	out := make([]string, 0, len(Kinds()))
	for _, k := range Kinds() {
		out = append(out, k.Kind)
	}
	return out
}

// ParseDisabled 解析「关闭集」，并丢掉不认识的事件名。
//
// 丢掉未知项而不是报错：旧版本存下的名字（或手工改错的值）不该让整个
// 通知配置失效；下次保存时会被重新归一化写回。
func ParseDisabled(raw string) []string {
	known := map[string]bool{}
	for _, k := range knownKinds() {
		known[k] = true
	}
	out := []string{}
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p == "" || !known[p] || containsString(out, p) {
			continue
		}
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// FormatDisabled 序列化「关闭集」（空集写成空串）。
func FormatDisabled(disabled []string) string {
	out := ParseDisabled(strings.Join(disabled, ","))
	return strings.Join(out, ",")
}

// LoadEvents 读出「事件是否开启」的完整映射。
//
// 读取顺序：新的关闭集 → 兼容 0.7.0 的开启集 → 全新安装全部开启。
// 兼容换算是必要的：0.7.0 存的是「开启的事件」，直接丢弃会让老用户在
// 升级后突然收到所有事件（包括他们特意关掉的那些）。
func LoadEvents(ctx context.Context, st *store.Store) map[string]bool {
	all := map[string]bool{}
	for _, k := range knownKinds() {
		all[k] = true
	}
	if raw, ok := st.LookupSetting(ctx, SettingEventsOff); ok {
		off := map[string]bool{}
		for _, k := range ParseDisabled(raw) {
			off[k] = true
		}
		for k := range all {
			all[k] = !off[k]
		}
		return all
	}
	if raw, ok := st.LookupSetting(ctx, SettingEventsLegacy); ok {
		on := map[string]bool{}
		if !strings.EqualFold(strings.TrimSpace(raw), eventsNoneLegacy) {
			for _, k := range ParseDisabled(raw) {
				on[k] = true
			}
		}
		for k := range all {
			all[k] = on[k]
		}
		return all
	}
	return all
}

// LoadConfig 从设置表读取通知配置。
func LoadConfig(ctx context.Context, st *store.Store) Config {
	return Config{
		URL:    strings.TrimSpace(st.GetSetting(ctx, SettingWebhook, "")),
		Format: NormalizeFormat(st.GetSetting(ctx, SettingFormat, "")),
		events: LoadEvents(ctx, st),
	}
}

// NormalizeFormat 把推送格式归一化成 json / text / markdown（其它取值按 json 处理）。
func NormalizeFormat(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case FormatText:
		return FormatText
	case FormatMarkdown:
		return FormatMarkdown
	}
	return FormatJSON
}

// ValidateURL 校验并归一化通知地址。
func ValidateURL(raw string) (string, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", errors.New("还没有填写通知地址")
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", errors.New("通知地址格式不正确，请填写完整的地址")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("通知地址需要以 http:// 或 https:// 开头")
	}
	if u.Host == "" {
		return "", errors.New("通知地址缺少主机名")
	}
	return u.String(), nil
}

// MaskURL 把地址脱敏成可安全展示与记日志的形式。
//
// 通知地址里几乎总带着令牌（企业机器人的 hook token、ntfy 的主题名），
// 原样显示或写进日志，等于把这些凭据交给每个能打开界面、能看日志的人。
func MaskURL(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	u, err := url.Parse(v)
	if err != nil || u.Host == "" {
		return "（地址无法识别）"
	}
	out := u.Scheme + "://" + u.Host
	if p := strings.Trim(u.Path, "/"); p != "" {
		out += "/…"
	}
	if u.RawQuery != "" {
		out += "?…"
	}
	return out
}

// VendorOf 从地址判断 Markdown 该按哪家的报文结构投递。
//
// 为什么不统一发一种：钉钉要 {"msgtype":"markdown","markdown":{"title","text"}}，
// 企业微信要 {"msgtype":"markdown","markdown":{"content"}}，
// 飞书要 {"msg_type":"interactive","card":{...}}。发错结构时对方同样返回
// HTTP 200，只是错误码非 0，用户看到的现象是「配好了但群里没消息」。
// 判断不出来时明确报错，让用户改用 JSON 或纯文本，绝不猜。
func VendorOf(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Hostname() == "" {
		return "", errors.New("通知地址无法识别，Markdown 格式需要能判断接收端")
	}
	host := strings.ToLower(u.Hostname())
	switch {
	case host == "oapi.dingtalk.com" || strings.HasSuffix(host, ".dingtalk.com"):
		return VendorDingtalk, nil
	case host == "qyapi.weixin.qq.com" || strings.HasSuffix(host, ".weixin.qq.com"):
		return VendorWeCom, nil
	case strings.HasSuffix(host, ".feishu.cn") || strings.HasSuffix(host, ".larksuite.com"):
		return VendorFeishu, nil
	}
	return "", fmt.Errorf("Markdown 格式目前只支持钉钉（oapi.dingtalk.com）、企业微信（qyapi.weixin.qq.com）"+
		"与飞书（open.feishu.cn）的群机器人，当前地址的主机名是 %s："+
		"请改用「JSON」或「纯文本」，或换成官方机器人地址", host)
}

// Result 是一次投递的结果。
type Result struct {
	OK         bool      `json:"ok"`
	StatusCode int       `json:"status_code,omitempty"`
	Message    string    `json:"message"`
	At         time.Time `json:"at"`
	// Payload 实际发出的内容（截断后）。
	//
	// 排障时最需要的恰恰是这一条：「到底发了什么过去」是接收端不显示消息时
	// 唯一可靠的线索（标题太长被截断？关键词不匹配？字段名不对？）。
	// 内容里不含地址与任何令牌，只有设备名与事件描述。
	Payload string `json:"payload,omitempty"`
}

// Status 是通知能力的对外快照，供界面展示。
type Status struct {
	// Configured 是否已填写通知地址。
	Configured bool `json:"configured"`
	// URL 脱敏后的地址。
	URL string `json:"url"`
	// Problem 地址本身的问题（为空表示地址可用）。
	Problem string `json:"problem,omitempty"`
	// Format 当前推送格式。
	Format string `json:"format"`
	// Events 已开启的事件类型。
	Events []string `json:"events"`
	// AllKinds 全部可配置事件，界面据此渲染开关（避免前后端各维护一份清单）。
	AllKinds []KindInfo `json:"all_kinds"`
	// Groups 事件分组，界面据此分节。
	Groups []GroupInfo `json:"groups"`
	// Last 最近一次投递结果（含测试消息）。
	Last *Result `json:"last,omitempty"`
	// Sent / Failed / Deduped / Dropped 本次进程生命周期内的计数。
	Sent    int64 `json:"sent"`
	Failed  int64 `json:"failed"`
	Deduped int64 `json:"deduped"`
	Dropped int64 `json:"dropped"`
}

// Sender 是事件投递器。
//
// 可被多个 goroutine 并发使用；代理进程用它投递事件，
// Web 进程只用来发送测试消息（不启动队列）。
type Sender struct {
	st     *store.Store
	log    *slog.Logger
	client *http.Client
	queue  chan Event

	mu      sync.Mutex
	seen    map[string]time.Time
	sent    int64
	failed  int64
	deduped int64
	dropped int64
}

// New 创建投递器。
func New(st *store.Store, logger *slog.Logger) *Sender {
	if logger == nil {
		logger = slog.Default()
	}
	return &Sender{
		st:     st,
		log:    logger,
		client: &http.Client{Timeout: DeliverTimeout},
		queue:  make(chan Event, queueSize),
		seen:   map[string]time.Time{},
	}
}

// Start 启动投递队列，阻塞直到 ctx 结束。
// 调用方应当把它放在独立 goroutine 里；ctx 结束后队列中未投递的事件会被丢弃。
func (s *Sender) Start(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-s.queue:
			s.deliver(ctx, ev)
		}
	}
}

// Notify 把事件放入队列后立刻返回。
//
// 这里刻意不做任何网络操作：调用方是 10 秒一轮的收敛循环，
// 一次 Webhook 超时就会让设备状态滞后一整轮。
func (s *Sender) Notify(ctx context.Context, ev Event) {
	cfg := LoadConfig(ctx, s.st)
	if cfg.URL == "" || !cfg.Enabled(ev.Kind) {
		return
	}
	if ev.At.IsZero() {
		ev.At = time.Now()
	}
	if !s.allow(ev) {
		return
	}
	select {
	case s.queue <- ev:
	default:
		s.mu.Lock()
		s.dropped++
		s.mu.Unlock()
		s.log.Warn("通知队列已满，丢弃事件", "kind", ev.Kind, "peer", ev.Peer)
	}
}

// allow 判断事件是否应当投递（静默窗口去重）。
//
// 在入队时而不是投递成功后就打标记：目标不可达时若不打标记，
// 每轮收敛都会重排同一个事件，队列很快被同一件事占满。
func (s *Sender) allow(ev Event) bool {
	key := ev.Kind + "|" + ev.Iface + "|" + ev.Peer
	window := DedupeWindow
	if w, ok := quietWindows[ev.Kind]; ok {
		window = w
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if last, ok := s.seen[key]; ok && now.Sub(last) < window {
		s.deduped++
		return false
	}
	// 顺手清理过期条目：长时间运行后去重表会随设备数增长，不能只增不减。
	for k, t := range s.seen {
		if now.Sub(t) >= DedupeWindow {
			delete(s.seen, k)
		}
	}
	s.seen[key] = now
	return true
}

// SendTest 同步投递一条测试消息并返回结果，供界面的「发送测试」使用。
func (s *Sender) SendTest(ctx context.Context) (Result, error) {
	cfg := LoadConfig(ctx, s.st)
	if _, err := ValidateURL(cfg.URL); err != nil {
		return Result{}, err
	}
	return s.deliver(ctx, Event{
		Kind:  KindTest,
		Title: "测试通知",
		Body:  "如果你收到这条消息，说明通知地址与格式都配置正确；之后设备上下线、到期、流量用尽、连接中断都会推送到这里。",
		At:    time.Now(),
	}), nil
}

// Status 返回通知状态快照。
func (s *Sender) Status(ctx context.Context) Status {
	cfg := LoadConfig(ctx, s.st)
	st := Status{
		Configured: cfg.URL != "",
		URL:        MaskURL(cfg.URL),
		Format:     cfg.Format,
		Events:     cfg.EnabledKinds(),
		AllKinds:   Kinds(),
		Groups:     Groups(),
	}
	if cfg.URL != "" {
		if _, err := ValidateURL(cfg.URL); err != nil {
			st.Problem = err.Error()
		}
		if cfg.Format == FormatMarkdown {
			if _, err := VendorOf(cfg.URL); err != nil {
				st.Problem = err.Error()
			}
		}
	}
	st.Last = loadLast(ctx, s.st)

	s.mu.Lock()
	st.Sent, st.Failed, st.Deduped, st.Dropped = s.sent, s.failed, s.deduped, s.dropped
	s.mu.Unlock()
	return st
}

// deliver 执行一次真实投递并记录结果。任何错误都转化为可读的结果，不向上抛。
func (s *Sender) deliver(ctx context.Context, ev Event) Result {
	cfg := LoadConfig(ctx, s.st)
	target, err := ValidateURL(cfg.URL)
	if err != nil {
		return s.record(ctx, ev, Result{At: time.Now(), Message: err.Error()})
	}

	// Markdown 需要先判定接收端：报文结构与错误码字段都按它决定。
	vendor := ""
	if cfg.Format == FormatMarkdown {
		v, err := VendorOf(target)
		if err != nil {
			return s.record(ctx, ev, Result{At: time.Now(), Message: err.Error()})
		}
		vendor = v
	}
	body, contentType, err := render(cfg.Format, vendor, ev)
	if err != nil {
		return s.record(ctx, ev, Result{At: time.Now(), Message: err.Error()})
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return s.record(ctx, ev, Result{At: time.Now(), Message: "无法构造请求：" + err.Error()})
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "fn-wireguard/"+Source)

	resp, err := s.client.Do(req)
	if err != nil {
		return s.record(ctx, ev, Result{At: time.Now(), Message: "请求失败：" + transportErr(err), Payload: truncate(body)})
	}
	defer resp.Body.Close()
	snippet, _ := io.ReadAll(io.LimitReader(resp.Body, respSnippet))

	res := Result{At: time.Now(), StatusCode: resp.StatusCode, Payload: truncate(body)}
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		res.OK = true
		res.Message = fmt.Sprintf("已送达（HTTP %d）", resp.StatusCode)
	default:
		detail := strings.TrimSpace(string(snippet))
		if detail == "" {
			res.Message = fmt.Sprintf("接收端返回 HTTP %d", resp.StatusCode)
		} else {
			res.Message = fmt.Sprintf("接收端返回 HTTP %d：%s", resp.StatusCode, detail)
		}
	}
	// 群机器人的业务失败藏在 HTTP 200 里，只有解析错误码才看得见。
	if res.OK {
		if e := responseError(snippet, vendor); e != "" {
			res.OK = false
			res.Message = e
		}
	}
	return s.record(ctx, ev, res)
}

// responseError 解析响应体里的业务错误码。
//
// 三家群机器人都用 HTTP 200 + 错误码表达失败（机器人被停用、自定义关键词
// 不匹配、频率超限……）。只看 HTTP 状态码会把这类失败记成「已送达」，
// 用户则在群里等一条永远不会出现的消息。
//
// 字段名必须区分对待：
//   - errcode 是钉钉与企业微信的约定，语义明确，对**所有**格式都检查；
//   - code 是飞书的约定（0 表示成功），但通用 JSON 接收端惯用 code=200 表示成功，
//     一律按「非 0 即失败」会把成功记成失败，因此只在确认是飞书时才检查。
//
// 只解析顶层字段，嵌套结构（例如 {"data":{"errcode":0}}）不会误判。
func responseError(snippet []byte, vendor string) string {
	if code, msg, ok := jsonErrorCode(snippet, "errcode"); ok && code != 0 {
		return formatCodeError(code, msg)
	}
	if vendor == VendorFeishu {
		if code, msg, ok := jsonErrorCode(snippet, "code"); ok && code != 0 {
			return formatCodeError(code, msg)
		}
	}
	return ""
}

// jsonErrorCode 读取响应体顶层的错误码与说明。
func jsonErrorCode(snippet []byte, field string) (int, string, bool) {
	raw := bytes.TrimSpace(snippet)
	if len(raw) == 0 || raw[0] != '{' {
		return 0, "", false
	}
	fields := map[string]json.RawMessage{}
	if err := json.Unmarshal(raw, &fields); err != nil {
		return 0, "", false
	}
	rawCode, ok := fields[field]
	if !ok {
		return 0, "", false
	}
	var code int
	if err := json.Unmarshal(rawCode, &code); err != nil {
		return 0, "", false
	}
	// 失败说明的字段名各家不同：钉钉/企业微信用 errmsg，飞书用 msg。
	for _, k := range []string{"errmsg", "msg", "StatusMessage"} {
		if rawMsg, ok := fields[k]; ok {
			var s string
			if json.Unmarshal(rawMsg, &s) == nil && strings.TrimSpace(s) != "" {
				return code, strings.TrimSpace(s), true
			}
		}
	}
	return code, "", true
}

func formatCodeError(code int, msg string) string {
	if msg == "" {
		msg = "接收端未给出原因"
	}
	return fmt.Sprintf("接收端返回错误码 %d：%s", code, msg)
}

// transportErr 取出不含完整地址的底层错误。
//
// url.Error 的 Error() 会带上完整 URL（含令牌），直接记录等于把凭据写进日志。
func transportErr(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// record 落库最近一次结果，并在失败时留下一条日志（地址已脱敏）。
func (s *Sender) record(ctx context.Context, ev Event, res Result) Result {
	s.mu.Lock()
	if res.OK {
		s.sent++
	} else {
		s.failed++
	}
	s.mu.Unlock()

	if raw, err := json.Marshal(res); err == nil {
		_ = s.st.SetSetting(ctx, SettingLast, string(raw))
	} else {
		s.log.Warn("通知结果序列化失败", "err", err)
	}

	// 日志同步、界面异步：发送失败必须在应用日志里留痕，
	// 否则用户只能看到界面上「最近一次失败」，查不到历史。
	if res.OK {
		s.log.Debug("通知已送达", "kind", ev.Kind, "peer", ev.Peer)
		return res
	}
	msg := fmt.Sprintf("通知发送失败：%s", res.Message)
	s.log.Warn(msg, "kind", ev.Kind, "peer", ev.Peer, "url", MaskURL(LoadConfig(ctx, s.st).URL))
	_ = s.st.AddLog(ctx, "warn", "notify", msg, fmt.Sprintf("事件=%s 对象=%s", ev.Kind, firstNonEmpty(ev.Peer, ev.Iface)))
	return res
}

func loadLast(ctx context.Context, st *store.Store) *Result {
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingLast, ""))
	if raw == "" {
		return nil
	}
	var res Result
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		return nil
	}
	return &res
}

// payload 是 JSON 格式的投递载荷。
type payload struct {
	Event     string `json:"event"`
	Level     string `json:"level"`
	Title     string `json:"title"`
	Message   string `json:"message"`
	Peer      string `json:"peer,omitempty"`
	Interface string `json:"interface,omitempty"`
	Time      string `json:"time"`
	Source    string `json:"source"`
}

// render 生成请求体与内容类型。vendor 只在 Markdown 格式下有意义。
func render(format, vendor string, ev Event) (body []byte, contentType string, err error) {
	switch format {
	case FormatText:
		return []byte(renderText(ev)), "text/plain; charset=utf-8", nil
	case FormatMarkdown:
		b, err := renderMarkdown(vendor, ev)
		return b, "application/json; charset=utf-8", err
	}
	b, err := json.Marshal(payload{
		Event:     ev.Kind,
		Level:     Level(ev.Kind),
		Title:     ev.Title,
		Message:   ev.Body,
		Peer:      ev.Peer,
		Interface: ev.Iface,
		Time:      ev.At.Format(time.RFC3339),
		Source:    Source,
	})
	if err != nil {
		// 载荷字段全是字符串，序列化失败只可能是实现错误；退化为纯文本保证消息能发出去。
		return []byte(renderText(ev)), "text/plain; charset=utf-8", nil
	}
	return b, "application/json; charset=utf-8", nil
}

// renderMarkdown 按接收端的报文结构生成 Markdown 消息。
//
// 三家的结构完全不同，且没有哪一种是「通用」的：
//
//	钉钉     {"msgtype":"markdown","markdown":{"title","text"}}
//	企业微信 {"msgtype":"markdown","markdown":{"content"}}
//	飞书     {"msg_type":"interactive","card":{"header":{...},"elements":[{"tag":"markdown"}]}}
//
// 飞书用交互式卡片而不是纯文本：卡片头部能按级别显示颜色（异常红、正常绿），
// 群里一眼就能分辨「这是需要处理的事」还是「只是状态变化」。
func renderMarkdown(vendor string, ev Event) ([]byte, error) {
	switch vendor {
	case VendorDingtalk:
		// 钉钉把 title 显示在消息卡片顶部，text 是 Markdown 正文。
		return json.Marshal(map[string]any{
			"msgtype": "markdown",
			"markdown": map[string]string{
				"title": clampTitle(ev.Title),
				"text":  markdownText(ev),
			},
		})
	case VendorWeCom:
		// 企业微信的 Markdown 只有 content 一个字段，标题写进正文。
		return json.Marshal(map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]string{"content": markdownText(ev)},
		})
	case VendorFeishu:
		// 飞书：标题在卡片头部（带颜色），正文放在 markdown 元素里，
		// 因此正文不再重复一级标题。
		return json.Marshal(map[string]any{
			"msg_type": "interactive",
			"card": map[string]any{
				"config": map[string]any{"wide_screen_mode": true},
				"header": map[string]any{
					"template": headerColor(ev),
					"title": map[string]string{
						"tag":     "plain_text",
						"content": clampTitle(ev.Title),
					},
				},
				"elements": []map[string]any{
					{"tag": "markdown", "content": markdownBody(ev)},
				},
			},
		})
	}
	return nil, fmt.Errorf("不支持的接收端类型：%s", vendor)
}

// headerColor 返回飞书卡片头部的颜色，按事件级别区分。
// 只有红色与绿色：用户要判断的是「要不要现在处理」，中间色反而增加判断成本。
func headerColor(ev Event) string {
	if Level(ev.Kind) == "warn" {
		return "red"
	}
	return "green"
}

// markdownText 生成带标题的 Markdown 正文（钉钉与企业微信用）。
func markdownText(ev Event) string {
	return "## " + ev.Title + "\n\n" + markdownBody(ev)
}

// markdownBody 生成 Markdown 正文（标题不在这里）。
//
// 用分点而不是一段话：在群里扫一眼就能看到「哪台设备、什么时候、
// 需要做什么」，而纯文本会挤成一坨。
func markdownBody(ev Event) string {
	mark := "通知"
	if Level(ev.Kind) == "warn" {
		mark = "异常"
	}
	var b strings.Builder
	if ev.Body != "" {
		b.WriteString("**" + mark + "**：" + ev.Body + "\n\n")
	}
	lines := []string{
		"**时间**：" + ev.At.Format("2006-01-02 15:04:05"),
	}
	if ev.Peer != "" {
		lines = append(lines, "**设备**："+ev.Peer)
	}
	if ev.Iface != "" {
		lines = append(lines, "**连接**："+ev.Iface)
	}
	b.WriteString(strings.Join(lines, "　|　"))
	b.WriteString("\n\n> 来源：" + Source)
	return b.String()
}

// clampTitle 截断过长的标题。
//
// 钉钉的 markdown.title 有长度上限，超长时消息可能整体被拒；
// 主动截断比让对方报错更好，因为用户几乎不可能猜到原因出在标题长度上。
func clampTitle(title string) string {
	const limit = 60
	runes := []rune(strings.TrimSpace(title))
	if len(runes) <= limit {
		return string(runes)
	}
	return string(runes[:limit]) + "…"
}

func renderText(ev Event) string {
	var b strings.Builder
	b.WriteString(ev.Title)
	if ev.Body != "" {
		b.WriteString("\n")
		b.WriteString(ev.Body)
	}
	if where := where(ev); where != "" {
		b.WriteString("\n")
		b.WriteString(where)
	}
	b.WriteString("\n时间：")
	b.WriteString(ev.At.Format("2006-01-02 15:04:05"))
	return b.String()
}

func where(ev Event) string {
	parts := []string{}
	if ev.Peer != "" {
		parts = append(parts, "设备："+ev.Peer)
	}
	if ev.Iface != "" {
		parts = append(parts, "连接："+ev.Iface)
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "　")
}

func truncate(body []byte) string {
	if len(body) <= payloadTrunc {
		return string(body)
	}
	cut := body[:payloadTrunc]
	// 按字节切开可能切坏多字节字符（中文恰好占了事件内容的大头），
	// 从尾部退到最后一个完整字符的边界：否则排障时看到的是一串乱码，
	// 比不记录内容还难用。
	for len(cut) > 0 {
		r, size := utf8.DecodeLastRune(cut)
		if r != utf8.RuneError || size > 1 {
			break
		}
		cut = cut[:len(cut)-1]
	}
	return string(cut) + "…（已截断）"
}

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return "-"
}
