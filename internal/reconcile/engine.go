// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package reconcile 是配置收敛引擎：以数据库中的期望态为唯一事实来源，
// 周期性（或按需）把期望态下发到内核，并把内核的实时状态采集回内存缓存。
//
// 幂等性来自两处：
//  1. 期望态完全由数据库推导，不依赖上一轮执行结果；
//  2. 后端 Apply 内部先做差异比较，只下发变化的字段。
//
// 因此进程重启、系统重启后只需跑一轮 Reconcile 即可恢复，无需重放脚本。
package reconcile

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"fnwg/internal/dnsserver"
	"fnwg/internal/model"
	"fnwg/internal/notify"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
)

// ReconcileInterval 是周期性收敛间隔。
const ReconcileInterval = 10 * time.Second

// SampleInterval 是状态采样间隔。
const SampleInterval = 2 * time.Second

// persistInterval 是历史采样落库间隔。
const persistInterval = 60 * time.Second

// BackupPlanCheckInterval 是计划备份的检查间隔。
//
// 5 分钟一查：日程精度是分钟，查得更密没有额外收益；而按小时查会让「每天 03:30」
// 最晚拖到 04:30 才跑——那一刻 NAS 若正好在忙或关机，就可能白等一天。
const BackupPlanCheckInterval = 5 * time.Minute

// BackupPlanRunner 由上层注入（见 SetBackupPlanRunner）：到点则执行一次计划备份。
//
// 用接口而不是直接调用业务层：引擎的方向一直是「只依赖存储与数据面」，
// 让它 import service 会把这条边界拆掉（业务层本来就依赖引擎提供的状态）。
// 返回值刻意用三个原始值，调用方只需要知道「跑没跑、成没成、为什么没成」。
type BackupPlanRunner interface {
	RunIfDue(ctx context.Context, now time.Time) (ran, ok bool, reason string)
	// RunBackupNow 立刻执行一次（界面上点「立即执行一次」），不看日程。
	//
	// 手动执行也放在这里，是因为它**必须由特权代理执行**：写入目标是飞牛授权给应用的目录，
	// 而界面进程（fnwg）对那个目录没有写权限。让界面进程自己写，就会出现「保存时检查通过、
	// 真写文件时被拒」这种自相矛盾的结果 —— 真机上已经这样翻过一次车。
	// 两条路（按日程 / 手动）落在同一个进程、同一个身份上，就不会再各走一套。
	RunBackupNow(ctx context.Context, userID int64, username, srcIP string) (ok bool, file, reason string)
	// InspectBackupDir 检查备份目标目录并列出其中的副本。
	//
	// 「能不能写」必须由本进程（特权代理）回答：目标目录是用户授权给应用的共享文件夹，
	// 界面进程（fnwg）对它没有写权限，问它得到的是它自己的权限，与备份能否成功无关。
	InspectBackupDir(ctx context.Context, dir string) (model.BackupDirInfo, error)
	// ReadBackupCopy 读取目标目录里的一份副本（供界面下载、或用它还原）。
	ReadBackupCopy(ctx context.Context, dir, name string) ([]byte, error)
	// WriteBackupCopy 把一份本地备份另存到目标目录，返回实际写出的文件名。
	//
	// 源按备份 ID 指定，不接受任意路径：这是特权进程，协议层刻意不提供任意路径读写能力。
	WriteBackupCopy(ctx context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error)
}

// Inspector 是配置漂移巡检的执行器（实现见 service.RunInspectIfDue）。
//
// 与计划备份一样用接口：引擎只依赖存储与数据面，不 import 业务层。
// 返回值同样刻意用原始值，引擎只需要知道「跑没跑、正不正常、一句话结论」。
type Inspector interface {
	// RunInspectIfDue 到点则巡检一次。
	RunInspectIfDue(ctx context.Context, now time.Time) (ran, ok bool, reason string)
	// RunInspectNow 立刻巡检一次（界面上点「立即巡检一次」），不看日程。
	//
	// 与按日程那一路落在同一个实现、同一个进程里：巡检的判定只有一份，
	// 不会出现「界面说正常、报告说异常」这种两套口径
	// （计划备份在这一点上连栽两轮，见 ROADMAP）。
	RunInspectNow(ctx context.Context, userID int64, username, srcIP string) (ok bool, errors, warnings int, reason string)
}

type peerSample struct {
	rx int64
	tx int64
	at time.Time
}

// peerPresence 是一次「设备在线状态翻转」的事实，用于触发通知。
type peerPresence struct {
	iface  string
	pubkey string
	online bool
}

// ifacePresence 是一次「连接工作状态翻转」的事实。
type ifacePresence struct {
	iface string
	up    bool
}

// Engine 收敛引擎。
type Engine struct {
	store    *store.Store
	back     wgback.Backend
	log      *slog.Logger
	notifier *notify.Sender
	// dns 是内网域名解析服务：只绑定隧道地址，随每次收敛对齐期望态。
	dns   *dnsserver.Server
	start time.Time

	mu         sync.RWMutex
	status     model.Status
	prev       map[string]peerSample
	online     map[string]bool
	ifaceUp    map[string]bool
	lastPers   time.Time
	lastReconc time.Time
	lastErr    error
	lastDiff   []string
	// dnsOn 记录当前「内网域名解析」开关状态，供状态上报使用。
	dnsOn bool
	// backupPlan 计划备份执行器，由 cmd 层注入；为 nil 时跳过（命令行与测试环境）。
	backupPlan BackupPlanRunner
	// inspector 配置漂移巡检执行器，同样由 cmd 层注入；为 nil 时跳过。
	inspector Inspector

	trigger chan struct{}
}

// RunBackupNow 以特权身份立即执行一次计划备份，返回「成没成、写到哪、为什么没成」。
//
// 界面上的「立即执行一次」走这里：写入目标是用户授权的目录，界面进程没有写权限，
// 而本进程（代理）以 root 运行，不受这个限制。
//
// 执行者信息（谁、从哪来）整份往下传：这次执行要写审计，审计页得能看出是有人手动跑的，
// 而不是系统自己跑了一次。
func (e *Engine) RunBackupNow(ctx context.Context, userID int64, username, srcIP string) (bool, string, string) {
	if e.backupPlan == nil {
		return false, "", errNoBackupRunner.Error()
	}
	return e.backupPlan.RunBackupNow(ctx, userID, username, srcIP)
}

// RunInspectNow 立刻做一次配置漂移巡检。
//
// 界面上点「立即巡检一次」走这里：巡检要读内核里的规则与路由，还要读通知与备份的状态，
// 这些事实都在代理侧；判定也只有一份实现（就在代理进程里），界面进程不自己判一遍。
func (e *Engine) RunInspectNow(ctx context.Context, userID int64, username, srcIP string) (bool, int, int, string) {
	if e.inspector == nil {
		return false, 0, 0, errNoInspector.Error()
	}
	return e.inspector.RunInspectNow(ctx, userID, username, srcIP)
}

// InspectBackupDir 检查备份目标目录并列出其中的副本。
//
// 目标目录的一切读写都由本进程完成（见 BackupPlanRunner 的说明），因此这里的结论
// 可以直接当成事实：能写就是能写。
func (e *Engine) InspectBackupDir(ctx context.Context, dir string) (model.BackupDirInfo, error) {
	if e.backupPlan == nil {
		return model.BackupDirInfo{}, errNoBackupRunner
	}
	return e.backupPlan.InspectBackupDir(ctx, dir)
}

// ReadBackupCopy 读取目标目录里的一份副本。
func (e *Engine) ReadBackupCopy(ctx context.Context, dir, name string) ([]byte, error) {
	if e.backupPlan == nil {
		return nil, errNoBackupRunner
	}
	return e.backupPlan.ReadBackupCopy(ctx, dir, name)
}

// WriteBackupCopy 把一份本地备份另存到目标目录。
func (e *Engine) WriteBackupCopy(ctx context.Context, dir string, backupID int64, userID int64, username, srcIP string) (string, error) {
	if e.backupPlan == nil {
		return "", errNoBackupRunner
	}
	return e.backupPlan.WriteBackupCopy(ctx, dir, backupID, userID, username, srcIP)
}

// errNoBackupRunner 表示引擎里没有注入计划备份执行器（命令行、测试环境）。
var errNoBackupRunner = errors.New("后台服务未启用计划备份（请确认特权代理正在运行）")

// errNoInspector 表示引擎里没有注入巡检执行器（命令行、测试环境）。
var errNoInspector = errors.New("后台服务未启用配置漂移巡检（请确认特权代理正在运行）")

// SetInspector 注入配置漂移巡检执行器。
func (e *Engine) SetInspector(i Inspector) { e.inspector = i }

// SetBackupPlanRunner 注入计划备份执行器。
//
// 由 cmd 层调用：只有那里同时知道「应用自己的数据目录在哪」和「谁来生成备份内容」。
func (e *Engine) SetBackupPlanRunner(r BackupPlanRunner) { e.backupPlan = r }

// New 创建引擎。
func New(st *store.Store, back wgback.Backend, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		store:    st,
		back:     back,
		log:      logger,
		notifier: notify.New(st, logger),
		dns:      dnsserver.New(logger),
		start:    time.Now(),
		prev:     map[string]peerSample{},
		online:   map[string]bool{},
		ifaceUp:  map[string]bool{},
		trigger:  make(chan struct{}, 1),
	}
}

// Trigger 请求立即收敛一次（异步，不阻塞调用方）。
func (e *Engine) Trigger() {
	select {
	case e.trigger <- struct{}{}:
	default:
	}
}

// Desired 从数据库推导出接口期望态。
func (e *Engine) Desired(ctx context.Context) ([]model.InterfaceSpec, error) {
	ifaces, err := e.store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	specs := make([]model.InterfaceSpec, 0, len(ifaces))
	for _, it := range ifaces {
		if !it.Enabled {
			continue
		}
		spec := model.InterfaceSpec{
			Name:         it.Name,
			PrivateKey:   it.PrivateKey,
			ListenPort:   it.ListenPort,
			FWMark:       it.FWMark,
			MTU:          it.MTU,
			Addresses:    it.Addresses,
			RouteTable:   it.RouteTable,
			AllowLAN:     it.AllowLAN,
			IsolatePeers: it.IsolatePeers,
			DNS:          it.DNS,
			Up:           it.Autostart,
		}
		peers, err := e.store.ListPeers(ctx, it.ID)
		if err != nil {
			return nil, err
		}
		for _, p := range peers {
			if !p.Enabled {
				continue
			}
			spec.Peers = append(spec.Peers, model.PeerSpec{
				Name:         p.Name,
				PublicKey:    p.PublicKey,
				PresharedKey: p.PresharedKey,
				Endpoint:     p.EndpointString(),
				AllowedIPs:   p.AllowedIPs,
				Keepalive:    p.Keepalive,
			})
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

// Reconcile 执行一次全量收敛。
func (e *Engine) Reconcile(ctx context.Context) (wgback.Diff, error) {
	specs, err := e.Desired(ctx)
	if err != nil {
		return wgback.Diff{}, err
	}
	diff, err := e.back.Apply(specs, wgback.ApplyOptions{RemoveMissing: true})

	// 内网域名解析跟着收敛走：隧道地址由内核下发，解析服务要先有地址才能绑定，
	// 因此放在 Apply 之后。开关未打开时它会把监听全部关掉。
	e.syncDNS(ctx, specs)

	e.mu.Lock()
	e.lastReconc = time.Now()
	e.lastErr = err
	e.lastDiff = diff.Actions
	e.mu.Unlock()

	if err != nil {
		e.log.Error("配置收敛失败", "err", err)
		_ = e.store.AddLog(ctx, "error", "reconcile", "配置收敛失败: "+err.Error(), "")
		// 配置没写进内核，用户却以为改好了 —— 这类「以为生效了」必须主动说出去。
		// 收敛每 10 秒重试一次，静默窗口（30 分钟）保证持续故障不会刷屏。
		e.notifier.Notify(ctx, notify.Event{
			Kind:  notify.KindApplyFailed,
			Title: "配置下发失败",
			Body: "把配置写入系统时出错：" + err.Error() +
				"。设备可能因此连不上。本应用每 10 秒会自动重试，若持续失败请到「运行记录」查看。",
			At: time.Now(),
		})
		return diff, err
	}
	if len(diff.Actions) > 0 {
		e.log.Info("配置收敛完成", "actions", strings.Join(diff.Actions, "; "))
		_ = e.store.AddLog(ctx, "info", "reconcile", "配置收敛完成", strings.Join(diff.Actions, "; "))
	}
	e.Sample(ctx)
	return diff, nil
}

// DeleteInterface 直接从内核删除接口（数据库记录的清理由调用方负责）。
func (e *Engine) DeleteInterface(ctx context.Context, name string) error {
	if err := e.back.DeleteInterface(name); err != nil {
		return err
	}
	e.log.Info("已删除接口", "name", name)
	return nil
}

// InspectNetwork 网络自检（只读），用于界面展示与排障。
func (e *Engine) InspectNetwork(ctx context.Context) (model.NetworkReport, error) {
	rep, err := e.back.Inspect(ctx)
	e.mu.RLock()
	on := e.dnsOn
	e.mu.RUnlock()
	rep.DNS = e.dns.Status(on)
	return rep, err
}

// syncDNS 让内网域名解析服务与当前期望态一致。
//
// 监听地址只取本应用连接的隧道地址：绝不监听 0.0.0.0:53，
// 因此不会与 NAS 上已有的 DNS 服务抢端口，也不影响系统解析。
func (e *Engine) syncDNS(ctx context.Context, specs []model.InterfaceSpec) {
	enabled := e.store.GetSetting(ctx, model.SettingDNSResolve, "") == "1"
	e.mu.Lock()
	e.dnsOn = enabled
	e.mu.Unlock()
	if !enabled {
		e.dns.Sync(dnsserver.Config{})
		return
	}

	recs, err := e.store.ListDNSRecords(ctx)
	if err != nil {
		e.log.Warn("读取内网域名记录失败", "err", err)
		return
	}

	listen := []string{}
	own := map[string]bool{}
	for _, s := range specs {
		if !s.Up {
			continue
		}
		for _, a := range s.Addresses {
			ip, _, err := net.ParseCIDR(strings.TrimSpace(a))
			if err != nil || ip.To4() == nil {
				continue
			}
			listen = append(listen, net.JoinHostPort(ip.String(), "53"))
			own[ip.String()] = true
		}
	}

	// 上游取连接里配置的 DNS。必须排除自己的隧道地址：
	// 把上游设成自己会形成解析环，查询一进来就自己转自己，直到超时。
	upstreams := []string{}
	seen := map[string]bool{}
	for _, s := range specs {
		for _, d := range s.DNS {
			d = strings.TrimSpace(d)
			host := d
			if h, _, err := net.SplitHostPort(d); err == nil {
				host = h
			}
			if d == "" || own[host] || seen[d] {
				continue
			}
			seen[d] = true
			upstreams = append(upstreams, d)
		}
	}

	records := make([]dnsserver.Record, 0, len(recs))
	for _, r := range recs {
		records = append(records, dnsserver.Record{Name: r.Name, IP: net.ParseIP(r.IP)})
	}
	e.dns.Sync(dnsserver.Config{Listen: listen, Records: records, Upstreams: upstreams})
}

// RepairNetwork 清除本应用残留在系统上的危险路由（自愈）。
func (e *Engine) RepairNetwork(ctx context.Context) ([]string, error) {
	actions, err := e.back.Heal(ctx)
	if err != nil {
		return actions, err
	}
	if len(actions) > 0 {
		e.log.Warn("已修复残留网络设置", "actions", strings.Join(actions, "; "))
		_ = e.store.AddLog(ctx, "warn", "netguard", "已修复残留网络设置", strings.Join(actions, "; "))
		_ = e.store.AddAudit(ctx, &model.AuditEntry{
			Action: "net.repair", TargetType: "system", Username: "system",
			Result: "ok", Message: strings.Join(actions, "; "),
		})
		// 这是唯一涉及「系统网络」的动作，即使自动修好了也应该让用户知道，
		// 否则用户永远不知道自己的 NAS 路由被本应用动过又改回来了。
		e.notifier.Notify(ctx, notify.Event{
			Kind:  notify.KindNetHealed,
			Title: "已自动修复残留网络设置",
			Body: "本应用发现自己此前留下的网络设置仍有残留，已清理：" +
				strings.Join(actions, "; ") + "。系统网络已恢复，无需你手工处理。",
			At: time.Now(),
		})
	}
	return actions, nil
}

// DeleteForeignInterface 删除一个不属于本应用的 WireGuard 网卡（疑似历史残留）。
// 具体的安全校验在数据面后端完成，这里只做转发与审计。
func (e *Engine) DeleteForeignInterface(ctx context.Context, name string) ([]string, error) {
	actions, err := e.back.DeleteForeignInterface(name)
	if err != nil {
		return actions, err
	}
	e.log.Warn("已清理疑似残留的 WireGuard 网卡", "name", name, "actions", strings.Join(actions, "; "))
	_ = e.store.AddLog(ctx, "warn", "netguard", "清理疑似残留网卡 "+name, strings.Join(actions, "; "))
	_ = e.store.AddAudit(ctx, &model.AuditEntry{
		Action: "net.delete_foreign", TargetType: "interface", TargetID: name, Username: "system",
		Result: "ok", Message: strings.Join(actions, "; "),
	})
	return actions, nil
}

// CleanupNetwork 删除本应用创建的全部内核对象（停用与卸载使用）。
func (e *Engine) CleanupNetwork(ctx context.Context) ([]string, error) {
	actions, err := e.back.Cleanup(ctx)
	e.log.Warn("已清理本应用创建的网络对象", "actions", strings.Join(actions, "; "))
	_ = e.store.AddAudit(ctx, &model.AuditEntry{
		Action: "net.cleanup", TargetType: "system", Username: "system",
		Result: "ok", Message: strings.Join(actions, "; "),
	})
	return actions, err
}

// Sample 采集一次实时状态并计算速率。
func (e *Engine) Sample(ctx context.Context) {
	names, err := e.store.InterfaceNames(ctx)
	if err != nil {
		return
	}
	list := make([]string, 0, len(names))
	for n := range names {
		list = append(list, n)
	}
	statuses, err := e.back.Snapshot(list)
	if err != nil {
		e.log.Warn("状态采集失败", "err", err)
		return
	}

	now := time.Now()
	snap := model.Status{Backend: e.back.Kind(), Interfaces: statuses, UpdatedAt: now}

	changes := []peerPresence{}
	ifaceChanges := []ifacePresence{}

	e.mu.Lock()
	prev := e.prev
	next := map[string]peerSample{}
	nextOnline := map[string]bool{}
	samples := make([]model.StatSample, 0, 16)
	ifaces, _ := e.store.ListInterfaces(ctx)
	idByName := map[string]int64{}
	shouldWork := map[string]bool{}
	for _, it := range ifaces {
		idByName[it.Name] = it.ID
		// 「本应处于工作状态」= 已启用且开机自动启用：与界面上
		// 「已启用但没工作」的判定口径一致，避免两处说法打架。
		shouldWork[it.Name] = it.Enabled && it.Autostart
	}
	upNow := map[string]bool{}
	for i := range snap.Interfaces {
		upNow[snap.Interfaces[i].Name] = snap.Interfaces[i].Up
	}
	for i := range snap.Interfaces {
		iface := &snap.Interfaces[i]
		for j := range iface.Peers {
			p := &iface.Peers[j]
			key := iface.Name + "|" + p.PublicKey
			cur := peerSample{rx: p.RxBytes, tx: p.TxBytes, at: now}
			if old, ok := prev[key]; ok && now.After(old.at) {
				dt := now.Sub(old.at).Seconds()
				if rx := p.RxBytes - old.rx; rx >= 0 {
					p.RxRate = float64(rx) / dt
				}
				if tx := p.TxBytes - old.tx; tx >= 0 {
					p.TxRate = float64(tx) / dt
				}
			}
			next[key] = cur
			// 上下线迁移检测：只有「已知状态发生翻转」才算事件。
			// 未知（应用刚起、设备刚建）不算——否则每次重启都会给用户发一轮「设备上线」。
			online := peerOnline(p.LastHandshake, now)
			if wasOnline, known := e.online[key]; known && wasOnline != online {
				changes = append(changes, peerPresence{iface: iface.Name, pubkey: p.PublicKey, online: online})
			}
			nextOnline[key] = online
			if id, ok := idByName[iface.Name]; ok {
				samples = append(samples, model.StatSample{
					InterfaceID:   id,
					InterfaceName: iface.Name,
					PeerPublicKey: p.PublicKey,
					Ts:            now,
					RxBytes:       p.RxBytes,
					TxBytes:       p.TxBytes,
				})
			}
		}
	}
	// 连接级上下线迁移：与设备用同一套「只在已知状态翻转时才报」的规则。
	//
	// 这里按「应工作的连接」遍历，而不是按快照遍历：网卡被其它工具删掉时它会从
	// 快照里彻底消失，只看快照就完全发现不了 —— 而那正是最需要告诉用户的情况。
	nextIfaceUp := map[string]bool{}
	for name, should := range shouldWork {
		if !should {
			continue
		}
		up := upNow[name]
		if was, known := e.ifaceUp[name]; known && was != up {
			ifaceChanges = append(ifaceChanges, ifacePresence{iface: name, up: up})
		}
		nextIfaceUp[name] = up
	}

	e.prev = next
	e.online = nextOnline
	e.ifaceUp = nextIfaceUp
	e.status = snap
	doPersist := now.Sub(e.lastPers) >= persistInterval
	if doPersist {
		e.lastPers = now
	}
	e.mu.Unlock()

	// 通知在锁外投递：Notify 只是入队（不碰网络），但仍不该拿锁去调用外部组件。
	if len(changes) > 0 {
		e.notifyPresence(ctx, changes, now)
	}
	if len(ifaceChanges) > 0 {
		e.notifyInterface(ctx, ifaceChanges, now)
	}

	if doPersist {
		if err := e.store.SaveStatSamples(ctx, samples); err != nil {
			e.log.Warn("统计落库失败", "err", err)
		}
		_ = e.store.PruneStats(ctx, now.Add(-24*time.Hour))
	}
}

// peerOnline 按统一的时间窗判定设备是否在线。
func peerOnline(lastHandshake, now time.Time) bool {
	return !lastHandshake.IsZero() && now.Sub(lastHandshake) < model.OnlineWindow
}

// notifyPresence 把设备上下线迁移推送给通知地址。
func (e *Engine) notifyPresence(ctx context.Context, changes []peerPresence, now time.Time) {
	peers, err := e.store.ListPeers(ctx, 0)
	if err != nil {
		return
	}
	byKey := map[string]model.Peer{}
	for _, p := range peers {
		byKey[p.InterfaceName+"|"+p.PublicKey] = p
	}
	endpoints := map[string]string{}
	for _, iface := range e.Status().Interfaces {
		for _, st := range iface.Peers {
			endpoints[iface.Name+"|"+st.PublicKey] = st.Endpoint
		}
	}
	window := fmt.Sprintf("%d 分钟", int(model.OnlineWindow.Minutes()))
	for _, c := range changes {
		key := c.iface + "|" + c.pubkey
		p, ok := byKey[key]
		if !ok {
			continue // 设备已被删除，不再打扰用户
		}
		name := p.Name
		if name == "" {
			name = "未命名设备"
		}
		ev := notify.Event{Peer: name, Iface: c.iface, At: now}
		if c.online {
			ev.Kind = notify.KindOnline
			ev.Title = fmt.Sprintf("设备「%s」已上线", name)
			ev.Body = fmt.Sprintf("连接：%s。%s", c.iface, endpointHint(endpoints[key]))
		} else {
			ev.Kind = notify.KindOffline
			ev.Title = fmt.Sprintf("设备「%s」已离线", name)
			ev.Body = fmt.Sprintf("连接：%s。已连续 %s 没有握手，可能是设备关机、切换网络或断开连接。", c.iface, window)
		}
		e.notifier.Notify(ctx, ev)
	}
}

// endpointHint 生成「来源地址」提示；没有来源地址时给一句更实用的替代信息。
func endpointHint(endpoint string) string {
	if endpoint == "" {
		return "本机已能看到它的握手，但暂时读不到来源地址。"
	}
	return "来源地址：" + endpoint + "。"
}

// notifyInterface 把连接中断/恢复推送给通知地址。
//
// 为什么值得单独通知：连接掉线时界面上的红点只有主动打开界面才看得到，
// 而用户往往是在「要连回家却连不上」的那一刻才发现 —— 那时已经晚了。
func (e *Engine) notifyInterface(ctx context.Context, changes []ifacePresence, now time.Time) {
	for _, c := range changes {
		ev := notify.Event{Iface: c.iface, At: now}
		if c.up {
			ev.Kind = notify.KindIfaceUp
			ev.Title = fmt.Sprintf("连接「%s」已恢复", c.iface)
			ev.Body = "这条连接已重新工作，设备可以正常连接了。"
		} else {
			ev.Kind = notify.KindIfaceDown
			ev.Title = fmt.Sprintf("连接「%s」已中断", c.iface)
			ev.Body = "这条连接本应处于工作状态（已启用且开机自动启用），但当前没有工作，设备将无法连接。" +
				"可到「系统维护」点一键修复，或到「我的连接」点「立即应用」重新下发配置。"
		}
		e.notifier.Notify(ctx, ev)
	}
}

// Status 返回最近一次状态快照。
func (e *Engine) Status() model.Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.status
}

// Health 返回健康度。
func (e *Engine) Health(ctx context.Context) model.Health {
	caps := e.back.Caps()
	e.mu.RLock()
	lastErr := e.lastErr
	e.mu.RUnlock()
	h := model.Health{
		AgentUp:      true,
		Backend:      caps.Backend,
		KernelModule: caps.KernelModule,
		TunDevice:    caps.TunDevice,
		UptimeSec:    int64(time.Since(e.start).Seconds()),
	}
	if lastErr != nil {
		h.Error = lastErr.Error()
	}
	return h
}

// LastReconcile 返回最近一次收敛信息。
func (e *Engine) LastReconcile() (time.Time, []string, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.lastReconc, e.lastDiff, e.lastErr
}

// EnrichPeers 用实时状态补充节点的运行期字段。
func (e *Engine) EnrichPeers(peers []model.Peer) {
	snap := e.Status()
	idx := map[string]model.PeerStatus{}
	for _, iface := range snap.Interfaces {
		for _, p := range iface.Peers {
			idx[iface.Name+"|"+p.PublicKey] = p
		}
	}
	now := time.Now()
	for i := range peers {
		p := &peers[i]
		st, ok := idx[p.InterfaceName+"|"+p.PublicKey]
		if !ok {
			continue
		}
		p.RxBytes = st.RxBytes
		p.TxBytes = st.TxBytes
		p.RxRate = st.RxRate
		p.TxRate = st.TxRate
		p.LastHandshake = st.LastHandshake
		p.Endpoint = st.Endpoint
		p.Online = peerOnline(st.LastHandshake, now)
	}
}

// EnrichInterfaces 用实时状态补充接口的运行期字段。
func (e *Engine) EnrichInterfaces(ifaces []model.Interface) {
	snap := e.Status()
	idx := map[string]model.InterfaceStatus{}
	for _, s := range snap.Interfaces {
		idx[s.Name] = s
	}
	for i := range ifaces {
		it := &ifaces[i]
		st, ok := idx[it.Name]
		if !ok {
			continue
		}
		it.Up = st.Up
		it.PublicKey = st.PublicKey
		it.Backend = snap.Backend
		it.PeerCount = len(st.Peers)
		var rx, tx int64
		var rxRate, txRate float64
		for _, p := range st.Peers {
			rx += p.RxBytes
			tx += p.TxBytes
			rxRate += p.RxRate
			txRate += p.TxRate
			if peerOnline(p.LastHandshake, time.Now()) {
				it.PeerOnline++
			}
		}
		it.RxBytes, it.TxBytes = rx, tx
		it.RxRate, it.TxRate = rxRate, txRate
	}
}

// EnforceQuota 执行流量配额与到期检查：该停用的停用，条件解除的自动恢复。
//
// 额度按**自然月**计算，依据是落盘的流量聚合（见 internal/traffic）。早先的口径是
// 「从设备创建起累计」，而用户填 50GB 时想的是「每月 50GB」；更要紧的是内核的累计计数
// 会在接口重建（重启、重新下发配置）后归零，于是额度会在重启之后悄悄失效 ——
// 用户以为它已经被挡住了，实际上又能继续用。
//
// 「月初自动恢复」是这套口径的另一半：只停用不恢复，用户每个月都要手工点一次启用。
// 而恢复的前提是分辨得出「当初是谁停用的」，所以自动停用会写下原因（DisabledReason）——
// 管理员手工停用的设备（原因为空）永远不会被自动放开。
func (e *Engine) EnforceQuota(ctx context.Context) {
	peers, err := e.store.ListPeers(ctx, 0)
	if err != nil {
		return
	}
	now := time.Now()
	// 本自然月的起点（本地时区）：额度问的就是「这个月用超了没有」。
	monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
	used, err := e.store.TrafficTotalsSince(ctx, monthStart)
	if err != nil {
		// 读不到用量时什么都不做：停用设备是破坏性动作，不能基于「没有数据」下判断。
		return
	}

	for i := range peers {
		p := peers[i]
		dec, reason, detail := DecideQuota(p, used[p.ID], now)
		switch dec {
		case QuotaDisable:
			p.Enabled, p.DisabledReason = false, reason
			if err := e.store.UpdatePeer(ctx, &p); err != nil {
				continue
			}
			e.peerAutoDisabled(ctx, p, reason, detail, now)
		case QuotaRestore:
			p.Enabled, p.DisabledReason = true, ""
			if err := e.store.UpdatePeer(ctx, &p); err != nil {
				continue
			}
			e.peerAutoRestored(ctx, p)
		}
	}
}

// QuotaDecision 是额度/期限检查的结论。
type QuotaDecision int

const (
	// QuotaKeep 保持现状。
	QuotaKeep QuotaDecision = iota
	// QuotaDisable 需要自动停用。
	QuotaDisable
	// QuotaRestore 停用条件已解除，需要自动恢复。
	QuotaRestore
)

// DecideQuota 判定某台设备当前该怎么处理，是纯函数：不读库、不改状态、不依赖当前时间以外的东西。
//
// 之所以独立出来：这段判定会**改动用户的设备状态**（停用一台设备等于把它踢下线），
// 而分支不少 —— 到期、收/发两个方向的额度、自动停用后的恢复、以及「管理员手工停用的绝不能自动放开」。
// 纯函数才能把这些分支逐条穷举，而不是等到真机上某台设备莫名其妙被放开了才发现。
//
// usage 传的是该设备**本自然月**的累计用量；停用的具体原因写进 DisabledReason，
// 因为那个原因决定了条件解除后能不能自动恢复。
func DecideQuota(p model.Peer, usage store.TrafficTotal, now time.Time) (QuotaDecision, string, string) {
	reason, detail := "", ""
	switch {
	case p.ExpireAt != nil && now.After(*p.ExpireAt):
		reason = model.PeerDisabledExpired
		detail = "已到期 " + p.ExpireAt.Local().Format("2006-01-02 15:04")
	case p.QuotaTx > 0 && usage.TxBytes >= p.QuotaTx:
		reason = model.PeerDisabledQuota
		detail = fmt.Sprintf("本月发送 %s，已达上限 %s", humanBytes(usage.TxBytes), humanBytes(p.QuotaTx))
	case p.QuotaRx > 0 && usage.RxBytes >= p.QuotaRx:
		reason = model.PeerDisabledQuota
		detail = fmt.Sprintf("本月接收 %s，已达上限 %s", humanBytes(usage.RxBytes), humanBytes(p.QuotaRx))
	}

	switch {
	case p.Enabled && reason != "":
		return QuotaDisable, reason, detail
	case !p.Enabled && p.DisabledReason != "" && reason == "":
		// 条件已解除：到了新的一月，或管理员提高了额度、延长了期限。
		// 只恢复「当初是自动停用」的设备 —— 管理员手工停用的 DisabledReason 为空，绝不自动放开。
		return QuotaRestore, "", ""
	}
	return QuotaKeep, "", ""
}

// peerAutoDisabled 记录并通知一次自动停用。
//
// 到期与流量用尽必须主动通知：设备被停用后，界面上看到的只是「离线」，
// 不通知的话用户会去检查自己的网络，而真正的原因在配额与期限设置里。
func (e *Engine) peerAutoDisabled(ctx context.Context, p model.Peer, reason, detail string, now time.Time) {
	name := p.Name
	if name == "" {
		name = "未命名设备"
	}
	msg := fmt.Sprintf("设备 %s 已自动停用：%s", name, detail)
	e.log.Warn(msg)
	_ = e.store.AddLog(ctx, "warn", "quota", msg, "")
	_ = e.store.AddAudit(ctx, &model.AuditEntry{
		Action:     "peer.auto_disable",
		TargetType: "peer",
		TargetID:   fmt.Sprint(p.ID),
		Username:   "system",
		Result:     "ok",
		Message:    msg,
	})

	kind, title, hint := notify.KindQuota,
		fmt.Sprintf("设备「%s」本月流量用尽，已自动停用", name),
		"下个自然月会按当月用量自动恢复；如需立刻继续使用，可在设备设置里提高流量额度后重新启用。"
	if reason == model.PeerDisabledExpired {
		kind, title, hint = notify.KindExpired,
			fmt.Sprintf("设备「%s」已到期，已自动停用", name),
			"如需继续使用，请在设备设置里延长到期时间后重新启用。"
	}
	e.notifier.Notify(ctx, notify.Event{
		Kind:  kind,
		Title: title,
		Body:  fmt.Sprintf("自动停用原因：%s。%s", detail, hint),
		Peer:  name,
		Iface: p.InterfaceName,
		At:    now,
	})
}

// peerAutoRestored 记录一次自动恢复。
//
// 刻意不发通知：设备恢复后会照常握手上线，那时既有的「设备上线」事件本身就会通知用户；
// 再加一条「已恢复」只会在群里多刷一条重复消息。
func (e *Engine) peerAutoRestored(ctx context.Context, p model.Peer) {
	name := p.Name
	if name == "" {
		name = "未命名设备"
	}
	msg := fmt.Sprintf("设备 %s 的停用条件已解除，已自动恢复启用", name)
	e.log.Info(msg)
	_ = e.store.AddLog(ctx, "info", "quota", msg, "")
	_ = e.store.AddAudit(ctx, &model.AuditEntry{
		Action:     "peer.auto_enable",
		TargetType: "peer",
		TargetID:   fmt.Sprint(p.ID),
		Username:   "system",
		Result:     "ok",
		Message:    msg,
	})
}

// humanBytes 把字节数写成日志与通知里能一眼看懂的形式。
//
// 只用在给用户看的文字里（日志、Webhook 正文）；接口返回的仍是原始字节数，
// 由前端按自己的习惯格式化 —— 服务端不该替界面决定显示成 MB 还是 GiB。
func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d %s", n, units[0])
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}

// Run 启动采样与收敛循环，阻塞直到 ctx 结束。
func (e *Engine) Run(ctx context.Context) {
	// 通知投递走独立协程：Webhook 目标超时最长 3 秒，
	// 若与收敛共用协程，一次超时就会让设备状态滞后一整轮。
	go e.notifier.Start(ctx)

	// 启动第一件事：先修复可能残留的危险网络设置（保证升级/重装不会影响 NAS 网络），
	// 然后再做一次全量收敛实现重启自恢复。
	if _, err := e.RepairNetwork(ctx); err != nil {
		e.log.Warn("启动自检修复失败", "err", err)
	}
	if _, err := e.Reconcile(ctx); err != nil {
		e.log.Error("启动初始化收敛失败", "err", err)
	}

	sample := time.NewTicker(SampleInterval)
	reconc := time.NewTicker(ReconcileInterval)
	quota := time.NewTicker(30 * time.Second)
	cleanup := time.NewTicker(time.Hour)
	// 同一根 ticker 驱动两个「按日程到点」的任务：计划备份与配置漂移巡检。
	// 它们都只判断「到点没有」，5 分钟的检查间隔对准时性没有影响。
	scheduled := time.NewTicker(BackupPlanCheckInterval)
	defer func() {
		sample.Stop()
		reconc.Stop()
		quota.Stop()
		cleanup.Stop()
		scheduled.Stop()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-sample.C:
			e.Sample(ctx)
		case <-reconc.C:
			if _, err := e.Reconcile(ctx); err != nil {
				e.log.Warn("周期收敛失败", "err", err)
			}
		case <-e.trigger:
			if _, err := e.Reconcile(ctx); err != nil {
				e.log.Warn("触发收敛失败", "err", err)
			}
		case <-quota.C:
			e.EnforceQuota(ctx)
		case <-cleanup.C:
			_ = e.store.PruneLogs(ctx, time.Now().AddDate(0, 0, -14))
			_ = e.store.CleanExpiredSessions(ctx)
		case <-scheduled.C:
			e.runBackupPlan(ctx)
			e.runInspect(ctx)
		}
	}
}

// runBackupPlan 到点执行一次计划备份，失败时推送通知。
//
// 通知放在引擎侧发：通知队列只在代理进程里启动（见 service 的说明），
// 而计划备份可能与界面同进程、也可能不在——交给「持有已启动队列」的一方发最可靠。
func (e *Engine) runBackupPlan(ctx context.Context) {
	if e.backupPlan == nil {
		return
	}
	ran, ok, reason := e.backupPlan.RunIfDue(ctx, time.Now())
	if !ran {
		return
	}
	if ok {
		e.log.Info("计划备份已完成")
		return
	}
	e.log.Warn("计划备份失败", "err", reason)
	e.notifier.Notify(ctx, notify.Event{
		Kind:  notify.KindBackupFailed,
		Title: "计划备份失败",
		Body: "这次没能把备份写到目标目录：" + reason +
			"。修好之后可在「系统设置 → 备份还原 → 计划备份」里点「立即执行一次」补上。",
		At: time.Now(),
	})
}

// runInspect 到点做一次配置漂移巡检，发现了需要处理的问题时推送通知。
//
// 通知放在引擎侧发：通知队列只在代理进程里启动，而巡检也跑在那里。
// 只推错误级结论（警告不推）：警告项往往长期存在（例如「疑似残留网卡」），
// 每天推一条同样的提醒，用户很快就会把整个渠道屏蔽掉 —— 那比不推更糟。
func (e *Engine) runInspect(ctx context.Context) {
	if e.inspector == nil {
		return
	}
	ran, ok, reason := e.inspector.RunInspectIfDue(ctx, time.Now())
	if !ran {
		return
	}
	if ok {
		e.log.Info("巡检完成", "结论", reason)
		return
	}
	e.log.Warn("巡检发现需要处理的问题", "结论", reason)
	e.notifier.Notify(ctx, notify.Event{
		Kind:  notify.KindInspectProblem,
		Title: "配置漂移巡检发现需要处理的问题",
		Body:  reason + "。详见「系统维护 → 配置漂移巡检」里的最近一次报告。",
		At:    time.Now(),
	})
}
