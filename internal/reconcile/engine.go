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
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
)

// ReconcileInterval 是周期性收敛间隔。
const ReconcileInterval = 10 * time.Second

// SampleInterval 是状态采样间隔。
const SampleInterval = 2 * time.Second

// persistInterval 是历史采样落库间隔。
const persistInterval = 60 * time.Second

type peerSample struct {
	rx int64
	tx int64
	at time.Time
}

// Engine 收敛引擎。
type Engine struct {
	store *store.Store
	back  wgback.Backend
	log   *slog.Logger
	start time.Time

	mu         sync.RWMutex
	status     model.Status
	prev       map[string]peerSample
	lastPers   time.Time
	lastReconc time.Time
	lastErr    error
	lastDiff   []string

	trigger chan struct{}
}

// New 创建引擎。
func New(st *store.Store, back wgback.Backend, logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		store:   st,
		back:    back,
		log:     logger,
		start:   time.Now(),
		prev:    map[string]peerSample{},
		trigger: make(chan struct{}, 1),
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
			Name:       it.Name,
			PrivateKey: it.PrivateKey,
			ListenPort: it.ListenPort,
			FWMark:     it.FWMark,
			MTU:        it.MTU,
			Addresses:  it.Addresses,
			RouteTable: it.RouteTable,
			AllowLAN:   it.AllowLAN,
			Up:         it.Autostart,
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

	e.mu.Lock()
	e.lastReconc = time.Now()
	e.lastErr = err
	e.lastDiff = diff.Actions
	e.mu.Unlock()

	if err != nil {
		e.log.Error("配置收敛失败", "err", err)
		_ = e.store.AddLog(ctx, "error", "reconcile", "配置收敛失败: "+err.Error(), "")
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
	return e.back.Inspect(ctx)
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

	e.mu.Lock()
	prev := e.prev
	next := map[string]peerSample{}
	samples := make([]model.StatSample, 0, 16)
	ifaces, _ := e.store.ListInterfaces(ctx)
	idByName := map[string]int64{}
	for _, it := range ifaces {
		idByName[it.Name] = it.ID
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
	e.prev = next
	e.status = snap
	doPersist := now.Sub(e.lastPers) >= persistInterval
	if doPersist {
		e.lastPers = now
	}
	e.mu.Unlock()

	if doPersist {
		if err := e.store.SaveStatSamples(ctx, samples); err != nil {
			e.log.Warn("统计落库失败", "err", err)
		}
		_ = e.store.PruneStats(ctx, now.Add(-24*time.Hour))
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
		p.Online = !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) < 3*time.Minute
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
			if !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < 3*time.Minute {
				it.PeerOnline++
			}
		}
		it.RxBytes, it.TxBytes = rx, tx
		it.RxRate, it.TxRate = rxRate, txRate
	}
}

// enforceQuota 执行流量配额与到期检查，必要时自动禁用节点。
func (e *Engine) enforceQuota(ctx context.Context) {
	snap := e.Status()
	peers, err := e.store.ListPeers(ctx, 0)
	if err != nil {
		return
	}
	now := time.Now()
	for _, iface := range snap.Interfaces {
		for _, st := range iface.Peers {
			for _, p := range peers {
				if p.InterfaceName != iface.Name || p.PublicKey != st.PublicKey || !p.Enabled {
					continue
				}
				reason := ""
				if p.ExpireAt != nil && now.After(*p.ExpireAt) {
					reason = "已到期"
				} else if p.QuotaRx > 0 && st.RxBytes >= p.QuotaRx {
					reason = fmt.Sprintf("接收流量超过配额 %d 字节", p.QuotaRx)
				} else if p.QuotaTx > 0 && st.TxBytes >= p.QuotaTx {
					reason = fmt.Sprintf("发送流量超过配额 %d 字节", p.QuotaTx)
				}
				if reason == "" {
					continue
				}
				p.Enabled = false
				if err := e.store.UpdatePeer(ctx, &p); err != nil {
					continue
				}
				msg := fmt.Sprintf("节点 %s 已自动禁用：%s", p.Name, reason)
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
			}
		}
	}
}

// Run 启动采样与收敛循环，阻塞直到 ctx 结束。
func (e *Engine) Run(ctx context.Context) {
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
	defer func() {
		sample.Stop()
		reconc.Stop()
		quota.Stop()
		cleanup.Stop()
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
			e.enforceQuota(ctx)
		case <-cleanup.C:
			_ = e.store.PruneLogs(ctx, time.Now().AddDate(0, 0, -14))
			_ = e.store.CleanExpiredSessions(ctx)
		}
	}
}
