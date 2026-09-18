// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package service 承载业务编排：参数校验、审计留痕、触发特权代理收敛。
package service

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"fnwg/internal/agentapi"
	"fnwg/internal/model"
	"fnwg/internal/notify"
	"fnwg/internal/store"
)

// Actor 描述一次操作的发起者，用于审计。
type Actor struct {
	UserID   int64
	Username string
	SrcIP    string
}

var (
	ifaceNameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{1,14}$`)
)

// Service 业务服务。
type Service struct {
	Store   *store.Store
	Core    agentapi.Core
	Cache   *StatusCache
	Log     *slog.Logger
	Version string
	// notifier 只用于读取通知状态与发送测试消息。
	// 真正的事件投递在代理进程的收敛引擎里（那里才知道设备上下线），
	// Web 进程不启动队列，避免同一事件被两个进程各发一遍。
	notifier *notify.Sender

	// snapshotDir 是配置快照的落盘目录（见 SetSnapshotDir）。
	// 未设置时自动留档静默跳过，命令行与测试环境因此不受影响。
	snapshotDir string
	// snapMu 串行化快照生成：并发改动配置时避免文件名相撞与重复留档。
	snapMu sync.Mutex
}

// New 创建服务。
func New(st *store.Store, core agentapi.Core, logger *slog.Logger, version string) *Service {
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		Store:    st,
		Core:     core,
		Cache:    NewStatusCache(core, logger),
		Log:      logger,
		Version:  version,
		notifier: notify.New(st, logger),
	}
}

// ---------------------------------------------------------------- 状态缓存

// StatusCache 周期从特权代理拉取实时状态并提供富化能力。
// Web 进程本身不接触内核，所有状态都来自代理，保持权限边界清晰。
type StatusCache struct {
	core agentapi.Core
	log  *slog.Logger

	mu     sync.RWMutex
	status model.Status
	err    error
}

// NewStatusCache 创建缓存。
func NewStatusCache(core agentapi.Core, logger *slog.Logger) *StatusCache {
	return &StatusCache{core: core, log: logger}
}

// Refresh 拉取一次状态。
func (c *StatusCache) Refresh(ctx context.Context) error {
	st, err := c.core.Status(ctx)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
	if err == nil {
		c.status = st
	}
	return err
}

// Get 返回最近一次状态快照。
//
// 注意：首次采集完成前缓存是零值，切片字段为 nil，JSON 会序列化成 null，
// 前端对 null 做遍历/归约会直接抛错导致页面空白，因此统一归一化为空数组。
func (c *StatusCache) Get() model.Status {
	c.mu.RLock()
	defer c.mu.RUnlock()
	st := c.status
	if st.Interfaces == nil {
		st.Interfaces = []model.InterfaceStatus{}
	}
	for i := range st.Interfaces {
		if st.Interfaces[i].Peers == nil {
			st.Interfaces[i].Peers = []model.PeerStatus{}
		}
		if st.Interfaces[i].Addresses == nil {
			st.Interfaces[i].Addresses = []string{}
		}
		for j := range st.Interfaces[i].Peers {
			if st.Interfaces[i].Peers[j].AllowedIPs == nil {
				st.Interfaces[i].Peers[j].AllowedIPs = []string{}
			}
		}
	}
	return st
}

// Err 返回最近一次采集错误。
func (c *StatusCache) Err() error {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.err
}

// Run 周期性刷新。
func (c *StatusCache) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	_ = c.Refresh(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(ctx); err != nil {
				c.log.Debug("刷新状态失败", "err", err)
			}
		}
	}
}

// EnrichPeers 用实时状态补充节点运行期字段。
func (c *StatusCache) EnrichPeers(peers []model.Peer) {
	snap := c.Get()
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
		p.RxBytes, p.TxBytes = st.RxBytes, st.TxBytes
		p.RxRate, p.TxRate = st.RxRate, st.TxRate
		p.LastHandshake = st.LastHandshake
		p.Endpoint = st.Endpoint
		p.Online = !st.LastHandshake.IsZero() && now.Sub(st.LastHandshake) < 3*time.Minute
	}
}

// EnrichInterfaces 用实时状态补充接口运行期字段。
func (c *StatusCache) EnrichInterfaces(ifaces []model.Interface) {
	snap := c.Get()
	idx := map[string]model.InterfaceStatus{}
	for _, s := range snap.Interfaces {
		idx[s.Name] = s
	}
	for i := range ifaces {
		it := &ifaces[i]
		it.Backend = snap.Backend
		st, ok := idx[it.Name]
		if !ok {
			continue
		}
		it.Up = st.Up
		it.PublicKey = st.PublicKey
		it.PeerCount = len(st.Peers)
		for _, p := range st.Peers {
			it.RxBytes += p.RxBytes
			it.TxBytes += p.TxBytes
			it.RxRate += p.RxRate
			it.TxRate += p.TxRate
			if !p.LastHandshake.IsZero() && time.Since(p.LastHandshake) < 3*time.Minute {
				it.PeerOnline++
			}
		}
	}
}

// ---------------------------------------------------------------- 通用工具

// audit 写入审计记录，失败仅记录日志不影响主流程。
func (s *Service) audit(ctx context.Context, a Actor, action, targetType, targetID, before, after, result, msg string) {
	if err := s.Store.AddAudit(ctx, &model.AuditEntry{
		UserID:     a.UserID,
		Username:   a.Username,
		SrcIP:      a.SrcIP,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		Before:     before,
		After:      after,
		Result:     result,
		Message:    msg,
	}); err != nil {
		s.Log.Warn("写入审计失败", "err", err)
	}
}

// reconcile 触发一次异步收敛（数据库已变更时调用）。
func (s *Service) reconcile(ctx context.Context) error {
	actions, err := s.Core.Reconcile(ctx)
	if err != nil {
		_ = s.Store.AddLog(ctx, "error", "apply", "配置下发失败: "+err.Error(), "")
		return err
	}
	if len(actions) > 0 {
		s.Log.Info("配置已下发", "actions", strings.Join(actions, "; "))
		_ = s.Store.AddLog(ctx, "info", "apply", "配置已下发", strings.Join(actions, "; "))
	}
	_ = s.Cache.Refresh(ctx)
	return nil
}

// ReconcileNow 供 API 手动触发。
func (s *Service) ReconcileNow(ctx context.Context) ([]string, error) {
	actions, err := s.Core.Reconcile(ctx)
	_ = s.Cache.Refresh(ctx)
	return actions, err
}

func validCIDR(v string) bool {
	_, _, err := net.ParseCIDR(v)
	return err == nil
}

func validateCIDRList(field string, list []string) error {
	for _, v := range list {
		if !validCIDR(v) {
			return fmt.Errorf("%s「%s」格式不对，请按“地址/子网位数”的写法填写，例如 10.10.0.1/24", field, v)
		}
	}
	return nil
}

func validateIPList(field string, list []string) error {
	for _, v := range list {
		if net.ParseIP(v) == nil {
			return fmt.Errorf("%s「%s」不是一个有效的地址，例如应填写 223.5.5.5", field, v)
		}
	}
	return nil
}

func validatePort(p int) error {
	if p < 0 || p > 65535 {
		return errors.New("端口号需要在 0 到 65535 之间")
	}
	return nil
}

// Health 汇总代理与内核能力。
func (s *Service) Health(ctx context.Context) model.Health {
	h, err := s.Core.Health(ctx)
	if err != nil {
		h.AgentUp = false
		if h.Error == "" {
			h.Error = err.Error()
		}
	}
	h.AgentVersion = s.Version
	if h.Backend == "" {
		h.Backend = s.Cache.Get().Backend
	}
	return h
}
