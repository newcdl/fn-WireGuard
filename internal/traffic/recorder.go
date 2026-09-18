// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package traffic 把内核里的累计计数采集为「按小时增量」，供流量报表与每月额度使用。
//
// 为什么单独成包：它只依赖「状态快照 + 存储」，与收敛引擎、HTTP 层都无关。
// 这样生产环境（agent）与开发模式（web）可以各自起一个，测试也能直接驱动 Sample()
// —— 挂在计时器里的逻辑如果不能单步执行，就只能靠等一分钟来验证。
package traffic

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/store"
)

// 采样与保留的默认值。
const (
	// DefaultInterval 是聚合采样间隔。取一分钟：既足够让「本月用量」及时反映，
	// 又不会让写盘次数与收敛循环（10 秒一次）绑在一起。
	DefaultInterval = time.Minute
	// rawEvery 控制「每几次聚合采样写一条原始快照」，默认 5 次即 5 分钟。
	// 原始快照供近期曲线用，粒度比聚合细，但只保留几天。
	defaultRawEvery = 5
	defaultRawKeep  = 7 * 24 * time.Hour
	// defaultRetention 是聚合数据的保留时长，可由设置项 traffic_retention_days 覆盖。
	defaultRetention = 90 * 24 * time.Hour
	// SettingRetentionDays 是保留天数的设置键。
	SettingRetentionDays = "traffic_retention_days"
	// 保留天数的合理区间：太短会让报表失去意义，太长则失去「自动清理」的意义。
	MinRetentionDays = 7
	MaxRetentionDays = 3650
)

type counters struct{ rx, tx int64 }

// Recorder 周期性把「每台设备的累计计数」折算成增量并落库。
type Recorder struct {
	store  *store.Store
	status func() model.Status
	log    *slog.Logger

	interval  time.Duration
	rawEvery  int
	rawKeep   time.Duration
	retention time.Duration

	// base 是上一次看到的累计计数，按「连接名 + 设备公钥」索引。
	//
	// 进程刚启动时它是空的，于是第一轮采样只记基线不记账 —— 否则会把
	// 「从 0 到当前累计」这一整段算进当前小时，报表上会出现一根凭空的巨柱。
	base      map[string]counters
	ticks     int
	lastPrune time.Time
}

// New 创建采样器。status 传「能拿到最新内核状态」的函数（通常是 engine.Status）。
func New(st *store.Store, status func() model.Status, log *slog.Logger) *Recorder {
	return &Recorder{
		store:     st,
		status:    status,
		log:       log,
		interval:  DefaultInterval,
		rawEvery:  defaultRawEvery,
		rawKeep:   defaultRawKeep,
		retention: defaultRetention,
		base:      map[string]counters{},
	}
}

// Start 起一个随 ctx 结束的采样循环。调用方只应调用一次。
func (r *Recorder) Start(ctx context.Context) {
	go func() {
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if err := r.Sample(ctx); err != nil {
					r.log.Warn("流量采样失败", "err", err)
				}
			}
		}
	}()
}

// Sample 采一轮：把每台设备的增量记到当前小时，按需写原始快照，并定期清理过期数据。
//
// 导出它是为了可测：时间驱动的循环里做的事必须能单步验证。
func (r *Recorder) Sample(ctx context.Context) error {
	snap := r.status()
	peers, err := r.store.ListPeers(ctx, 0)
	if err != nil {
		return err
	}
	byKey := make(map[string]*model.Peer, len(peers))
	for i := range peers {
		byKey[peerKey(peers[i].InterfaceName, peers[i].PublicKey)] = &peers[i]
	}

	now := time.Now()
	hour := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
	r.ticks++
	writeRaw := r.rawEvery > 0 && (r.ticks == 1 || r.ticks%r.rawEvery == 0)
	raw := make([]model.StatSample, 0, len(peers))

	for _, iface := range snap.Interfaces {
		for _, ps := range iface.Peers {
			k := peerKey(iface.Name, ps.PublicKey)
			cur := counters{rx: ps.RxBytes, tx: ps.TxBytes}
			prev, seen := r.base[k]
			r.base[k] = cur

			p := byKey[k]
			if p == nil {
				// 状态里有、库里没有：设备刚建好还没落库或刚被删掉，跳过。
				continue
			}
			if writeRaw {
				raw = append(raw, model.StatSample{
					InterfaceID:   p.InterfaceID,
					PeerPublicKey: ps.PublicKey, Ts: now,
					RxBytes: cur.rx, TxBytes: cur.tx,
				})
			}
			if !seen {
				continue // 第一轮只记基线
			}
			rx, tx := cur.rx-prev.rx, cur.tx-prev.tx
			if rx < 0 || tx < 0 {
				// 累计计数变小 = 接口被重建（重启、重新下发配置）或计数回绕。
				// 这一段增量已无从得知，宁可少记，也不把负数写进报表。
				continue
			}
			if err := r.store.AddTrafficDelta(ctx, p.ID, p.InterfaceID, hour, rx, tx); err != nil {
				return err
			}
		}
	}

	if len(raw) > 0 {
		if err := r.store.SaveStatSamples(ctx, raw); err != nil {
			return err
		}
		if err := r.store.PruneStats(ctx, now.Add(-r.rawKeep)); err != nil {
			return err
		}
	}
	return r.prune(ctx, now)
}

// Retention 返回聚合数据的保留时长：优先取设置项，非法或缺失时用默认值。
func (r *Recorder) Retention(ctx context.Context) time.Duration {
	raw := r.store.GetSetting(ctx, SettingRetentionDays, "")
	days, err := strconv.Atoi(raw)
	if err != nil || days < MinRetentionDays || days > MaxRetentionDays {
		return r.retention
	}
	return time.Duration(days) * 24 * time.Hour
}

// prune 清理过期的小时记录，最多每天做一次（清理是整表扫描，没必要每轮都做）。
func (r *Recorder) prune(ctx context.Context, now time.Time) error {
	if !r.lastPrune.IsZero() && now.Sub(r.lastPrune) < 24*time.Hour {
		return nil
	}
	r.lastPrune = now
	keep := r.Retention(ctx)
	deleted, err := r.store.PruneTraffic(ctx, now.Add(-keep))
	if err != nil {
		return err
	}
	if deleted > 0 {
		r.log.Info("已清理过期流量记录", "rows", deleted, "retention_days", int(keep.Hours()/24))
	}
	return nil
}

// peerKey 是「连接名 + 公钥」的合成键。
//
// 用连接名而不是 interface_id：状态快照里的连接是按名字给出的，
// 而接口 id 需要额外查一次库；公钥在同一连接内唯一，两者足以定位一台设备。
// 用 NUL 分隔，避免「连接名里带公钥前缀」这类构造出来的撞车。
func peerKey(ifaceName, publicKey string) string {
	return ifaceName + "\x00" + publicKey
}
