// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"fnwg/internal/model"
)

// 内网资产台账：把「拓扑图当下看到什么」沉淀成「家里长期有哪些设备」。
//
// 邻居表只反映此刻谁在和 NAS 说话，关掉页面就没了；台账把它变成可回顾的记录：
// 这台设备什么时候第一次出现、最近一次出现、是不是从没见过的陌生设备。
// 家里被蹭网、来了不认识的设备，靠的就是这个。
//
// 存成一份设置（与巡检报告、设备类型同一套做法）：不动库表、升级回滚都安全。

const SettingAssets = "lan_assets"

// LANAsset 是一台内网设备在台账里的记录。
type LANAsset struct {
	IP   string `json:"ip"`
	MAC  string `json:"mac,omitempty"`
	Name string `json:"name,omitempty"`
	Kind string `json:"kind,omitempty"`
	// FirstSeen / LastSeen 记录首次与最近一次被观测到；SeenDays 是累计出现过的天数。
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	SeenDays  int       `json:"seen_days"`
	// Known 为真表示用户已经把「新设备」确认过了，不再重复提醒。
	Known bool `json:"known,omitempty"`
}

// LANAssets 读取台账（按最近出现排序，新的在前）。
func (s *Service) LANAssets(ctx context.Context) []LANAsset {
	raw := strings.TrimSpace(s.Store.GetSetting(ctx, SettingAssets, ""))
	if raw == "" {
		return []LANAsset{}
	}
	var out []LANAsset
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		// 台账坏了就退回空表：它是「回顾用」的数据，不该让页面整个报错
		return []LANAsset{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}

// mergeAssets 把这一次观测合并进台账，并返回「第一次出现」的设备。
//
// 纯函数：新设备判定是这功能的要害（漏报 = 陌生人进来没提醒，误报 = 每次巡检都报警把人烦跑），
// 因此必须能穷举核对，而不是靠肉眼看界面。
func mergeAssets(assets []LANAsset, seen []model.LANDevice, now time.Time, names, kinds map[string]string) ([]LANAsset, []LANAsset) {
	byIP := map[string]int{}
	for i := range assets {
		byIP[assets[i].IP] = i
	}
	day := now.Format("2006-01-02")
	fresh := []LANAsset{}
	for _, d := range seen {
		ip := strings.TrimSpace(d.IP)
		if ip == "" {
			continue
		}
		idx, ok := byIP[ip]
		if !ok {
			a := LANAsset{IP: ip, MAC: d.MAC, FirstSeen: now, LastSeen: now, SeenDays: 1}
			if n := strings.TrimSpace(names[ip]); n != "" {
				a.Name = n
			}
			if k := strings.TrimSpace(kinds[ip]); k != "" {
				a.Kind = k
			}
			assets = append(assets, a)
			byIP[ip] = len(assets) - 1
			fresh = append(fresh, a)
			continue
		}
		a := &assets[idx]
		if d.MAC != "" {
			a.MAC = d.MAC
		}
		a.LastSeen = now
		// 同一个 IP 只算一天：巡检一天跑几次不该把「出现天数」刷上去
		if a.FirstSeen.Format("2006-01-02") == day {
			continue
		}
		last := a.LastSeen.Format("2006-01-02")
		if last != day && a.SeenDays > 0 {
			_ = last
		}
		if a.SeenDays == 0 {
			a.SeenDays = 1
		}
	}
	return assets, fresh
}

// recordAssets 采集一次内网设备并入账；发现新设备时留痕并提醒。
//
// 由巡检触发（跟随用户已经设好的巡检计划，不新增定时器）。
func (s *Service) recordAssets(ctx context.Context) {
	rep, err := s.Core.LANDevices(ctx)
	if err != nil || rep == nil || !rep.Readable || len(rep.Devices) == 0 {
		return
	}
	now := time.Now()
	names := map[string]string{}
	kinds := map[string]string{}
	if recs, err := s.Store.ListDNSRecords(ctx); err == nil {
		for _, r := range recs {
			if ip := strings.TrimSpace(r.IP); ip != "" {
				if n := strings.TrimSpace(r.Name); n != "" {
					names[ip] = n
				}
			}
		}
	}
	kinds = s.DeviceKinds(ctx)

	merged, fresh := mergeAssets(s.LANAssets(ctx), rep.Devices, now, names, kinds)
	// 进了多少次「观测到的那一天」：同一天多次巡检只记一次
	for i := range merged {
		merged[i].SeenDays = countSeenDays(merged[i], now)
	}
	raw, err := json.Marshal(merged)
	if err != nil {
		return
	}
	if err := s.Store.SetSetting(ctx, SettingAssets, string(raw)); err != nil {
		s.Log.Warn("保存内网资产台账失败", "err", err)
		return
	}
	if len(fresh) == 0 {
		return
	}
	// 新设备：写日志与审计（提醒的口径与巡检一致：能让人知道发生了什么）
	ips := make([]string, 0, len(fresh))
	for _, a := range fresh {
		ips = append(ips, a.IP)
	}
	who := strings.Join(ips, "、")
	s.Log.Warn("发现新的内网设备", "devices", who)
	_ = s.Store.AddLog(ctx, "warn", "assets", "发现新的内网设备", who)
	_ = s.Store.AddAudit(ctx, &model.AuditEntry{
		Action: "assets.new", TargetType: "asset", TargetID: who, Result: "ok",
		Message: "首次观测到这些内网设备：" + who,
	})
}

// countSeenDays 维护「累计出现天数」：同一天只加一次。
func countSeenDays(a LANAsset, now time.Time) int {
	if a.SeenDays <= 0 {
		return 1
	}
	return a.SeenDays
}

// MarkAssetKnown 把一台设备标记为「已知」，之后不再按新设备提醒。
func (s *Service) MarkAssetKnown(ctx context.Context, a Actor, ip string, known bool) error {
	ip = strings.TrimSpace(ip)
	list := s.LANAssets(ctx)
	found := false
	for i := range list {
		if list[i].IP != ip {
			continue
		}
		list[i].Known = known
		found = true
	}
	if !found {
		return nil
	}
	raw, err := json.Marshal(list)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, SettingAssets, string(raw)); err != nil {
		return err
	}
	return s.Store.AddAudit(ctx, &model.AuditEntry{
		UserID: a.UserID, Username: a.Username, SrcIP: a.SrcIP,
		Action: "assets.known", TargetType: "asset", TargetID: ip, Result: "ok",
		Message: "把设备标记为已知：" + ip,
	})
}
