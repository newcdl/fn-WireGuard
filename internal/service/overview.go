// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

package service

import (
	"context"
	"sort"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/wgkey"
)

// Overview 是仪表盘聚合数据。
type Overview struct {
	Health         model.Health      `json:"health"`
	Backend        string            `json:"backend"`
	InterfaceCount int               `json:"interface_count"`
	InterfaceUp    int               `json:"interface_up"`
	PeerCount      int               `json:"peer_count"`
	PeerOnline     int               `json:"peer_online"`
	PeerEnabled    int               `json:"peer_enabled"`
	TotalRx        int64             `json:"total_rx"`
	TotalTx        int64             `json:"total_tx"`
	RxRate         float64           `json:"rx_rate"`
	TxRate         float64           `json:"tx_rate"`
	Interfaces     []model.Interface `json:"interfaces"`
	TopPeers       []model.Peer      `json:"top_peers"`
	Recent         []model.Peer      `json:"recent_handshakes"`
	ServerEndpoint string            `json:"server_endpoint"`
	GeneratedAt    time.Time         `json:"generated_at"`
}

// GetOverview 汇总仪表盘数据。
func (s *Service) GetOverview(ctx context.Context) (*Overview, error) {
	ifaces, err := s.Store.ListInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	s.Cache.EnrichInterfaces(ifaces)
	ov := &Overview{
		Health:         s.Health(ctx),
		Backend:        s.Cache.Get().Backend,
		InterfaceCount: len(ifaces),
		Interfaces:     make([]model.Interface, 0, len(ifaces)),
		TopPeers:       []model.Peer{},
		Recent:         []model.Peer{},
		ServerEndpoint: s.Store.GetSetting(ctx, "server_endpoint", ""),
		GeneratedAt:    time.Now(),
	}
	for i := range ifaces {
		it := ifaces[i]
		it.PrivateKey = ""
		if it.Up {
			ov.InterfaceUp++
		}
		ov.TotalRx += it.RxBytes
		ov.TotalTx += it.TxBytes
		ov.RxRate += it.RxRate
		ov.TxRate += it.TxRate
		ov.PeerCount += it.PeerCount
		ov.PeerOnline += it.PeerOnline
		ov.Interfaces = append(ov.Interfaces, it)
	}

	peers, err := s.Store.ListPeers(ctx, 0)
	if err != nil {
		return nil, err
	}
	s.Cache.EnrichPeers(peers)
	for i := range peers {
		p := peers[i]
		p.PresharedKey = ""
		p.ClientPrivateKey = ""
		if p.Enabled {
			ov.PeerEnabled++
		}
		if p.Online {
			ov.Recent = append(ov.Recent, p)
		}
		ov.TopPeers = append(ov.TopPeers, p)
	}
	// 流量排行
	sort.Slice(ov.TopPeers, func(i, j int) bool {
		return ov.TopPeers[i].RxBytes+ov.TopPeers[i].TxBytes > ov.TopPeers[j].RxBytes+ov.TopPeers[j].TxBytes
	})
	if len(ov.TopPeers) > 10 {
		ov.TopPeers = ov.TopPeers[:10]
	}
	// 最近握手
	sort.Slice(ov.Recent, func(i, j int) bool {
		return ov.Recent[i].LastHandshake.After(ov.Recent[j].LastHandshake)
	})
	if len(ov.Recent) > 10 {
		ov.Recent = ov.Recent[:10]
	}
	return ov, nil
}

// ListAudit 查询审计记录。
func (s *Service) ListAudit(ctx context.Context, f model.AuditFilter) ([]model.AuditEntry, int64, error) {
	return s.Store.ListAudit(ctx, f)
}

// VerifyAudit 校验审计链完整性。
func (s *Service) VerifyAudit(ctx context.Context) (bool, int64, error) {
	return s.Store.VerifyAudit(ctx)
}

// ListLogs 查询应用日志。
func (s *Service) ListLogs(ctx context.Context, level, scope, keyword string, limit, offset int) ([]model.LogEntry, int64, error) {
	return s.Store.ListLogs(ctx, level, scope, keyword, limit, offset)
}

// GetSettings 返回全部设置。
func (s *Service) GetSettings(ctx context.Context) (map[string]string, error) {
	return s.Store.AllSettings(ctx)
}

// SetSettings 批量写入设置。
func (s *Service) SetSettings(ctx context.Context, kv map[string]string, a Actor) error {
	if err := normalizeNotifySettings(kv); err != nil {
		return err
	}
	// 只记键名不记取值：设置里包含通知地址这类带令牌的敏感内容，
	// 写进审计等于把凭据交给每个能查审计的人。快照同理，备注里也只给键名。
	changed := make([]string, 0, len(kv))
	for k := range kv {
		changed = append(changed, k)
	}
	sort.Strings(changed)
	s.snapshotBefore(ctx, "settings.update", settingsNote(changed))
	for k, v := range kv {
		if err := s.Store.SetSetting(ctx, k, v); err != nil {
			return err
		}
	}
	s.audit(ctx, a, "settings.update", "settings", "", "", "", "ok", "变更项："+strings.Join(changed, "、"))
	return nil
}

// GenerateKeypair 生成密钥对（供密钥管理页使用）。
func (s *Service) GenerateKeypair(ctx context.Context, a Actor) (map[string]string, error) {
	priv, pub, err := wgkey.Generate()
	if err != nil {
		return nil, err
	}
	s.audit(ctx, a, "key.generate", "key", "", "", shortKey(pub), "ok", "")
	return map[string]string{"private_key": priv, "public_key": pub}, nil
}

// GeneratePSK 生成预共享密钥。
func (s *Service) GeneratePSK(ctx context.Context, a Actor) (map[string]string, error) {
	psk, err := newPSK()
	if err != nil {
		return nil, err
	}
	s.audit(ctx, a, "key.generate_psk", "key", "", "", "", "ok", "")
	return map[string]string{"preshared_key": psk}, nil
}

// PeerHistory 返回节点历史流量。
func (s *Service) PeerHistory(ctx context.Context, interfaceID int64, publicKey string, since time.Time) ([][3]float64, error) {
	return s.Store.PeerHistory(ctx, interfaceID, publicKey, since, 2000)
}
