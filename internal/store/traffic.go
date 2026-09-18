// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package store

import (
	"context"
	"time"
)

// TrafficRow 是某个设备在一个小时内的流量增量。
type TrafficRow struct {
	PeerID      int64     `json:"peer_id"`
	InterfaceID int64     `json:"interface_id"`
	Hour        time.Time `json:"hour"`
	RxBytes     int64     `json:"rx_bytes"`
	TxBytes     int64     `json:"tx_bytes"`
}

// TrafficTotal 是某台设备在一段时间内的合计。
type TrafficTotal struct {
	PeerID      int64 `json:"peer_id"`
	InterfaceID int64 `json:"interface_id"`
	RxBytes     int64 `json:"rx_bytes"`
	TxBytes     int64 `json:"tx_bytes"`
}

// AddTrafficDelta 把一小段流量增量累加到它所属的那个小时上。
//
// 同一小时的多次调用是**累加**而不是覆盖：采样间隔将来无论改成多少，
// 账都不会丢，也不会因为一次重试而重复计。
func (s *Store) AddTrafficDelta(ctx context.Context, peerID, interfaceID int64, hour time.Time, rx, tx int64) error {
	if rx <= 0 && tx <= 0 {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO wg_traffic_hourly(peer_id,interface_id,hour_ts,rx_bytes,tx_bytes)
		VALUES(?,?,?,?,?)
		ON CONFLICT(peer_id,hour_ts) DO UPDATE SET
			rx_bytes = rx_bytes + excluded.rx_bytes,
			tx_bytes = tx_bytes + excluded.tx_bytes`,
		peerID, interfaceID, hour.Unix(), rx, tx)
	return err
}

// TrafficSince 返回自 since 起的全部小时记录（升序）。
//
// 只给「区间过滤 + 排序」，不做按天/按设备的聚合：那属于展示口径，
// 放在服务层用 Go 按本地时区归并更清楚 —— SQLite 的 localtime 会跟着进程时区走，
// 跨时区与夏令时下容易算出一个用户不认的「日」。
func (s *Store) TrafficSince(ctx context.Context, since time.Time) ([]TrafficRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT peer_id,interface_id,hour_ts,rx_bytes,tx_bytes
		FROM wg_traffic_hourly WHERE hour_ts >= ? ORDER BY hour_ts, peer_id`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TrafficRow{}
	for rows.Next() {
		var r TrafficRow
		var ts int64
		if err := rows.Scan(&r.PeerID, &r.InterfaceID, &ts, &r.RxBytes, &r.TxBytes); err != nil {
			return nil, err
		}
		r.Hour = time.Unix(ts, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// TrafficTotalsSince 返回每台设备自 since 起的合计（用于月度额度与报表汇总）。
func (s *Store) TrafficTotalsSince(ctx context.Context, since time.Time) (map[int64]TrafficTotal, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT peer_id, MAX(interface_id), SUM(rx_bytes), SUM(tx_bytes)
		FROM wg_traffic_hourly WHERE hour_ts >= ? GROUP BY peer_id`, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]TrafficTotal{}
	for rows.Next() {
		var t TrafficTotal
		if err := rows.Scan(&t.PeerID, &t.InterfaceID, &t.RxBytes, &t.TxBytes); err != nil {
			return nil, err
		}
		out[t.PeerID] = t
	}
	return out, rows.Err()
}

// PruneTraffic 删除早于 before 的小时记录，返回删除行数。
func (s *Store) PruneTraffic(ctx context.Context, before time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM wg_traffic_hourly WHERE hour_ts < ?`, before.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// TrafficFootprint 返回流量表的占用概况：小时记录条数、最早一条的时间（空表返回零值）。
//
// 维护页拿它显示「保留了多少、占多大地方」——保留策略是用户可调的，
// 调完得能立刻看到代价，否则那个设置项就只是一句承诺。
func (s *Store) TrafficFootprint(ctx context.Context) (rows int64, oldest time.Time, err error) {
	var cnt int64
	var minTS int64
	if err = s.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(MIN(hour_ts),0) FROM wg_traffic_hourly`).Scan(&cnt, &minTS); err != nil {
		return 0, time.Time{}, err
	}
	if minTS > 0 {
		oldest = time.Unix(minTS, 0)
	}
	return cnt, oldest, nil
}

// DeletePeerTraffic 删除某台设备的全部流量记录。
//
// 随设备一起删，而不是留着当历史：设备删除后 peer_id 会被后续新建的设备复用，
// 留着就会把上一台设备的用量算到新设备头上（「这个月用了 300GB」而它其实刚建）。
func (s *Store) DeletePeerTraffic(ctx context.Context, peerID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM wg_traffic_hourly WHERE peer_id = ?`, peerID)
	return err
}
