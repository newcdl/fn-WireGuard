// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/traffic"
)

// 报表区间的取值范围（天）。
//
// 上限不等于保留期：请求超过保留期只是更早的那几天没有数据，本身不算错，
// 但一个「近十年」的区间会让响应里的按天数组长得毫无意义，所以给一个硬上限。
const (
	MinReportDays     = 1
	MaxReportDays     = 365
	DefaultReportDays = 30
)

// TrafficDay 是某一天（服务器本地时区的自然日）的流量合计。
type TrafficDay struct {
	Day     string `json:"day"` // 2026-09-19
	RxBytes int64  `json:"rx_bytes"`
	TxBytes int64  `json:"tx_bytes"`
}

// TrafficPeerRow 是报表里的一台设备。
type TrafficPeerRow struct {
	PeerID         int64      `json:"peer_id"`
	Name           string     `json:"name"`
	InterfaceID    int64      `json:"interface_id"`
	InterfaceName  string     `json:"interface_name"`
	Enabled        bool       `json:"enabled"`
	DisabledReason string     `json:"disabled_reason,omitempty"`
	ExpireAt       *time.Time `json:"expire_at,omitempty"`
	// QuotaTx 是每月的发送额度（0 表示不限）。
	//
	// 报表里只带这一项额度：接收是别人主动发给它的（例如它在看 NAS 上的视频），
	// 用户管不住，拿它计额度等于替别人挨罚——与额度判定的口径必须一致，
	// 否则报表会和设备列表的「本月用量」对不上。
	QuotaTx int64 `json:"quota_tx"`
	// MonthRxBytes/MonthTxBytes 是本自然月合计：额度的判定依据，也是「本月用量」的来源。
	MonthRxBytes int64 `json:"month_rx_bytes"`
	MonthTxBytes int64 `json:"month_tx_bytes"`
	// RxBytes/TxBytes 是所选区间内的合计。
	RxBytes int64 `json:"rx_bytes"`
	TxBytes int64 `json:"tx_bytes"`
	// Daily 是区间内的逐日明细，区间里每一天都在（没流量的日子补 0）。
	// 缺天会让折线把不相邻的两天连成一条直线，看上去像「那天用了很多」。
	Daily []TrafficDay `json:"daily"`
}

// TrafficReport 是流量报表。
type TrafficReport struct {
	Days int       `json:"days"`
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
	// Peers 按区间合计从大到小排列：报表第一眼要回答的是「谁在占带宽」。
	Peers []TrafficPeerRow `json:"peers"`
	// Daily/RxBytes/TxBytes 是全部设备合计，用于折线与顶部汇总。
	Daily   []TrafficDay `json:"daily"`
	RxBytes int64        `json:"rx_bytes"`
	TxBytes int64        `json:"tx_bytes"`
	// 保留策略与占用：保留多久、已经留了多少条、最早一条是什么时候。
	// 与维护页显示同一份数据 —— 用户调完保留天数，得能立刻看到代价。
	RetentionDays int        `json:"retention_days"`
	HourRows      int64      `json:"hour_rows"`
	Oldest        *time.Time `json:"oldest,omitempty"`
}

// TrafficReport 汇总「近 days 天」的流量。
//
// 按天归并在 Go 里做而不是交给 SQLite：数据库的 localtime 跟着进程时区走，
// 跨时区与夏令时下会算出一个用户不认的「日」——用户眼里的「今天」是本机时区的今天。
func (s *Service) TrafficReport(ctx context.Context, days int) (*TrafficReport, error) {
	days = clampReportDays(days)
	now := time.Now()
	from := startOfDay(now).AddDate(0, 0, -(days - 1))

	rows, err := s.Store.TrafficSince(ctx, from)
	if err != nil {
		return nil, err
	}
	peers, err := s.Store.ListPeers(ctx, 0)
	if err != nil {
		return nil, err
	}
	monthTotals, err := s.Store.TrafficTotalsSince(ctx, startOfMonth(now))
	if err != nil {
		return nil, err
	}
	hourRows, oldest, err := s.Store.TrafficFootprint(ctx)
	if err != nil {
		return nil, err
	}

	// 先把区间内的每一天摆好，后面所有累加都按这个下标走。
	dayKeys := make([]string, 0, days)
	dayIndex := make(map[string]int, days)
	for i := 0; i < days; i++ {
		key := from.AddDate(0, 0, i).Format("2006-01-02")
		dayKeys = append(dayKeys, key)
		dayIndex[key] = i
	}
	blankDaily := func() []TrafficDay {
		out := make([]TrafficDay, len(dayKeys))
		for i, k := range dayKeys {
			out[i] = TrafficDay{Day: k}
		}
		return out
	}

	report := &TrafficReport{
		Days:          days,
		From:          from,
		To:            now,
		Daily:         blankDaily(),
		RetentionDays: traffic.RetentionDays(ctx, s.Store),
		HourRows:      hourRows,
	}
	if !oldest.IsZero() {
		t := oldest
		report.Oldest = &t
	}

	// 全部设备先入列（包括区间内一条记录都没有的）。
	//
	// 只列「有流量的设备」看着更干净，但那样一台刚建、或者一直没连上的设备会直接从报表里消失，
	// 看起来像已经被删了——而「这台怎么一直没用量」恰恰是用户来报表页要找的答案之一。
	byPeer := make(map[int64]*TrafficPeerRow, len(peers))
	ordered := make([]*TrafficPeerRow, 0, len(peers))
	for _, p := range peers {
		row := &TrafficPeerRow{
			PeerID:        p.ID,
			Name:          p.Name,
			InterfaceID:   p.InterfaceID,
			InterfaceName: p.InterfaceName,
			Enabled:       p.Enabled,
			// 自动停用（额度用尽 / 已到期）的原因一定要带到报表里：
			// 「设备是停着的，而它这个月刚好用满了额度」这两件事放在一起才解释得通。
			DisabledReason: p.DisabledReason,
			ExpireAt:       p.ExpireAt,
			QuotaTx:        p.QuotaTx,
			Daily:          blankDaily(),
		}
		if t, ok := monthTotals[p.ID]; ok {
			row.MonthRxBytes, row.MonthTxBytes = t.RxBytes, t.TxBytes
		}
		byPeer[p.ID] = row
		ordered = append(ordered, row)
	}

	for _, r := range rows {
		row := byPeer[r.PeerID]
		if row == nil {
			// 设备已删除。删除设备时记录会一并清掉，这里只是兜底：
			// 万一有残留，也不能让它把别的设备的量算进合计。
			continue
		}
		i, ok := dayIndex[r.Hour.Format("2006-01-02")]
		if !ok {
			continue
		}
		row.RxBytes += r.RxBytes
		row.TxBytes += r.TxBytes
		row.Daily[i].RxBytes += r.RxBytes
		row.Daily[i].TxBytes += r.TxBytes
		report.Daily[i].RxBytes += r.RxBytes
		report.Daily[i].TxBytes += r.TxBytes
		report.RxBytes += r.RxBytes
		report.TxBytes += r.TxBytes
	}

	sort.SliceStable(ordered, func(i, j int) bool {
		li := ordered[i].RxBytes + ordered[i].TxBytes
		lj := ordered[j].RxBytes + ordered[j].TxBytes
		if li != lj {
			return li > lj
		}
		// 都没流量时按连接、名称排。顺序必须稳定：报表每刷新一次顺序就变，
		// 用户会以为自己看错了行。
		if ordered[i].InterfaceName != ordered[j].InterfaceName {
			return ordered[i].InterfaceName < ordered[j].InterfaceName
		}
		return ordered[i].Name < ordered[j].Name
	})
	report.Peers = make([]TrafficPeerRow, 0, len(ordered))
	for _, row := range ordered {
		report.Peers = append(report.Peers, *row)
	}
	return report, nil
}

// TrafficCSV 导出近 days 天的流量明细（一行一台设备一天）。
//
// 明细而不是「每台设备一行」：区间合计在界面上已经能看，导出到表格里更有价值的是
// 能用数据透视表按天、按月看趋势，那需要「设备 × 日期」的长表。
func (s *Service) TrafficCSV(ctx context.Context, days int) (string, error) {
	rep, err := s.TrafficReport(ctx, days)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	// 开头的 BOM 是给 Excel 的：没有它，Excel 会把 UTF-8 的中文列名读成乱码，
	// 用户双击打开看到一屏问号，会以为导出坏了。
	b.WriteString("\uFEFF")
	b.WriteString("设备,连接,日期,接收(字节),发送(字节),本月接收(字节),本月发送(字节),每月发送额度(字节)\n")
	var monthRx, monthTx int64
	for _, p := range rep.Peers {
		monthRx += p.MonthRxBytes
		monthTx += p.MonthTxBytes
		for _, d := range p.Daily {
			fmt.Fprintf(&b, "%s,%s,%s,%d,%d,%d,%d,%d\n",
				csvCell(p.Name), csvCell(p.InterfaceName), d.Day, d.RxBytes, d.TxBytes,
				p.MonthRxBytes, p.MonthTxBytes, p.QuotaTx)
		}
	}
	// 末尾一行合计：直接回答「这段时间一共用了多少」。
	// 它等于把上面的逐日相加，放在最后一行不会破坏按设备筛选（筛掉合计行即可）。
	if len(rep.Peers) > 0 {
		fmt.Fprintf(&b, "合计,,%s ~ %s,%d,%d,%d,%d,\n",
			rep.From.Format("2006-01-02"), rep.To.Format("2006-01-02"),
			rep.RxBytes, rep.TxBytes, monthRx, monthTx)
	}
	return b.String(), nil
}

// SetTrafficRetentionDays 调整流量明细的保留天数。
//
// 越界值在这里就挡住，不能等到采样器读到时才「回落到默认值」继续跑：
// 那样界面显示着用户填的数，实际按另一个数在清理，属于表面接受、实际不生效。
func (s *Service) SetTrafficRetentionDays(ctx context.Context, days int, a Actor) error {
	if err := traffic.ValidateRetentionDays(days); err != nil {
		return err
	}
	return s.SetSettings(ctx, map[string]string{traffic.SettingRetentionDays: fmt.Sprint(days)}, a)
}

// normalizeTrafficSettings 校验经 /settings 写入的流量设置。
//
// 保留天数在设置接口这里也要挡一道：报表页用的是 SetTrafficRetentionDays，
// 但设置接口接受任意键值对，两条路都通到同一个键上。只挡住一条，
// 另一条写进去的越界值就会被采样器悄悄回落成默认值——界面显示 3 天、实际按 90 天清理。
func normalizeTrafficSettings(kv map[string]string) error {
	raw, ok := kv[traffic.SettingRetentionDays]
	if !ok {
		return nil
	}
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("保留天数需要填写数字")
	}
	if err := traffic.ValidateRetentionDays(days); err != nil {
		return err
	}
	// 归一化后写回：去掉首尾空格，"030" 也存成 "30"，免得设置里留下两种写法。
	kv[traffic.SettingRetentionDays] = strconv.Itoa(days)
	return nil
}

// clampReportDays 把区间收敛到允许范围：不合法（0、负数、超大）一律按默认值处理，
// 而不是报错 —— 报表是只读的，用户点一下不该因为一个参数就吃一个错误弹窗。
func clampReportDays(days int) int {
	if days < MinReportDays || days > MaxReportDays {
		return DefaultReportDays
	}
	return days
}

// csvCell 转义一个 CSV 单元格：含逗号、引号或换行时整体加引号，内部引号翻倍。
//
// 导出的不只是数字：设备名与连接名是用户自己起的，叫「客厅, 电视」或者带引号都很正常，
// 不转义就会把一张表拆成对不上的列。
func csvCell(v string) string {
	if !strings.ContainsAny(v, ",\"\r\n") {
		return v
	}
	return `"` + strings.ReplaceAll(v, `"`, `""`) + `"`
}

// startOfDay 返回 t 所在自然日的零点（保持 t 的时区）。
func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

// startOfMonth 返回 t 所在自然月的第一天零点。
func startOfMonth(t time.Time) time.Time {
	y, m, _ := t.Date()
	return time.Date(y, m, 1, 0, 0, 0, 0, t.Location())
}
