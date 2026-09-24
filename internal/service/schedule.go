// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// 执行频率。日程取值只此一处：计划备份与配置漂移巡检共用同一套规则
// （理由见 Schedule），频率自然也不该各存一份。
const (
	// FreqDaily 每天一次。
	FreqDaily = "daily"
	// FreqWeekly 每周一次。
	FreqWeekly = "weekly"
)

// Schedule 是一份「按日程执行」的规则：每天几点，或每周某天的几点。
//
// 为什么单独成一个类型：本应用里按日程跑的后台任务已经有两处（计划备份、配置漂移巡检），
// 将来还会有第三处。日程判断看着简单，但每一条都踩过坑：
//   - 用「几点几分」而不是「每隔多少小时」：用户想的是「每天凌晨三点备一次」，
//     而不是「每 86400 秒一次」——后者会在重启后漂到半夜之外的时间；
//   - 「上一个日程点」要自己往回数，跨周、跨月的边界最容易写反；
//   - 「错过就补跑」与「刚打开开关不立刻补跑」是两条相反的诉求，
//     后者靠一个「生效时间」基准来区分（见 Due）。
//
// 各写一份的结果是「备份少了一份」「巡检多跑一次」这类安静的错误：都不报错，
// 只让人慢慢不再信任这个功能。因此只留这一份实现，两个功能都用它。
type Schedule struct {
	// Freq 频率：daily（每天）或 weekly（每周一次）。
	Freq string `json:"freq"`
	// At 执行时刻，格式 HH:MM（NAS 本地时间）。
	At string `json:"at"`
	// Weekday 每周执行的那一天：1=周一 … 7=周日（仅 weekly 有效）。
	Weekday int `json:"weekday"`
}

// Validate 校验日程字段（与是否启用无关，执行前也要过一遍）。
func (s Schedule) Validate() error {
	if s.Freq != FreqDaily && s.Freq != FreqWeekly {
		return fmt.Errorf("执行频率只能是「每天」或「每周」")
	}
	if _, _, ok := parseClock(s.At); !ok {
		return fmt.Errorf("执行时刻要写成 24 小时制的 HH:MM，例如 03:30")
	}
	if s.Freq == FreqWeekly && (s.Weekday < 1 || s.Weekday > 7) {
		return fmt.Errorf("每周执行要指定星期几（1=周一 … 7=周日）")
	}
	return nil
}

// Normalize 把越界的日程字段回落到默认值。
//
// 逐项回落而不是整份丢弃：配置可能来自旧版本或被手工改过，
// 用户要的是一份能用的日程，而不是一句「配置解析失败」。
func (s Schedule) Normalize(def Schedule) Schedule {
	if s.Freq != FreqWeekly {
		s.Freq = FreqDaily
	}
	if _, _, ok := parseClock(s.At); !ok {
		s.At = def.At
	}
	if s.Weekday < 1 || s.Weekday > 7 {
		s.Weekday = def.Weekday
	}
	if s.Weekday < 1 {
		s.Weekday = 1
	}
	return s
}

// Due 判断此刻是否应当执行。
//
// 判据只有两条：① 上一个日程点在「计划生效」之后；② 最近一次执行早于那个日程点。
// 这样不必为「NAS 关机错过时间」「改过时间」额外维护状态：开机后一旦发现上一场日程
// 还没做过，就补一次（少做一次比晚一点更值得避免）。而刚打开开关那次不算错过
// （基准见各调用方的 Since 设置项），否则用户会被立刻多跑一次。
func (s Schedule) Due(now, lastAt, since time.Time) bool {
	due, ok := s.LastDue(now)
	if !ok {
		return false
	}
	if !since.IsZero() && !due.After(since) {
		return false
	}
	return lastAt.IsZero() || lastAt.Before(due)
}

// LastDue 返回「不晚于 now 的最近一个日程点」。
func (s Schedule) LastDue(now time.Time) (time.Time, bool) {
	h, m, ok := parseClock(s.At)
	if !ok {
		return time.Time{}, false
	}
	cand := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	if s.Freq == FreqWeekly {
		// 1=周一 → time.Monday；7=周日 → 7%7=0 → time.Sunday。
		wd := time.Weekday(s.Weekday % 7)
		back := (int(now.Weekday()) - int(wd) + 7) % 7
		cand = cand.AddDate(0, 0, -back)
		if cand.After(now) {
			cand = cand.AddDate(0, 0, -7)
		}
		return cand, true
	}
	if cand.After(now) {
		cand = cand.AddDate(0, 0, -1)
	}
	return cand, true
}

// NextDue 返回下一次执行时间，供界面显示「下一次：明天 03:30」。
//
// 注意它只回答「日程上的下一个点」，不代表「此刻不会补跑」：
// 若已经错过了上一场日程，下一次检查（最多 5 分钟后）就会立刻执行。
func (s Schedule) NextDue(now time.Time) (time.Time, bool) {
	h, m, ok := parseClock(s.At)
	if !ok {
		return time.Time{}, false
	}
	cand := time.Date(now.Year(), now.Month(), now.Day(), h, m, 0, 0, now.Location())
	switch s.Freq {
	case FreqWeekly:
		wd := time.Weekday(s.Weekday % 7)
		ahead := (int(wd) - int(now.Weekday()) + 7) % 7
		cand = cand.AddDate(0, 0, ahead)
		if !cand.After(now) {
			cand = cand.AddDate(0, 0, 7)
		}
	default:
		if !cand.After(now) {
			cand = cand.AddDate(0, 0, 1)
		}
	}
	return cand, true
}

// Describe 用一句话描述日程：「每天 03:30」「每周一 03:30」。
func (s Schedule) Describe() string {
	if s.Freq == FreqWeekly {
		return "每周" + weekdayLabel(s.Weekday) + " " + s.At
	}
	return "每天 " + s.At
}

// parseClock 解析 HH:MM，返回时、分与是否合法。
func parseClock(v string) (int, int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ":")
	if len(parts) != 2 {
		return 0, 0, false
	}
	h, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
	m, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err1 != nil || err2 != nil || h < 0 || h > 23 || m < 0 || m > 59 {
		return 0, 0, false
	}
	return h, m, true
}

// weekdayLabel 把 1..7 转成中文星期。
func weekdayLabel(n int) string {
	labels := [...]string{"", "一", "二", "三", "四", "五", "六", "日"}
	if n < 1 || n > 7 {
		return ""
	}
	return labels[n]
}
