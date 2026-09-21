// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/notify"
	"fnwg/internal/store"
)

// 配置漂移巡检：按日程把「实际状态」和「用户配置出来的期望状态」对一遍，出一份报告。
//
// 为什么要有它：这个应用会启用很多东西（内核模块、连接、内网访问、隔离、解析、通知、备份），
// 每一样都可能在某次系统升级、存储迁移、权限变化之后**安静地不再生效**——
// 界面上的开关还是开的，用户以为一切正常，直到真的需要它的那天。
// 顶栏的异常清单是「此刻」的结论，但它只在有人打开页面时才被看见；
// 定期巡检是为了让「三个月前就开始漂移」这件事在发生后不久就被说出来。
//
// 判定放在服务层而不是界面里，理由有两条：
//  1. 定期巡检跑在**代理进程**里（它才是「一定在跑」的那个进程），那里没有浏览器；
//  2. 判定一旦有第二份实现，界面说「正常」、报告说「异常」这种自相矛盾迟早会出现
//     （同一个应用里出现两套口径，用户不知道该信哪个 —— 这类教训本项目已经吃过几次）。
//
// 因此：判定只有这一份（judgeInspect），界面的异常清单与定期报告读的是同一个函数、
// 同一批检查项。界面侧只是按等级过滤（ok 项不上顶栏，报告里留着当体检记录）。
const (
	// SettingInspectPlan 巡检计划配置（JSON）。
	SettingInspectPlan = "inspect_plan"
	// SettingInspectSince 计划生效时间点（unix 秒），理由同计划备份：
	// 免得「下午三点打开开关」立刻补跑一次。
	SettingInspectSince = "inspect_since"
	// SettingInspectReports 历史报告（JSON 数组，新的在前）。
	SettingInspectReports = "inspect_reports"

	// 保留份数的合理区间。按每天一次算，默认 14 份是两周，够回看「什么时候开始不对劲的」。
	MinInspectKeep     = 1
	MaxInspectKeep     = 60
	DefaultInspectKeep = 14

	// 报告里每条的等级。
	//
	// ok 也进报告：报告的用处之一是「这段时间一直体检通过」，
	// 只记异常的话，一份全绿的报告会退化成空文件，看不出到底查没查。
	InspectOK      = "ok"
	InspectWarning = "warning"
	InspectError   = "error"
)

// InspectItem 是巡检里的一条结论。
//
// 字段与界面异常清单一一对应（key/level/title/detail/fix/repairable/to）：
// 同一个判定要同时喂给顶栏提示与报告详情，两边各一套字段只会让其中一处漏掉字段。
type InspectItem struct {
	// Key 是稳定标识：界面据此去重、定位，也用来对比「上次这条还在不在」。
	Key   string `json:"key"`
	Level string `json:"level"` // ok | warning | error
	// Title 一句话结论。
	Title string `json:"title"`
	// Detail 实测到的具体事实（哪条连接、哪一层没过）。
	Detail string `json:"detail"`
	// Fix 处理建议；能照着做，不写「请检查配置」这类空话。
	Fix string `json:"fix,omitempty"`
	// Repairable 表示能否在「系统维护」里一键修好。
	Repairable bool `json:"repairable,omitempty"`
	// To 需要用户去别的页面处理时的目标路由名。
	To string `json:"to,omitempty"`
}

// InspectReport 是一次巡检的完整结论。
type InspectReport struct {
	At time.Time `json:"at"`
	// Manual 表示由用户点「立即巡检一次」触发（与按日程区分）。
	Manual bool `json:"manual,omitempty"`
	// Items 全部检查结论，按检查顺序（重要的在前），含通过项。
	Items    []InspectItem `json:"items"`
	Errors   int           `json:"errors"`
	Warnings int           `json:"warnings"`
	Passed   int           `json:"passed"`
}

// InspectPlan 是巡检计划：开关 + 日程 + 保留报告份数。
type InspectPlan struct {
	Enabled bool `json:"enabled"`
	// Schedule 内嵌：JSON 里平铺 freq / at / weekday，与计划备份的形状一致，
	// 界面与设置项都少一层嵌套。
	Schedule
	// Keep 保留多少份历史报告（含本次）。
	Keep int `json:"keep"`
}

// InspectStatus 是巡检的对外状态，界面一次取全。
type InspectStatus struct {
	Plan InspectPlan `json:"plan"`
	// Last 最近一次报告；从没跑过时为空。
	Last *InspectReport `json:"last,omitempty"`
	// Reports 历史报告（含最近一次），新的在前。
	Reports []InspectReport `json:"reports"`
	// Since 计划生效时间（上次打开开关的时刻）。
	Since *time.Time `json:"since,omitempty"`
	// NextAt 下次预计执行时间；计划关闭时为空。
	NextAt *time.Time `json:"next_at,omitempty"`
}

// DefaultInspectPlan 返回默认配置：关闭、每天 06:30、保留 14 份。
//
// 默认时刻与计划备份（03:30）错开：巡检要读内核规则与路由，虽然只读，
// 但没必要和备份抢同一分钟的磁盘。
func DefaultInspectPlan() InspectPlan {
	return InspectPlan{
		Schedule: Schedule{Freq: FreqDaily, At: "06:30", Weekday: 1},
		Keep:     DefaultInspectKeep,
	}
}

// Validate 校验配置。
func (p InspectPlan) Validate() error {
	if err := p.Schedule.Validate(); err != nil {
		return err
	}
	if p.Keep < MinInspectKeep || p.Keep > MaxInspectKeep {
		return fmt.Errorf("保留份数需要在 %d 到 %d 之间", MinInspectKeep, MaxInspectKeep)
	}
	return nil
}

// Describe 用一句话描述配置，供审计与日志使用。
func (p InspectPlan) Describe() string {
	if !p.Enabled {
		return "已关闭"
	}
	return fmt.Sprintf("%s · 保留 %d 份报告", p.Schedule.Describe(), p.Keep)
}

// LoadInspectPlan 读取配置；没存过或内容坏了都回落到默认值。
func LoadInspectPlan(ctx context.Context, st *store.Store) InspectPlan {
	plan := DefaultInspectPlan()
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingInspectPlan, ""))
	if raw == "" {
		return plan
	}
	if err := json.Unmarshal([]byte(raw), &plan); err != nil {
		return DefaultInspectPlan()
	}
	plan.Schedule = plan.Schedule.Normalize(DefaultInspectPlan().Schedule)
	if plan.Keep < MinInspectKeep || plan.Keep > MaxInspectKeep {
		plan.Keep = DefaultInspectKeep
	}
	return plan
}

// SaveInspectPlan 保存配置。
func (s *Service) SaveInspectPlan(ctx context.Context, plan InspectPlan, now time.Time, a Actor) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	old := LoadInspectPlan(ctx, s.Store)
	raw, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if err := s.Store.SetSetting(ctx, SettingInspectPlan, string(raw)); err != nil {
		return err
	}
	// 从「关闭」变为「启用」时记下生效时间，作为「有没有错过日程」的起点。
	if plan.Enabled && !old.Enabled {
		if err := s.Store.SetSetting(ctx, SettingInspectSince, strconv.FormatInt(now.Unix(), 10)); err != nil {
			return err
		}
	}
	s.auditInspect(ctx, a, "inspect.save", "ok", "巡检计划："+plan.Describe())
	return nil
}

// InspectStatusOf 汇总巡检状态，供界面展示。
func InspectStatusOf(ctx context.Context, st *store.Store, now time.Time) *InspectStatus {
	plan := LoadInspectPlan(ctx, st)
	reports := loadInspectReports(ctx, st)
	out := &InspectStatus{Plan: plan, Reports: reports}
	if len(reports) > 0 {
		last := reports[0]
		out.Last = &last
	}
	if reports == nil {
		out.Reports = []InspectReport{}
	}
	if since := loadInspectSince(ctx, st); !since.IsZero() {
		out.Since = &since
	}
	if plan.Enabled {
		if next, ok := plan.Schedule.NextDue(now); ok {
			out.NextAt = &next
		}
	}
	return out
}

// rejectInspectPlanSettings 拒绝经通用设置接口写入巡检配置。
//
// 理由与计划备份相同：这是一组互相约束的字段（日程 + 保留份数），
// 逐键写入既没法整体校验，也会绕开「保留份数越界」这类检查。
// 只留 PUT /system/inspect 一条写入路径。
func rejectInspectPlanSettings(kv map[string]string) error {
	for k := range kv {
		if strings.HasPrefix(k, "inspect_plan") {
			return fmt.Errorf("巡检计划的配置请通过「系统维护 → 配置漂移巡检」保存（收到的是 %s）", k)
		}
	}
	return nil
}

// ------------------------------------------------------------------ 判定

// inspectFacts 是判定要用到的全部事实。
//
// 每一条都来自本进程能直接拿到的数据（或经 Core 委派给代理），不做任何修改动作。
type inspectFacts struct {
	Now time.Time
	// Health 代理存活与内核能力；读不到时代理侧会把它折成 AgentUp=false。
	Health model.Health
	// Net 网络自检（面向用户的可读形式）；NetErr 非空表示这次没读到。
	Net    *NetworkCheckResult
	NetErr string
	// Ov 概览（连接的实际工作状态、对外地址）；OvErr 非空表示这次没读到。
	Ov    *Overview
	OvErr string
	// Notify 通知配置与最近一次投递结果。
	Notify notify.Status
	// Gateway 飞牛桌面入口的状态（由界面进程记录，见 SaveGatewayFact）。
	Gateway    model.GatewayEntry
	HasGateway bool
	// BackupEnabled / BackupLast 计划备份的开关与最近一次结果。
	BackupEnabled bool
	BackupLast    *BackupRunState
}

// InspectChecks 做一次即时判定，不落库。
//
// 顶栏与各页的异常清单走这里：它们要的是「此刻」的结论，
// 与定期报告用的是同一个判定函数（判定的唯一实现，见本文件开头）。
func (s *Service) InspectChecks(ctx context.Context) []InspectItem {
	return judgeInspect(s.inspectFacts(ctx))
}

// inspectFacts 采集判定所需的事实。
//
// 任何一项读不到都不影响其余项：这是本项目的一贯做法 ——
// 一个探测失败不该让整页状态变成空白，那反而让用户失去线索。
func (s *Service) inspectFacts(ctx context.Context) inspectFacts {
	f := inspectFacts{Now: time.Now()}
	f.Health = s.Health(ctx)
	if res, err := s.CheckNetwork(ctx); err != nil {
		f.NetErr = err.Error()
	} else {
		f.Net = res
	}
	// 概览里的连接在线状态来自状态缓存，代理进程里那个缓存是冷的
	// （它平时不提供服务接口），因此先刷一次再取。
	if s.Cache != nil {
		_ = s.Cache.Refresh(ctx)
	}
	if ov, err := s.GetOverview(ctx); err != nil {
		f.OvErr = err.Error()
	} else {
		f.Ov = ov
	}
	f.Notify = s.NotifyStatus(ctx)
	f.Gateway, f.HasGateway = LoadGatewayFact(ctx, s.Store)
	f.BackupEnabled = LoadBackupPlan(ctx, s.Store).Enabled
	f.BackupLast = loadBackupRunState(ctx, s.Store)
	return f
}

// judgeInspect 是巡检的全部判定：事实进、结论出。
//
// 纯函数（不碰时钟之外的任何外部状态），因此可以逐条断言 ——
// 这份清单的价值全在「每一条都对」，而它最容易出的错是「该报的没报」
// （用户以为巡检过了就等于没问题），所以每一条都有对应用例。
//
// 顺序即重要性：后台服务 → 运行模式 → 系统网络 → 桌面入口 → 连接 →
// 内网访问 → 隔离 → 访问控制冲突 → 残留网卡 → 对外地址 → 通知 → 解析 → 备份。
func judgeInspect(f inspectFacts) []InspectItem {
	out := []InspectItem{}

	// ① 后台服务：它没在跑，后面所有「配置是否生效」的判断都没有意义（配置根本没下发）
	if !f.Health.AgentUp {
		detail := "负责实际建立连接的组件（fnwg-agent）没有运行。"
		if f.Health.Error != "" {
			detail = "负责实际建立连接的组件（fnwg-agent）没有响应：" + f.Health.Error
		}
		out = append(out, InspectItem{
			Key: "agent", Level: InspectError,
			Title:  "后台服务未运行，当前修改不会生效",
			Detail: detail,
			Fix:    "到应用中心重启本应用；若重启后仍不恢复，请查看「运行记录」中的错误。",
			To:     "logs",
		})
	} else {
		out = append(out, InspectItem{
			Key: "agent", Level: InspectOK,
			Title:  "后台服务正在运行",
			Detail: fmt.Sprintf("后端 %s，已运行 %s。", backendLabel(f.Health.Backend), inspectUptime(f.Health.UptimeSec)),
		})
	}

	// ② 运行模式：标准模式优先，退到兼容模式只提示（功能还能用），两种都不行才是错误。
	//    演示模式（内存后端）不参与判断：它既不碰内核也不碰网卡，
	//    照真实口径就会得到一条永远成立、却毫无意义的结论。
	demo := f.Health.Backend == "mock"
	switch {
	case demo:
		out = append(out, InspectItem{
			Key: "kernel", Level: InspectOK,
			Title:  "当前是演示模式",
			Detail: "后端为内存实现，不接触内核与网卡；本模式下运行状态不代表真机行为。",
		})
	case !f.Health.AgentUp:
		// 代理没在跑，能力位读不到，这里不重复说（上面那条已经说清了）
	case f.Health.KernelModule:
		out = append(out, InspectItem{
			Key: "kernel", Level: InspectOK,
			Title:  "标准模式（内核加速）可用",
			Detail: "系统内核支持加密网络模块，连接由内核直接处理。",
		})
	case f.Health.TunDevice:
		out = append(out, InspectItem{
			Key: "compat", Level: InspectWarning,
			Title:  "正在使用兼容模式",
			Detail: "系统没有可用的内核加密网络模块，已自动改用兼容模式，连接可以正常工作，速度和资源占用略逊于标准模式。",
			Fix:    "无需手动操作；若 NAS 系统升级后支持了内核模块，会自动切回标准模式。",
			To:     "maintenance",
		})
	default:
		out = append(out, InspectItem{
			Key: "kernel", Level: InspectError,
			Title:  "系统未开启标准加速模式",
			Detail: "既找不到内核加密网络模块，也没有可用的兼容模式（缺少 TUN 设备），新建的连接无法工作。",
			// 不写死版本号：那句话写死过「一般 0.9.0 以上」，而能装上本应用的系统早已高于它，
			// 于是提示变成一句无法执行的废话。现在只说清「去更新系统」，并把反馈路径写明。
			Fix: "这属于系统内核能力问题：请先把 NAS 系统更新到较新版本再试。若更新后仍不支持，请把系统版本与内核版本（uname -r）反馈给我们以便适配。",
			To:  "logs",
		})
	}

	// ③ 网络自检读不到：说清原因，并跳过所有依赖它的小节。
	//    这里刻意不把「没读到」当成「一切正常」——那是最危险的一种假通过。
	if f.NetErr != "" {
		out = append(out, InspectItem{
			Key: "net-unreadable", Level: InspectWarning,
			Title:  "这次没能读到系统网络状态",
			Detail: "网络自检失败：" + f.NetErr,
			Fix:    "若刚重启过应用，稍等片刻再看；持续如此请到「运行记录」查看错误，并到「系统维护」点「立即修复」。",
			To:     "maintenance",
		})
	} else if n := f.Net; n != nil {
		// ④ NAS 自身上网路线被本应用占用：唯一可能影响系统网络的情况，最要紧
		stray := make([]string, 0, len(n.StrayDefaults))
		for _, d := range n.StrayDefaults {
			stray = append(stray, "dev="+d.Dev)
		}
		if len(stray) > 0 || !n.Healthy {
			detail := fmt.Sprintf("系统默认路由指向了本应用的连接（%s），FN Connect / 应用市场可能已受影响。", strings.Join(stray, "、"))
			if len(stray) == 0 {
				detail = strings.Join(n.Messages, "；")
				if detail == "" {
					detail = "系统网络自检未通过。"
				}
			}
			out = append(out, InspectItem{
				Key: "net", Level: InspectError,
				Title:      "NAS 自身的上网路线异常",
				Detail:     detail,
				Fix:        "点「立即修复」，或到「系统维护」执行一键修复；本应用只会清理自己造成的残留。",
				Repairable: true,
				To:         "maintenance",
			})
		} else {
			out = append(out, InspectItem{
				Key: "net", Level: InspectOK,
				Title:  "NAS 自身的上网路线正常",
				Detail: fmt.Sprintf("系统默认路由有 %d 条，均未指向本应用的连接。", len(n.SystemDefaults)),
			})
		}
	}

	// ⑤ 飞牛桌面入口：这条通道一断，桌面图标是**确定**打不开的（502），不报就没人知道。
	//    它的状态由界面进程记录（socket 在那个进程里），代理侧只能读记录。
	if f.HasGateway && f.Gateway.Configured {
		if f.Gateway.Ready {
			out = append(out, InspectItem{
				Key: "gateway", Level: InspectOK,
				Title:  "从飞牛桌面点图标可以打开本应用",
				Detail: "网关入口已就绪：" + f.Gateway.Path,
			})
		} else {
			detail := f.Gateway.Detail
			if detail == "" {
				detail = "飞牛统一网关入口没有就绪，而从飞牛桌面打开走的正是这条通道。"
			}
			fix := f.Gateway.Fix
			if fix == "" {
				fix = "应用每 15 秒会自动重建一次；若长期如此，请到应用中心重启本应用。"
			}
			out = append(out, InspectItem{
				Key: "gateway", Level: InspectError,
				Title:  "从飞牛桌面点图标打不开本应用（会显示 502）",
				Detail: detail, Fix: fix, To: "maintenance",
			})
		}
	}

	// ⑥ 已启用但没真正工作的连接 —— 「启用了功能，运行状态不符合预期」的典型
	if f.OvErr != "" {
		out = append(out, InspectItem{
			Key: "ov-unreadable", Level: InspectWarning,
			Title:  "这次没能读到连接状态",
			Detail: "读取概览失败：" + f.OvErr,
			Fix:    "稍后重试；持续如此请到「运行记录」查看错误。",
			To:     "logs",
		})
	} else if ov := f.Ov; ov != nil {
		notUp := make([]string, 0, 2)
		enabled := 0
		for _, it := range ov.Interfaces {
			if !it.Enabled {
				continue
			}
			enabled++
			if !it.Up {
				notUp = append(notUp, it.Name)
			}
		}
		switch {
		case len(notUp) > 0:
			out = append(out, InspectItem{
				Key: "iface-down", Level: InspectError,
				Title:  fmt.Sprintf("%d 条已启用的连接没有工作", len(notUp)),
				Detail: fmt.Sprintf("未工作：%s。设备现在连不上。", strings.Join(notUp, "、")),
				Fix:    "到「我的连接」查看该连接，点「重新应用」把配置重新下发一次。",
				To:     "interfaces",
			})
		case enabled > 0:
			out = append(out, InspectItem{
				Key: "iface-down", Level: InspectOK,
				Title:  fmt.Sprintf("%d 条已启用的连接都在工作", enabled),
				Detail: "内核里的网卡与配置一致，设备可以连接。",
			})
		}
	}

	// ⑦ 内网访问 / 设备间隔离：**只有真的开了这个功能**才有「有没有生效」可言。
	//
	// 没开的时候后端仍会给出「尚未下发：没有打开内网访问开关的连接」这类检查项，
	// 若把它们一律当成问题，报告里就会长期挂着一条「已开启，但还没真正生效」——
	// 而用户什么都没开。结论一旦开始说无用的话，整份报告就没人看了。
	// 判据用连接上的开关本身（结构字段），不认文案：文案会改，开关不会骗人。
	if f.Net != nil {
		lanOn, isolateOn := lanAccessConfigured(f.Ov)
		failed := make([]model.NATCheck, 0, len(f.Net.NAT.Checks))
		var isolate *model.NATCheck
		for i := range f.Net.NAT.Checks {
			c := f.Net.NAT.Checks[i]
			if c.OK {
				continue
			}
			if c.Key == "isolate" {
				if isolateOn {
					isolate = &c
				}
				continue
			}
			if lanOn {
				failed = append(failed, c)
			}
		}
		if len(failed) > 0 {
			parts := make([]string, 0, len(failed))
			fix := ""
			for _, c := range failed {
				parts = append(parts, c.Label+"："+c.Detail)
				if fix == "" {
					fix = c.Fix
				}
			}
			out = append(out, InspectItem{
				Key: "nat", Level: InspectWarning,
				Title:  "「允许设备访问家里内网」已开启，但还没真正生效",
				Detail: strings.Join(parts, "；"),
				Fix:    fix,
				To:     "maintenance",
			})
		} else if lanOn {
			out = append(out, InspectItem{
				Key: "nat", Level: InspectOK,
				Title:  "内网访问链路的各层检查都通过",
				Detail: "转发规则、内核开关与出口网卡都符合当前配置。",
			})
		}
		if isolate != nil {
			out = append(out, InspectItem{
				Key: "isolate", Level: InspectWarning,
				Title:  "「设备间隔离」已开启，但还没真正生效",
				Detail: isolate.Detail,
				Fix:    isolate.Fix,
				To:     "maintenance",
			})
		} else if isolateOn {
			out = append(out, InspectItem{
				Key: "isolate", Level: InspectOK,
				Title:  "设备间隔离正在生效",
				Detail: fmt.Sprintf("已对 %d 个隧道网段生效。", len(f.Net.NAT.IsolateNets)),
			})
		}

		// ⑧ 访问控制配置互相矛盾：三项设置各自都对，组合起来互相抵消。
		//    这类问题只能靠汇总式诊断说出来 —— 现象只是一个模糊的「配了却访问不了」。
		if len(f.Net.AccessIssues) > 0 {
			for _, a := range f.Net.AccessIssues {
				out = append(out, InspectItem{
					Key:    fmt.Sprintf("access:%s:%d", a.Key, a.InterfaceID),
					Level:  InspectWarning,
					Title:  a.Title,
					Detail: a.Detail,
					Fix:    a.Fix,
					To:     firstNonEmpty(a.To, "interfaces"),
				})
			}
		} else if enabledInterfaceCount(f.Ov) > 0 {
			out = append(out, InspectItem{
				Key: "access", Level: InspectOK,
				Title:  "访问控制配置没有互相矛盾的地方",
				Detail: "「设备通行范围」「内网访问」「设备间隔离」三项设置彼此不冲突。",
			})
		}

		// ⑨ 疑似残留网卡：不是错误（可能真在被别的工具使用），但会一直占着端口
		if len(f.Net.ForeignInterfaces) > 0 {
			names := make([]string, 0, len(f.Net.ForeignInterfaces))
			for _, fi := range f.Net.ForeignInterfaces {
				item := fi.Name
				if fi.ListenPort > 0 {
					item += fmt.Sprintf("（占用端口 %d）", fi.ListenPort)
				}
				names = append(names, item)
			}
			out = append(out, InspectItem{
				Key: "foreign", Level: InspectWarning,
				Title:  fmt.Sprintf("发现 %d 个疑似残留网卡", len(f.Net.ForeignInterfaces)),
				Detail: strings.Join(names, "、") + " 不是本应用创建的，会占用它们监听中的端口。",
				Fix:    "确认不是别的工具在用之后，到「系统维护」清理。",
				To:     "maintenance",
			})
		} else {
			out = append(out, InspectItem{
				Key: "foreign", Level: InspectOK,
				Title:  "没有发现不属于本应用的 WireGuard 网卡",
				Detail: "内核里存在的加密网络网卡都由本应用管理。",
			})
		}

		// ⑩ 还没填对外访问地址：二维码里的地址在外网用不了
		if f.Net.DNS.Enabled && len(f.Net.DNS.Listen) == 0 {
			note := f.Net.DNS.Note
			if note == "" {
				note = "当前没有可用的隧道地址：请确认至少有一条连接已启用并正常工作。"
			}
			out = append(out, InspectItem{
				Key: "dns", Level: InspectWarning,
				Title:  "「内网域名解析」已开启，但还没真正生效",
				Detail: note,
				Fix:    "确认连接已启用且正常工作；本应用每 10 秒会自动重试，也可到「系统维护」点「立即应用」。",
				To:     "settings",
			})
		} else if f.Net.DNS.Enabled {
			out = append(out, InspectItem{
				Key: "dns", Level: InspectOK,
				Title:  "内网域名解析正在工作",
				Detail: fmt.Sprintf("已在 %s 监听，已加载 %d 条记录。", strings.Join(f.Net.DNS.Listen, "、"), f.Net.DNS.Records),
			})
		}
	}

	if ov := f.Ov; ov != nil && f.OvErr == "" {
		if ov.InterfaceCount > 0 && strings.TrimSpace(ov.ServerEndpoint) == "" {
			out = append(out, InspectItem{
				Key: "endpoint", Level: InspectWarning,
				Title:  "还没有填写「对外访问地址」",
				Detail: "手机在外网需要一个能连回家的地址，现在生成的二维码只在内网可用。",
				Fix:    "到「系统设置 → 接入设置」填写家里的公网域名或 IP。",
				To:     "settings",
			})
		} else if ov.InterfaceCount > 0 {
			out = append(out, InspectItem{
				Key: "endpoint", Level: InspectOK,
				Title:  "对外访问地址已填写",
				Detail: "二维码里带的是这个地址，手机在外网也能连回来。",
			})
		}
	}

	// ⑪ 通知配了但发不出去：这类故障完全静默（用户以为配好了在等消息）。
	if nt := f.Notify; nt.Configured {
		switch {
		case nt.Problem != "":
			out = append(out, InspectItem{
				Key: "notify", Level: InspectWarning,
				Title:  "通知地址无法使用",
				Detail: "配置的通知地址有问题：" + nt.Problem,
				Fix:    "到「系统设置 → 事件通知」修正地址后点「发送测试通知」验证。",
				To:     "settings",
			})
		case nt.Last != nil && !nt.Last.OK:
			out = append(out, InspectItem{
				Key: "notify", Level: InspectWarning,
				Title:  "通知发送失败",
				Detail: fmt.Sprintf("最近一次尝试（%s）未送达：%s", nt.Last.At.Format("2006-01-02 15:04"), nt.Last.Message),
				Fix:    "确认通知地址可访问、令牌未过期，然后到「系统设置 → 事件通知」点「发送测试通知」重试。",
				To:     "settings",
			})
		default:
			out = append(out, InspectItem{
				Key: "notify", Level: InspectOK,
				Title:  "通知可以正常发送",
				Detail: "通知地址可用，最近一次投递没有报错。",
			})
		}
	}

	// ⑫ 计划备份：开关开着但最近一次失败，是「看着有备份、其实没有」——
	//     这类状态等真要用备份那天才发现，代价最大，所以报成 error 而不是 warning。
	if f.BackupEnabled {
		switch {
		case f.BackupLast == nil:
			out = append(out, InspectItem{
				Key: "backup", Level: InspectWarning,
				Title:  "计划备份还没成功执行过",
				Detail: "开关是打开的，但还没有任何一次执行记录。",
				Fix:    "到「系统设置 → 备份还原 → 计划备份」点「立即执行一次」验证一次。",
				To:     "settings",
			})
		case !f.BackupLast.OK:
			at := f.BackupLast.At.Format("2006-01-02 15:04")
			out = append(out, InspectItem{
				Key: "backup", Level: InspectError,
				Title:  "计划备份最近一次没有成功",
				Detail: fmt.Sprintf("最近一次执行（%s）失败：%s", at, f.BackupLast.Error),
				Fix:    "到「系统设置 → 备份还原 → 计划备份」查看原因并点「立即执行一次」重试。",
				To:     "settings",
			})
		default:
			detail := fmt.Sprintf("最近一次（%s）成功", f.BackupLast.At.Format("2006-01-02 15:04"))
			if f.BackupLast.File != "" {
				detail += "：" + f.BackupLast.File
			}
			out = append(out, InspectItem{
				Key: "backup", Level: InspectOK,
				Title:  "计划备份正常",
				Detail: detail + "。",
			})
		}
	}
	return out
}

// countReport 统计一份报告里各等级的条数。
func countReport(items []InspectItem) (errors, warnings, passed int) {
	for _, it := range items {
		switch it.Level {
		case InspectError:
			errors++
		case InspectWarning:
			warnings++
		default:
			passed++
		}
	}
	return errors, warnings, passed
}

// lanAccessConfigured 判断「有没有连接打开了内网访问 / 设备间隔离」。
//
// 概览没读到（Ov 为 nil）时返回 true/true：宁可多检查一项，也不要因为读不到状态
// 就把一个真的开着却没有生效的规则放过 —— 那类故障用户完全看不见。
func lanAccessConfigured(ov *Overview) (lanOn, isolateOn bool) {
	if ov == nil {
		return true, true
	}
	for _, it := range ov.Interfaces {
		if !it.Enabled {
			continue
		}
		if it.AllowLAN {
			lanOn = true
		}
		if it.IsolatePeers {
			isolateOn = true
		}
	}
	return lanOn, isolateOn
}

// enabledInterfaceCount 统计已启用的连接数（概览没读到时为 0）。
func enabledInterfaceCount(ov *Overview) int {
	if ov == nil {
		return 0
	}
	n := 0
	for _, it := range ov.Interfaces {
		if it.Enabled {
			n++
		}
	}
	return n
}

// backendLabel 把后端类型翻译成用户能懂的说法。
func backendLabel(b string) string {
	switch b {
	case "kernel":
		return "标准模式（内核加速）"
	case "userspace":
		return "兼容模式（用户态实现）"
	case "mock":
		return "演示模式（内存实现）"
	}
	return b
}

// inspectUptime 把秒数写成便于阅读的运行时长。
func inspectUptime(sec int64) string {
	if sec <= 0 {
		return "刚刚启动"
	}
	d := time.Duration(sec) * time.Second
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf("%d 天 %d 小时", int(d.Hours())/24, int(d.Hours())%24)
	case d >= time.Hour:
		return fmt.Sprintf("%d 小时 %d 分钟", int(d.Hours()), int(d.Minutes())%60)
	case d >= time.Minute:
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
	return "不到 1 分钟"
}

// ------------------------------------------------------------------ 执行与留痕

// RunInspectIfDue 到点则巡检一次，供代理进程的定时循环调用。
//
// 返回「是否执行、是否正常、一句话结论」三个原始值：调用方是收敛引擎，
// 它不该为了收一个结果去依赖本包的类型（与计划备份同一条约定）。
// ok 只反映**错误级**结论：警告不推送（否则每天一条同样的提醒，很快会被用户屏蔽，
// 那比不推更糟），但仍然留在报告里等用户来看。
func (s *Service) RunInspectIfDue(ctx context.Context, now time.Time) (ran, ok bool, reason string) {
	plan := LoadInspectPlan(ctx, s.Store)
	if !plan.Enabled {
		return false, false, ""
	}
	var lastAt time.Time
	if last := loadLatestInspectReport(ctx, s.Store); last != nil {
		lastAt = last.At
	}
	if !plan.Schedule.Due(now, lastAt, loadInspectSince(ctx, s.Store)) {
		return false, false, ""
	}
	rep := s.runInspect(ctx, plan, now, false, Actor{Username: "system"})
	return true, rep.Errors == 0, inspectSummary(*rep)
}

// RunInspectNow 立刻巡检一次（界面上点「立即巡检一次」），不看日程。
//
// 与按日程那一路落在同一个进程、同一个函数：巡检的判定与写入只有一条路径，
// 不会一边按 A 判、一边按 B 做（计划备份在这一点上栽过两轮，见 ROADMAP）。
func (s *Service) RunInspectNow(ctx context.Context, userID int64, username, srcIP string) (ok bool, errors, warnings int, reason string) {
	a := Actor{UserID: userID, Username: username, SrcIP: srcIP}
	if strings.TrimSpace(a.Username) == "" {
		a.Username = "system"
	}
	plan := LoadInspectPlan(ctx, s.Store)
	rep := s.runInspect(ctx, plan, time.Now(), true, a)
	return rep.Errors == 0, rep.Errors, rep.Warnings, inspectSummary(*rep)
}

// runInspect 执行一次巡检：判定 → 写报告 → 记日志与审计。
//
// 不返回 error：调用方（界面按钮、定时循环）要的是「这次查出了什么」，
// 而它同时要落到报告里给用户看 —— 与计划备份同一条理由：原因放进结果，
// 比让调用方事后再查一遍更不容易漏。
func (s *Service) runInspect(ctx context.Context, plan InspectPlan, now time.Time, manual bool, a Actor) *InspectReport {
	// 顺带把内网设备入账：台账与「多久巡检一次」保持一致，不另外加定时器
	s.recordAssets(ctx)
	items := judgeInspect(s.inspectFacts(ctx))
	rep := &InspectReport{At: now, Manual: manual, Items: items}
	rep.Errors, rep.Warnings, rep.Passed = countReport(items)
	if err := saveInspectReport(ctx, s.Store, plan, rep); err != nil {
		s.Log.Warn("保存巡检报告失败", "err", err)
	}
	summary := inspectSummary(*rep)
	if rep.Errors > 0 {
		s.Log.Warn("巡检发现需要处理的问题", "errors", rep.Errors, "warnings", rep.Warnings)
		_ = s.Store.AddLog(ctx, "warn", "inspect", "巡检发现需要处理的问题", summary)
		s.auditInspect(ctx, a, "inspect.run", "fail", summary)
		return rep
	}
	s.Log.Info("巡检完成", "passed", rep.Passed, "warnings", rep.Warnings)
	_ = s.Store.AddLog(ctx, "info", "inspect", "巡检完成", summary)
	s.auditInspect(ctx, a, "inspect.run", "ok", summary)
	return rep
}

// inspectSummary 用一句话概括这次巡检（日志、审计、通知正文都用它）。
func inspectSummary(rep InspectReport) string {
	if rep.Errors == 0 && rep.Warnings == 0 {
		return fmt.Sprintf("检查 %d 项，全部正常", len(rep.Items))
	}
	parts := make([]string, 0, 3)
	for _, it := range rep.Items {
		if it.Level != InspectError {
			continue
		}
		parts = append(parts, it.Title)
		if len(parts) == 3 {
			break
		}
	}
	head := ""
	if len(parts) > 0 {
		head = "：" + strings.Join(parts, "；")
	}
	return fmt.Sprintf("检查 %d 项，%d 项需要处理、%d 项待确认%s", len(rep.Items), rep.Errors, rep.Warnings, head)
}

// saveInspectReport 追加一份报告，并按保留份数裁掉最旧的。
func saveInspectReport(ctx context.Context, st *store.Store, plan InspectPlan, rep *InspectReport) error {
	reports := append([]InspectReport{*rep}, loadInspectReports(ctx, st)...)
	if keep := plan.Keep; keep >= MinInspectKeep && len(reports) > keep {
		reports = reports[:keep]
	}
	raw, err := json.Marshal(reports)
	if err != nil {
		return err
	}
	return st.SetSetting(ctx, SettingInspectReports, string(raw))
}

// loadInspectReports 读取历史报告（新的在前）；没记录过或内容坏了都返回空。
//
// 历史报告不是关键数据，坏掉时退回「没有历史」即可 ——
// 一份读不出来的旧报告不该让整个巡检页变成错误。
func loadInspectReports(ctx context.Context, st *store.Store) []InspectReport {
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingInspectReports, ""))
	if raw == "" {
		return nil
	}
	var out []InspectReport
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// loadLatestInspectReport 读取最近一次报告；没跑过返回 nil。
func loadLatestInspectReport(ctx context.Context, st *store.Store) *InspectReport {
	reports := loadInspectReports(ctx, st)
	if len(reports) == 0 {
		return nil
	}
	last := reports[0]
	return &last
}

// loadInspectSince 读取计划生效时间。
func loadInspectSince(ctx context.Context, st *store.Store) time.Time {
	n, err := strconv.ParseInt(strings.TrimSpace(st.GetSetting(ctx, SettingInspectSince, "")), 10, 64)
	if err != nil || n <= 0 {
		return time.Time{}
	}
	return time.Unix(n, 0)
}

// auditInspect 写一条审计。动作名统一以 inspect 开头，便于在审计页按对象筛选。
func (s *Service) auditInspect(ctx context.Context, a Actor, action, result, msg string) {
	if err := s.Store.AddAudit(ctx, &model.AuditEntry{
		UserID:     a.UserID,
		Username:   a.Username,
		SrcIP:      a.SrcIP,
		Action:     action,
		TargetType: "inspect",
		TargetID:   "drift",
		Result:     result,
		Message:    msg,
	}); err != nil {
		s.Log.Warn("写入审计失败", "err", err)
	}
}

// ------------------------------------------------------------------ 飞牛桌面入口的事实

// SettingGatewayLast 是飞牛桌面入口状态的存储键（见 SaveGatewayFact）。
const SettingGatewayLast = "gateway_last"

// gatewayFact 是界面进程记下的入口状态快照。
//
// At 只用于排障（「这个状态是什么时候记的」），判定不看它：
// 入口状态只在**变化时**才写一次，因此一个很久以前的 At 不代表状态是旧的。
type gatewayFact struct {
	At time.Time `json:"at"`
	model.GatewayEntry
}

// SaveGatewayFact 记录网关入口状态（由界面进程的入口守护协程调用）。
//
// 为什么要落库：入口 socket 只存在于界面进程里，代理进程判不了它；
// 而定期巡检跑在代理进程（它是「一定在跑」的那一个）。
// 把这条事实写进库里，报告才能既有这一项、又只有一份判定。
// 只在状态变化时写，平时没有额外开销。
func SaveGatewayFact(ctx context.Context, st *store.Store, entry model.GatewayEntry, at time.Time) {
	if st == nil {
		return
	}
	if prev, ok := LoadGatewayFact(ctx, st); ok &&
		prev.Configured == entry.Configured && prev.Ready == entry.Ready &&
		prev.Path == entry.Path && prev.Detail == entry.Detail && prev.Fix == entry.Fix {
		return
	}
	raw, err := json.Marshal(gatewayFact{At: at, GatewayEntry: entry})
	if err != nil {
		return
	}
	_ = st.SetSetting(ctx, SettingGatewayLast, string(raw))
}

// LoadGatewayFact 读取界面进程记下的入口状态；从没记过返回 false。
func LoadGatewayFact(ctx context.Context, st *store.Store) (model.GatewayEntry, bool) {
	if st == nil {
		return model.GatewayEntry{}, false
	}
	raw := strings.TrimSpace(st.GetSetting(ctx, SettingGatewayLast, ""))
	if raw == "" {
		return model.GatewayEntry{}, false
	}
	var f gatewayFact
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		return model.GatewayEntry{}, false
	}
	return f.GatewayEntry, true
}

// firstNonEmpty 返回第一个非空值（用于「取建议的跳转目标，缺省给个兜底」）。
func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
