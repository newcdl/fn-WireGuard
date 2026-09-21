// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"testing"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/notify"
)

// 判定清单的穷举用例。
//
// 这份清单的价值全在「每一条都对」，而它最容易出的错是**该报的没报**：
// 用户看到一份「全部通过」的报告，就会以为真的没问题 —— 这比报错更危险。
// 因此做法是：先构造一份「处处正常」的事实并断言没有任何异常，
// 再逐项把某一处弄坏，断言恰好出现期望的那一条（key + 等级），
// 并且总数只多了这一条（漏报与误报都会被抓出来）。
func goodFacts() inspectFacts {
	at := time.Date(2026, 9, 20, 3, 30, 0, 0, time.Local)
	return inspectFacts{
		Now: at,
		Health: model.Health{
			AgentUp: true, AgentVersion: "test", Backend: "kernel",
			KernelModule: true, TunDevice: true, UptimeSec: 7200,
		},
		Net: &NetworkCheckResult{
			Healthy:           true,
			ManagedInterfaces: []string{"wg0"},
			SystemDefaults:    []model.DefaultRoute{{Family: 4, Dev: "eth0", Gw: "192.168.1.1"}},
			StrayDefaults:     []model.DefaultRoute{},
			ForeignInterfaces: []model.ForeignInterface{},
			NAT: model.NATStatus{
				Active:        true,
				Sources:       []string{"10.10.0.0/24"},
				WANs:          []string{"eth0"},
				IPForward:     true,
				IsolateActive: true,
				IsolateNets:   []string{"10.10.0.0/24"},
				Checks: []model.NATCheck{
					{Key: "nft", Label: "转发规则", OK: true, Detail: "规则已就绪"},
					{Key: "isolate", Label: "设备间隔离", OK: true, Detail: "隔离规则已就绪"},
				},
			},
			DNS:          model.DNSStatus{Enabled: true, Listen: []string{"10.10.0.1:53"}, Records: 3},
			AccessIssues: []AccessIssue{},
			Messages:     []string{"本应用创建了 1 条连接（wg0）"},
		},
		Ov: &Overview{
			InterfaceCount: 1,
			ServerEndpoint: "nas.example.com:51820",
			Interfaces: []model.Interface{{
				ID: 1, Name: "wg0", Enabled: true, Up: true,
				// 两项功能都开着，才谈得上「有没有生效」（见 judgeInspect 第 ⑦ 段）
				AllowLAN: true, IsolatePeers: true,
			}},
		},
		Notify:        notify.Status{Configured: true},
		Gateway:       model.GatewayEntry{Configured: true, Ready: true, Path: "/tmp/gw.sock"},
		HasGateway:    true,
		BackupEnabled: true,
		BackupLast:    &BackupRunState{At: at.AddDate(0, 0, -1), OK: true, File: "fn-wireguard-backup-1.json"},
	}
}

// itemOf 取出某个 key 的结论。
func itemOf(items []InspectItem, key string) (InspectItem, bool) {
	for _, it := range items {
		if it.Key == key {
			return it, true
		}
	}
	return InspectItem{}, false
}

func TestJudgeInspectAllGood(t *testing.T) {
	items := judgeInspect(goodFacts())
	errs, warns, passed := countReport(items)
	if errs != 0 || warns != 0 {
		t.Fatalf("处处正常的事实不该报出异常：errors=%d warnings=%d items=%+v", errs, warns, items)
	}
	if passed != len(items) {
		t.Fatalf("通过项计数不对：passed=%d items=%d", passed, len(items))
	}
	// 每一项都必须有一条结论（含通过）：少一条就意味着那项检查根本没跑，
	// 而报告看起来仍然「全部通过」—— 这正是最危险的失败方式。
	for _, key := range []string{
		"agent", "kernel", "net", "gateway", "iface-down", "nat", "isolate",
		"access", "foreign", "dns", "endpoint", "notify", "backup",
	} {
		it, ok := itemOf(items, key)
		if !ok {
			t.Fatalf("缺少检查项 %q（报告会显示成「全部通过」）", key)
		}
		if it.Level != InspectOK {
			t.Fatalf("%s 在正常事实下应当是 ok，实际 %s：%s", key, it.Level, it.Detail)
		}
	}
}

func TestJudgeInspectProblems(t *testing.T) {
	cases := []struct {
		name   string
		break_ func(*inspectFacts)
		key    string
		level  string
		// gone 是「这条检查项应当整条消失」的 key（数据读不到时不假装通过）
		gone []string
	}{
		{
			name:   "后台服务没运行",
			break_: func(f *inspectFacts) { f.Health.AgentUp = false; f.Health.Error = "socket 不存在" },
			key:    "agent",
			level:  InspectError,
		},
		{
			name:   "内核模块没有、兼容模式可用",
			break_: func(f *inspectFacts) { f.Health.KernelModule = false },
			key:    "compat",
			level:  InspectWarning,
		},
		{
			name:   "内核模块与兼容模式都不可用",
			break_: func(f *inspectFacts) { f.Health.KernelModule = false; f.Health.TunDevice = false },
			key:    "kernel",
			level:  InspectError,
		},
		{
			name: "系统默认路由被本应用占用",
			break_: func(f *inspectFacts) {
				f.Net.StrayDefaults = []model.DefaultRoute{{Family: 4, Dev: "wg0"}}
				f.Net.Healthy = false
			},
			key:   "net",
			level: InspectError,
		},
		{
			name:   "桌面入口没就绪",
			break_: func(f *inspectFacts) { f.Gateway.Ready = false; f.Gateway.Detail = "socket 在但没人监听" },
			key:    "gateway",
			level:  InspectError,
		},
		{
			name:   "已启用的连接没工作",
			break_: func(f *inspectFacts) { f.Ov.Interfaces[0].Up = false },
			key:    "iface-down",
			level:  InspectError,
		},
		{
			name: "内网访问某一层没过",
			break_: func(f *inspectFacts) {
				f.Net.NAT.Checks = append(f.Net.NAT.Checks,
					model.NATCheck{Key: "wan", Label: "出口网卡", OK: false, Detail: "探测不到", Fix: "到「连接」里选择出口网卡"})
			},
			key:   "nat",
			level: InspectWarning,
		},
		{
			name: "设备间隔离没生效",
			break_: func(f *inspectFacts) {
				f.Net.NAT.Checks[1] = model.NATCheck{Key: "isolate", Label: "设备间隔离", OK: false, Detail: "规则未生效", Fix: "点重新应用"}
			},
			key:   "isolate",
			level: InspectWarning,
		},
		{
			name: "访问控制配置互相矛盾",
			break_: func(f *inspectFacts) {
				f.Net.AccessIssues = []AccessIssue{{Key: "scope", Title: "通行范围与隔离冲突", Detail: "10.10.0.0/24 同时被放行与隔离", Fix: "取消其中一个"}}
			},
			key:   "access:scope:0",
			level: InspectWarning,
		},
		{
			name: "疑似残留网卡",
			break_: func(f *inspectFacts) {
				f.Net.ForeignInterfaces = []model.ForeignInterface{{Name: "wg9", ListenPort: 51820}}
			},
			key:   "foreign",
			level: InspectWarning,
		},
		{
			name:   "没填对外地址",
			break_: func(f *inspectFacts) { f.Ov.ServerEndpoint = "" },
			key:    "endpoint",
			level:  InspectWarning,
		},
		{
			name:   "通知地址本身有问题",
			break_: func(f *inspectFacts) { f.Notify.Problem = "不是合法的 http(s) 地址" },
			key:    "notify",
			level:  InspectWarning,
		},
		{
			name: "通知最近一次投递失败",
			break_: func(f *inspectFacts) {
				f.Notify.Last = &notify.Result{OK: false, Message: "连接超时", At: f.Now}
			},
			key:   "notify",
			level: InspectWarning,
		},
		{
			name:   "域名解析开了但没监听",
			break_: func(f *inspectFacts) { f.Net.DNS.Listen = []string{}; f.Net.DNS.Note = "没有可用的隧道地址" },
			key:    "dns",
			level:  InspectWarning,
		},
		{
			name:   "计划备份最近一次失败",
			break_: func(f *inspectFacts) { f.BackupLast.OK = false; f.BackupLast.Error = "目标目录不可写" },
			key:    "backup",
			level:  InspectError,
		},
		{
			name:   "计划备份开着但还没跑过",
			break_: func(f *inspectFacts) { f.BackupLast = nil },
			key:    "backup",
			level:  InspectWarning,
		},
		{
			name:   "网络自检读不到",
			break_: func(f *inspectFacts) { f.Net = nil; f.NetErr = "后台服务没有响应" },
			key:    "net-unreadable",
			level:  InspectWarning,
			// 数据没读到就不能假装通过：依赖它的检查项整条消失，
			// 而不是留下一堆「正常」把用户骗过去。
			gone: []string{"net", "nat", "isolate", "foreign", "dns"},
		},
		{
			name:   "连接状态读不到",
			break_: func(f *inspectFacts) { f.Ov = nil; f.OvErr = "读取概览失败" },
			key:    "ov-unreadable",
			level:  InspectWarning,
			gone:   []string{"iface-down", "endpoint"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := goodFacts()
			c.break_(&f)
			items := judgeInspect(f)

			it, ok := itemOf(items, c.key)
			if !ok {
				t.Fatalf("应当报出 %q，实际只有 %+v", c.key, keysOf(items))
			}
			if it.Level != c.level {
				t.Fatalf("%s 的等级应当是 %s，实际 %s（%s）", c.key, c.level, it.Level, it.Detail)
			}
			if it.Title == "" || it.Detail == "" {
				t.Fatalf("%s 缺标题或事实说明：%+v", c.key, it)
			}
			// 警告与错误都要给出一条能照着做的建议
			if it.Fix == "" {
				t.Fatalf("%s 没有给出处理建议", c.key)
			}
			for _, key := range c.gone {
				if _, still := itemOf(items, key); still {
					t.Fatalf("%q 在数据读不到时不该出现（会造成假通过）", key)
				}
			}
			// 除了这一条，其余项仍然正常 —— 一条故障不该把整份报告染红
			errs, warns, _ := countReport(items)
			if c.level == InspectError && errs != 1 {
				t.Fatalf("错误项数不对：%d（items=%+v）", errs, keysOf(items))
			}
			if c.level == InspectWarning && (warns != 1 || errs != 0) {
				t.Fatalf("警告项数不对：warns=%d errs=%d（items=%+v）", warns, errs, keysOf(items))
			}
		})
	}
}

// TestJudgeInspectDemoMode 演示模式（内存后端）不参与「内核能力」的判断。
//
// 它既不碰内核也不碰网卡，能力位必然报「无模块、无 TUN」——
// 照真实口径就会得到一条永远成立、却毫无意义的结论，还会让开发环境常驻红点。
func TestJudgeInspectDemoMode(t *testing.T) {
	f := goodFacts()
	f.Health.Backend = "mock"
	f.Health.KernelModule = false
	f.Health.TunDevice = false
	it, ok := itemOf(judgeInspect(f), "kernel")
	if !ok || it.Level != InspectOK {
		t.Fatalf("演示模式下不该报内核能力问题：%+v", it)
	}
	if _, compat := itemOf(judgeInspect(f), "compat"); compat {
		t.Fatal("演示模式下不该出现「正在使用兼容模式」")
	}
}

// TestJudgeInspectSkipsInactiveFeatures 没开的开关不该产生「待确认」。
//
// 后端在内网访问没被任何连接启用时，仍会给出「尚未下发：没有打开内网访问开关的连接」
// 这类检查项。若一律当成问题，报告里就会长期挂着一条「已开启，但还没真正生效」——
// 而用户什么都没开。定期报告最怕这种噪音：它一旦开始说无用的话，就没人再看了。
func TestJudgeInspectSkipsInactiveFeatures(t *testing.T) {
	f := goodFacts()
	// 两项功能都没开，而后端照旧给出「未下发」的检查项
	f.Ov.Interfaces[0].AllowLAN = false
	f.Ov.Interfaces[0].IsolatePeers = false
	f.Net.NAT.Active = false
	f.Net.NAT.IsolateActive = false
	f.Net.NAT.IsolateNets = nil
	f.Net.NAT.Checks = []model.NATCheck{
		{Key: "rules", Label: "转发规则", OK: false, Detail: "尚未下发：没有已启用且打开了「内网访问」开关的连接"},
		{Key: "isolate", Label: "设备间隔离", OK: false, Detail: "尚未下发：没有已启用且打开了「设备间隔离」开关的连接"},
	}

	items := judgeInspect(f)
	for _, key := range []string{"nat", "isolate"} {
		if it, ok := itemOf(items, key); ok {
			t.Fatalf("没开的功能不该报出 %q：%s / %s", key, it.Title, it.Detail)
		}
	}
	if errs, warns, _ := countReport(items); errs != 0 || warns != 0 {
		t.Fatalf("没开的功能不该产生待确认项：errs=%d warns=%d（%+v）", errs, warns, keysOf(items))
	}
}

// TestJudgeInspectKeepsRealNatProblem 真开着却没生效时必须报出来（别把上面那条修过头）。
func TestJudgeInspectKeepsRealNatProblem(t *testing.T) {
	f := goodFacts()
	f.Net.NAT.Checks = append(f.Net.NAT.Checks,
		model.NATCheck{Key: "rules", Label: "转发规则", OK: false, Detail: "规则内容与期望一致但内核里查不到（可能被其它工具清理过）", Fix: "点「立即应用」重新下发"})

	it, ok := itemOf(judgeInspect(f), "nat")
	if !ok || it.Level != InspectWarning {
		t.Fatalf("开着却未生效的内网访问必须报出来：%+v", it)
	}
	if it.Detail == "" || it.Fix == "" {
		t.Fatalf("报出来就要说清事实与处置：%+v", it)
	}
}

func keysOf(items []InspectItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Key+"="+it.Level)
	}
	return out
}
