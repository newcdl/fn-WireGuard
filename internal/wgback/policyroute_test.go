// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import "testing"

// 策略路由「要不要补下发」的判定。
//
// 这一条以前只看状态文件的记录：记录在就整轮跳过。于是内核里那条 ip rule / 表内路由
// 被清掉之后（重启、系统网络服务重启、其它工具清理）永远补不回来 —— 异地组网静默失效，
// 界面与日志都正常（真机出现过「重启后组网断了、随便保存一下设备就恢复」）。
// 这里的用例把「记录 / 内核事实 / 核对是否可信」三种组合都钉死。
func TestPolicyRouteNeeded(t *testing.T) {
	cases := []struct {
		name     string
		recorded bool
		live     bool
		checked  bool
		want     bool
	}{
		{"记录在、内核也在：不动", true, true, true, false},
		{"记录在、内核里没了：必须补下发", true, false, true, true},
		{"没有记录、内核里也没有：下发", false, false, true, true},
		{"没有记录、但内核里有（外部已有同目标）：不重复下发", false, true, true, false},
		{"核对不可信、有记录：退回原行为（不动）", true, false, false, false},
		{"核对不可信、无记录：按无记录处理", false, false, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := PolicyRouteNeeded(c.recorded, c.live, c.checked); got != c.want {
				t.Fatalf("PolicyRouteNeeded(%v,%v,%v) = %v，期望 %v",
					c.recorded, c.live, c.checked, got, c.want)
			}
		})
	}
}

// TestPolicyRulePresent 规则核对：只认「同一个目标网段 + 同一个表号」。
func TestPolicyRulePresent(t *testing.T) {
	rules := []PolicyRuleView{
		{Dst: "", Table: 254}, // 系统里的非目标规则
		{Dst: "192.168.2.0/24", Table: PolicyTableID},
		{Dst: "192.168.3.0/24", Table: 100}, // 同目标但表号不同：不算
	}
	if !PolicyRulePresent(rules, "192.168.2.0/24", PolicyTableID) {
		t.Fatal("同一个目标网段 + 专用表应当算已存在")
	}
	if PolicyRulePresent(rules, "192.168.3.0/24", PolicyTableID) {
		t.Fatal("表号不同不该算已存在（否则会漏下发）")
	}
	if PolicyRulePresent(rules, "192.168.9.0/24", PolicyTableID) {
		t.Fatal("目标不同不该算已存在")
	}
	if PolicyRulePresent(nil, "192.168.2.0/24", PolicyTableID) {
		t.Fatal("读不到规则时应当算不存在（随后核对可信则由调用方处理）")
	}
}

// TestPolicyRoutePresent 路由核对：专用表里要有同目标的路由。
func TestPolicyRoutePresent(t *testing.T) {
	dsts := []string{"192.168.2.0/24", "192.168.3.0/24"}
	if !PolicyRoutePresent(dsts, "192.168.2.0/24") {
		t.Fatal("表内已有同目标路由，应当算存在")
	}
	if PolicyRoutePresent(dsts, "192.168.9.0/24") {
		t.Fatal("表内没有该目标路由，不该算存在")
	}
	if PolicyRoutePresent(nil, "192.168.2.0/24") {
		t.Fatal("空列表不该算存在")
	}
}

// TestNormalizedCIDR 归一化：带主机位的写法要与内核里那条路由的写法对得上，
// 否则核对会永远判成「不存在」，每轮收敛都重复下发。
func TestNormalizedCIDR(t *testing.T) {
	for _, in := range []string{"192.168.2.5/24", "192.168.2.0/24"} {
		if got := normalizedCIDR(in); got != "192.168.2.0/24" {
			t.Fatalf("%s 归一化应为 192.168.2.0/24，实际 %q", in, got)
		}
	}
	if got := normalizedCIDR(" 192.168.2.0/24 "); got != "192.168.2.0/24" {
		t.Fatalf("两侧空白应被忽略，实际 %q", got)
	}
	if got := normalizedCIDR("不是网段"); got != "" {
		t.Fatalf("非法写法应返回空串，实际 %q", got)
	}
}
