// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package wgback

import (
	"net"
	"strings"
)

// 本文件定义异地组网（本机需要主动访问对端内网）时的路由下发方式。
//
// 核心约束：绝不修改飞牛系统的路由表。
// 因此这里不使用主路由表（main / table 254），而是：
//  1. 把路由写进本应用专用的策略路由表（table PolicyTableID）；
//  2. 对「目标网段」加一条 ip rule 指向该表。
//
// 生效方式（以对端内网 192.168.5.0/24 为例）：
//
//	ip rule  add to 192.168.5.0/24 lookup 51888 priority 20000
//	ip route add 192.168.5.0/24 dev wg200 table 51888
//
// 效果：
//   - `ip route show`、`ip route show default` 与安装前完全一致，主表零改动；
//   - FN Connect、应用市场、系统更新等系统流量的目标不在这些网段内，完全不受影响；
//   - 只有「目的地确实是对端内网」的流量才会去查专用表并被送进隧道；
//   - 撤销 ip rule 后专用表立即失效（规则指向空表时会自然落回主表），
//     所以停用/卸载只需删掉自己的 rule 与表内路由，不会留下影响系统的残留。
//
// 这样做的好处是：异地组网能用，而 NAS 自身的上网路线在整个生命周期里
// 从未被本应用改动过哪怕一条。

const (
	// PolicyTableID 是本应用专用的策略路由表号，不会出现在系统主表里。
	PolicyTableID = 51888
	// policyRulePriority 是规则优先级：取值介于系统规则与 main 表（32766）之间，
	// 保证只对指定目标网段生效、且不影响系统规则的判定顺序。
	policyRulePriority = 20000
)

// PolicyRoute 是一条写入专用策略表的路由及其配套规则。
type PolicyRoute struct {
	// Dev 归属的连接名（接口名），用于按连接清理。
	Dev string `json:"dev"`
	// CIDR 目标网段。
	CIDR string `json:"cidr"`
	// Table 目标表号。
	Table int `json:"table"`
	// Family 协议族：4 或 6（netlink 常量在 linux.go 中映射）。
	Family int `json:"family"`
}

// PlanPolicyRoutes 把 PlanRoutes 的结论转换为待下发的策略路由清单。
//
// 注意：PlanRoutes 的 Add 已经在纯函数里过了全部安全红线，
// 这里只负责补上「落到专用表」这个属性。
func PlanPolicyRoutes(dev string, plan RoutePlan) []PolicyRoute {
	out := make([]PolicyRoute, 0, len(plan.Add))
	for _, cidr := range plan.Add {
		_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		out = append(out, PolicyRoute{
			Dev:    dev,
			CIDR:   n.String(),
			Table:  PolicyTableID,
			Family: ipFamily(n.IP),
		})
	}
	return out
}

// ipFamily 返回 4 或 6。
func ipFamily(ip net.IP) int {
	if ip.To4() != nil {
		return 4
	}
	return 6
}

// PolicyRuleView / PolicyRouteView 是内核里的 ip rule 与路由的关键字段。
//
// 刻意不用 netlink 的类型：核对逻辑要能在任何平台上被用例穷举（本项目的一贯做法：
// 判定留在纯函数里，netlink 只在 Linux 侧做取数与落地）。
type PolicyRuleView struct {
	// Dst 是规则的目标网段（空串表示非目标规则）。
	Dst string
	// Table 是规则指向的表号。
	Table int
}

// PolicyRouteNeeded 判断一条策略路由是否需要（重新）下发。
//
// 三个输入：状态文件里有没有记录、内核里是否确实还在、这次核对是否可信。
//
//   - 核对不可信（读内核失败）时退回「按记录判断」——宁可少动一次，也不无脑重加；
//   - 核对可信时**只看内核**：记录还在、内核里没了就补下发。
//
// 为什么不能只信记录：ip rule 与专用表里的路由都是内核状态，重启、系统网络服务重启、
// 其它网络工具清理都会让它们消失，而状态文件里的记录还在。只信记录就永远不会补回来，
// 于是现象是「异地组网直接不通、或时通时不通」，而界面与日志看上去一切正常
// （nft 的转发规则早就按内核现状核对过，策略路由这一路当时漏了）。
func PolicyRouteNeeded(recorded, live, checked bool) bool {
	if !checked {
		return !recorded
	}
	return !live
}

// PolicyRulePresent 判断内核返回的规则列表里是否已有「目标网段 → 专用表」这条规则。
func PolicyRulePresent(rules []PolicyRuleView, cidr string, table int) bool {
	for _, r := range rules {
		if r.Table == table && r.Dst == cidr {
			return true
		}
	}
	return false
}

// PolicyRoutePresent 判断内核返回的（指定表内）路由目标列表里是否已有该网段。
func PolicyRoutePresent(dsts []string, cidr string) bool {
	for _, d := range dsts {
		if d == cidr {
			return true
		}
	}
	return false
}

// normalizedCIDR 把网段写成归一化形式（去掉主机位）；非法写法返回空串。
//
// 核对时必须用它：配置里可能写成 192.168.2.5/24，而内核回读的是 192.168.2.0/24，
// 直接比字符串会永远判成「不存在」，于是每轮收敛都重复下发同一条规则。
func normalizedCIDR(cidr string) string {
	_, n, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return ""
	}
	return maskedCIDR(n)
}

// DescribePolicyRoutes 汇总策略路由，用于日志与界面展示。
func DescribePolicyRoutes(list []PolicyRoute) string {
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, 0, len(list))
	for _, p := range list {
		parts = append(parts, p.CIDR)
	}
	return strings.Join(parts, "、")
}
