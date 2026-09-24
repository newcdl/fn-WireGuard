// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package service

import (
	"fmt"
	"strings"

	"fnwg/internal/model"
)

// 设备级的内网访问范围（按设备限制内网目标）。
//
// 和「连接级开关」与「设备侧通行范围」的关系，一句话说清三者分别管什么：
//
//	连接级「允许设备访问家里内网」—— 这条连接里的设备**能不能**访问内网（总闸）；
//	设备侧的通行范围（client_allowed_ips）—— 设备把哪些流量送进隧道（**建议**，设备可以改）；
//	本文件这套（lan_policy + lan_targets）—— 这台设备进了隧道之后**实际能去哪**（服务端说了算）。
//
// 为什么必须有第三条：前两条都拦不住一个「不配合」的设备。设备侧配置只是发给它的建议，
// 它完全可以自己加一条路由把流量送进来；服务端规则是唯一说了算的那道。
//
// 默认值 inherit（随连接）保证升级不改变任何现有行为。

// normalizePeerLANAccess 校验并归一化设备的内网访问范围。
//
// 返回归一化后的策略与目标列表：
//   - 策略为空按 inherit 处理；
//   - inherit 与 deny 的目标一律清空（这两个取值下目标没有意义，留着只会让界面上显示一堆
//     用不上的东西，还容易让人以为「deny 也允许这些」）；
//   - restrict 必须至少有一个目标，且每个目标都要能被 model.ParseLANTarget 解析。
func normalizePeerLANAccess(policy string, targets []string) (string, []string, error) {
	switch strings.TrimSpace(policy) {
	case "", model.LANPolicyInherit:
		return model.LANPolicyInherit, []string{}, nil
	case model.LANPolicyDeny:
		return model.LANPolicyDeny, []string{}, nil
	case model.LANPolicyRestrict:
		// 继续往下校验目标
	default:
		return "", nil, fmt.Errorf("内网访问范围取值不正确（只能是随连接 / 只允许指定目标 / 不允许）")
	}

	out := []string{}
	seen := map[string]bool{}
	for _, raw := range targets {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		addr, port, err := model.ParseLANTarget(raw)
		if err != nil {
			return "", nil, fmt.Errorf("内网目标：%w", err)
		}
		key := model.LANTargetString(addr, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, key)
	}
	if len(out) == 0 {
		return "", nil, fmt.Errorf("选「只允许访问指定目标」时至少要填一个目标，例如 192.168.1.10 或 192.168.1.10:445")
	}
	return model.LANPolicyRestrict, out, nil
}
