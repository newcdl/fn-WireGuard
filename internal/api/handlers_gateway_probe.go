// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import "net/http"

// handleGatewayProbe 只读诊断：报告「这次请求从哪条通道来」以及「网关注入了哪些身份头」。
//
// 为什么要它：飞牛统一网关会给经网关转发的请求注入 X-Trim-Userid / X-Trim-Username /
// X-Trim-Isadmin（官方文档「统一网关 → 会话校验和用户 Header」）。但这几个头**在真机上是否真的存在、
// 取值是否符合预期、客户端伪造的同名头会不会被网关覆盖**，三件事都只能实测，推断不出来。
// 于是先做这个接口，把观察到的事实原样说出来，再决定后面怎么做 —— 它本身不参与任何权限判定。
//
// 三条约束（都不可省）：
//  1. 只有管理员（user.manage）能访问：它是用来核对身份的接口，不该人手一个；
//  2. **只有通道可信时才回显头的取值**（见 gatewayTrusted）：端口通道上的这些头一律是客户端自己塞的，
//     回显它们既无意义又会误导人；那里只报「看到了哪些同名头」，因为那正是「P1 必须自己剥掉它们」的证据；
//  3. 不回显任何别的请求头 —— 避免它变成一个「随便看请求内容」的探针。
func (s *Server) handleGatewayProbe(w http.ResponseWriter, r *http.Request) {
	peer := gatewayPeer(r)
	trusted := gatewayTrusted(r)

	channel := "port"
	if peer.Unix {
		channel = "socket"
	}

	// 端口通道上出现的身份头已在中间件里剥掉（见 stripUntrustedIdentityHeaders），
	// 这里读的是那一步留下的名字 —— 它同时是「伪造的头确实到了应用」与「我们确实剥了」的证据。
	stripped := strippedIdentityHeaders(r)
	if stripped == nil {
		stripped = []string{}
	}

	out := map[string]any{
		// socket = 请求由网关进程经 Unix Socket 递过来；port = 从端口直连。
		"channel":         channel,
		"channel_trusted": trusted,
		// 对端进程的用户 ID，以及「未获信任」的原因（仅日志与排障用）。
		"peer_uid":    peer.UID,
		"peer_detail": peer.Detail,
		// 桌面入口此刻是否真的可用（安装/升级脚本用的同一个判定）。
		"socket_ready": s.gatewaySocketReady(),
		// 只报名字、不报取值：端口通道上的这些头一律按伪造处理，已被中间件删除。
		"identity_headers_stripped": stripped,
	}
	if trusted {
		// 只有通道可信时才读值：这时它们才可能是网关注入的身份，值得核对。
		out["gateway_identity"] = map[string]any{
			"userid":   r.Header.Get("X-Trim-Userid"),
			"username": r.Header.Get("X-Trim-Username"),
			"isadmin":  r.Header.Get("X-Trim-Isadmin"),
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// channelOf 回报本次请求走的通道（登录页与诊断用）。
func channelOf(r *http.Request) string {
	if gatewayPeer(r).Unix {
		return "socket"
	}
	return "port"
}

// gatewayAvailable 表示「这次请求带着可用的飞牛身份」，即能不能免密进入。
//
// 它刻意只回答能不能，不透露身份内容：这个判定会出现在登录前就能读的 /auth/state 上，
// 那里不该有任何身份信息（是谁、是不是管理员都不该从这里漏出去）。
func gatewayAvailable(r *http.Request) bool {
	_, ok := gatewayIdentityIfTrusted(r)
	return ok
}
