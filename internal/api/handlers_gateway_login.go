// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"net/http"

	"fnwg/internal/model"
)

// handleGatewayLogin 用飞牛身份换发一个普通会话（登录页那个「以飞牛账号 XXX 登录」按钮）。
//
// 为什么是「按钮」而不是自动进入：身份头每个请求都会带上，自动放行会让退出登录变成
// 「下一刻又被带进来」；而且显式点一次，用户清楚自己是用哪个身份进来的。
//
// 它同样只认通道可信的身份（见 gatewayIdentityIfTrusted）：端口通道上没有飞牛身份，
// 也就不存在凭它登录这回事。
func (s *Server) handleGatewayLogin(w http.ResponseWriter, r *http.Request) {
	id, ok := gatewayIdentityIfTrusted(r)
	if !ok {
		writeErr(w, http.StatusForbidden,
			"这次请求没有可用的飞牛身份：请从飞牛桌面点开本应用（用 IP:端口 打开时没有飞牛身份，请用账号密码登录）")
		return
	}
	step, err := s.svc.LoginAsGatewayUser(r.Context(), id.UID, id.Username, id.IsAdmin, r.UserAgent(), clientIP(r))
	if err != nil {
		// 例如「该账号已被停用」：这是管理员的明确决定，必须挡住并说清原因
		s.log.Info("飞牛账号未能登录", "uid", id.UID, "reason", err.Error(), "ip", clientIP(r))
		writeErr(w, http.StatusForbidden, err.Error())
		return
	}
	s.setSessionCookie(w, step.Token)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        step.User,
		"permissions": model.PermissionsOf(step.User.Role),
	})
}
