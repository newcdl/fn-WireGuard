// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import "net/http"

// handleStepUp 完成一次步进验证（敏感操作前的二次验证），见 service/stepup.go 的开关。
//
// 它服务的是「凭飞牛身份免密进来」的会话：那种会话没有登录那一刻的凭据校验，
// 所以敏感操作前再验一次动态口令。端口通道（账号密码登录）不需要走这里。
func (s *Server) handleStepUp(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	var in struct {
		Code string `json:"code"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.VerifyStepUp(r.Context(), u, in.Code); err != nil {
		// 失败的尝试留痕（只记账号与原因，绝不记验证码本身）
		s.log.Info("步进验证未通过", "user", u.Username, "reason", err.Error(), "ip", clientIP(r))
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
