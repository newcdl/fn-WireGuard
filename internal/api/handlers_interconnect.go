// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"net/http"

	"fnwg/internal/service"
)

// interconnectImportRequest 是导入互联邀请的请求体。
//
// 收的是「用户粘贴的文本」而不是结构化对象：用户拿到的是对方发来的一个文件/一段文本，
// 由后端去解析与校验，报错信息也就能直接照原样显示（哪一项不对、为什么不对）。
type interconnectImportRequest struct {
	Text string `json:"text"`
}

// handleCreateInterconnect 生成一份互联邀请：本端建好连接与对端条目，并返回要交给对方的文件。
func (s *Server) handleCreateInterconnect(w http.ResponseWriter, r *http.Request) {
	var in service.InterconnectInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.svc.CreateInterconnect(r.Context(), in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleImportInterconnect 导入对方发来的互联邀请。
//
// 校验不通过一律 400 并把原因原样回给界面：这些原因（网段撞车、公钥重复、隧道网段冲突）
// 都是用户当场能处理的事，报成 500 只会让人以为「服务器坏了」。
func (s *Server) handleImportInterconnect(w http.ResponseWriter, r *http.Request) {
	var req interconnectImportRequest
	if err := decodeBody(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	inv, err := service.ParseInterconnectInvite([]byte(req.Text))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.svc.ImportInterconnect(r.Context(), inv, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
