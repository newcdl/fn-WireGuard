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
	// ListenPort 是本机这条连接要监听的 UDP 端口，0 = 自动分配。
	// 允许指定是因为「外部端口 ≠ 本机端口」很常见（路由器映射、内网穿透），
	// 与外部端口对不上时对端永远连不上，而现象只有「一直离线」。
	ListenPort int `json:"listen_port"`
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
	out, err := s.svc.ImportInterconnect(r.Context(), inv, req.ListenPort, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handlePreviewInterconnect 导入前的预检：把「将要建什么、会有什么后果」算出来给用户确认。
//
// 与 handleImportInterconnect 共用同一个请求体，前端因此可以把用户在对话框里填的监听端口
// 原样带过来 —— 预检给出的端口就是他最终会得到的那个，确认框里的话才有意义。
// 它是只读的：不落库、不下发，也不写审计。
func (s *Server) handlePreviewInterconnect(w http.ResponseWriter, r *http.Request) {
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
	out, err := s.svc.PreviewInterconnect(r.Context(), inv, req.ListenPort)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleInterconnectInvite 重现一份已生成的互联邀请。
//
// 权限按「查看密钥」同级校验：邀请里含对端连接的私钥与二次加密口令，
// 等同于把对方那条连接交出去；没有该权限的账号应当只能看到条目、看不到邀请。
func (s *Server) handleInterconnectInvite(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	out, err := s.svc.InterconnectInvite(r.Context(), id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
