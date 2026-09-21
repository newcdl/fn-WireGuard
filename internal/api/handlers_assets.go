// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import "net/http"

// handleAssets 返回内网资产台账（只读）。
func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.LANAssets(r.Context()))
}

// handleMarkAsset 把一台设备标记为已知（或取消），之后不再按新设备提醒。
func (s *Server) handleMarkAsset(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP    string `json:"ip"`
		Known bool   `json:"known"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.MarkAssetKnown(r.Context(), actorOf(r), in.IP, in.Known); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": in.IP, "known": in.Known})
}
