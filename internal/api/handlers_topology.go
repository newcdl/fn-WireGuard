// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"net/http"

	"fnwg/internal/service"
)

// handleTopology 返回当前网络拓扑的快照（只读，供「总览」与「我的连接」两页画图）。
//
// 只读接口，不触发任何下发改动；取不到的部分（例如代理不可用）由说明字段交代，
// 不报成 500 —— 图缺一块但有说明，比整页报错有用。
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Topology(r.Context()))
}

// handleDeviceKinds 返回可选的设备类型清单与已配置的记录（界面据此渲染下拉）。
func (s *Server) handleDeviceKinds(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"options": service.DeviceKindOptions,
		"records": s.svc.DeviceKindList(r.Context()),
	})
}

// handleSetDeviceKind 设置某台内网设备的类型（按 IP 记；传空 = 清除，回到自动判断）。
func (s *Server) handleSetDeviceKind(w http.ResponseWriter, r *http.Request) {
	var in struct {
		IP   string `json:"ip"`
		Kind string `json:"kind"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.SetDeviceKind(r.Context(), actorOf(r), in.IP, in.Kind); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"ip": in.IP, "kind": in.Kind})
}
