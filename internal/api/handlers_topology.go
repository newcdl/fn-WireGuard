// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import "net/http"

// handleTopology 返回当前网络拓扑的快照（只读，供「总览」与「我的连接」两页画图）。
//
// 只读接口，不触发任何下发改动；取不到的部分（例如代理不可用）由说明字段交代，
// 不报成 500 —— 图缺一块但有说明，比整页报错有用。
func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Topology(r.Context()))
}
