// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"fnwg/internal/service"
	"fnwg/internal/traffic"
)

// handleTrafficReport 返回近 N 天的流量报表。
func (s *Server) handleTrafficReport(w http.ResponseWriter, r *http.Request) {
	days := atoiDefault(r.URL.Query().Get("days"), service.DefaultReportDays)
	rep, err := s.svc.TrafficReport(r.Context(), days)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// handleTrafficExport 把报表导出为 CSV。
//
// 直接由浏览器下载（前端用一个普通链接打开这个地址），因此返回的是文件内容而不是 JSON：
// 走 fetch 再在前端拼 Blob 也做得到，但那样几十万行的表格要先整个读进内存再复制一遍。
func (s *Server) handleTrafficExport(w http.ResponseWriter, r *http.Request) {
	days := atoiDefault(r.URL.Query().Get("days"), service.DefaultReportDays)
	body, err := s.svc.TrafficCSV(r.Context(), days)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	name := fmt.Sprintf("wireguard-traffic-%s.csv", time.Now().Format("20060102"))
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = io.WriteString(w, body)
}

// handleSetTrafficRetention 调整流量明细的保留天数。
func (s *Server) handleSetTrafficRetention(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Days int `json:"days"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.SetTrafficRetentionDays(r.Context(), in.Days, actorOf(r)); err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, traffic.ErrInvalidRetention) {
			status = http.StatusBadRequest
		}
		writeErr(w, status, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"retention_days": in.Days})
}
