// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"net/http"
	"time"

	"fnwg/internal/service"
)

// handleInspectStatus 返回巡检计划、最近一次报告与历史报告。
//
// 只读库、不触发判定：报告是**定期巡检**的产物（由后台服务按日程写出），
// 界面要看的是「上次查出了什么」。而「此刻是什么状态」走 /system/inspect/checks ——
// 两件事混在一个接口里，会让这个只读接口在代理没响应时整个失败。
func (s *Server) handleInspectStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, service.InspectStatusOf(r.Context(), s.svc.Store, time.Now()))
}

// inspectChecksResult 是即时判定的返回体。
type inspectChecksResult struct {
	At    time.Time             `json:"at"`
	Items []service.InspectItem `json:"items"`
}

// handleInspectChecks 返回此刻的判定结论（不落库）。
//
// 顶栏与各页的异常清单读它：判定只有一份实现（在服务层，见 service.judgeInspect），
// 界面不再自己写一套 —— 否则「界面说正常、报告说异常」这类自相矛盾迟早会出现。
// 返回体里含通过项（ok），界面按等级过滤即可。
func (s *Server) handleInspectChecks(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, inspectChecksResult{
		At:    time.Now(),
		Items: s.svc.InspectChecks(r.Context()),
	})
}

// handleSaveInspectPlan 保存巡检计划。
//
// 校验不通过（时刻写法不对、保留份数越界）一律 400 并原样回原因：
// 这类错误用户当场就能改，报成 500 只会让人以为「服务器坏了」。
func (s *Server) handleSaveInspectPlan(w http.ResponseWriter, r *http.Request) {
	var plan service.InspectPlan
	if err := decodeBody(r, &plan); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.SaveInspectPlan(r.Context(), plan, time.Now(), actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 回最新的状态：界面拿到就能直接渲染，不必再请求一次。
	writeJSON(w, http.StatusOK, service.InspectStatusOf(r.Context(), s.svc.Store, time.Now()))
}

// handleRunInspect 立即巡检一次。
//
// 执行交给**特权代理**：巡检要读内核里的规则与路由，还要读通知与备份的状态；
// 判定也只有一份实现（就在代理进程里那个 Service 上），界面进程不自己判一遍。
// 与按日程那一路同一个实现、同一个进程，不会出现「界面说正常、报告说异常」两套口径。
//
// 结论放在返回体里，不作为请求错误返回：「这次查出了问题」是界面要显示的结果；
// 只有「代理本身没响应」才回请求错误 —— 那种情况用户重试或不重试自己会判断。
func (s *Server) handleRunInspect(w http.ResponseWriter, r *http.Request) {
	a := actorOf(r)
	if _, err := s.svc.Core.RunInspect(r.Context(), a.UserID, a.Username, a.SrcIP); err != nil {
		writeErr(w, http.StatusBadGateway, "后台服务没有响应："+err.Error())
		return
	}
	// 报告刚由代理写进库，直接回最新状态：界面拿到就能显示，不必再请求一次。
	writeJSON(w, http.StatusOK, service.InspectStatusOf(r.Context(), s.svc.Store, time.Now()))
}
