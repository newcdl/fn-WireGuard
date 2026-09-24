// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"fmt"
	"net/http"
	"time"

	"fnwg/internal/service"
)

// handleBackupPlanStatus 返回计划备份的配置、最近一次结果与目标目录里的副本。
func (s *Server) handleBackupPlanStatus(w http.ResponseWriter, r *http.Request) {
	out := s.planRunner.Status(r.Context(), time.Now())
	s.attachDirInfo(r, out)
	writeJSON(w, http.StatusOK, out)
}

// attachDirInfo 向特权代理问一次目标目录的实况，合并进状态。
//
// 为什么要绕这一道：目标目录是用户授权给应用的共享文件夹，**只有代理（root）能可靠读写**，
// 界面进程（fnwg）连遍历都可能被拒。界面自己去探测，得到的结论与实际执行无关 ——
// 真机上先后撞过两次：一次「界面说不可写、按日程却写得好好的」，
// 一次「保存时检查通过、点另存才报权限不足」。事实只问做这件事的人。
//
// 代理问不到时不去猜：dir_ok 保持 false，并把原因写在 dir_note 里给用户看。
func (s *Server) attachDirInfo(r *http.Request, out *service.BackupPlanStatus) {
	if out.ResolvedDir == "" {
		return
	}
	info, err := s.svc.Core.InspectBackupDir(r.Context(), out.ResolvedDir)
	if err != nil {
		out.DirOK = false
		out.DirNote = "暂时无法确认目标目录（后台服务没有响应）：" + err.Error()
		return
	}
	out.DirOK = info.OK
	out.Files = info.Files
	if info.Note != "" {
		out.DirNote = info.Note
	}
}

// handleSaveBackupPlan 保存计划备份配置。
//
// 校验不通过（时刻写法不对、目标目录不存在或不可写）一律 400 并把原因原样回给界面：
// 这类错误是用户当场能改的，报成 500 只会让人以为「服务器坏了」。
func (s *Server) handleSaveBackupPlan(w http.ResponseWriter, r *http.Request) {
	var plan service.BackupPlan
	if err := decodeBody(r, &plan); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 启用前先让**真正执行写入的进程**确认目标目录可用：否则这个开关是「假打开」的 ——
	// 界面显示着「已开启 · 每天 03:30」，实际每天失败一次，而用户以为有备份。
	// 放在保存之前：不通过就不落库，界面上不会留下一个存着却跑不起来的配置。
	if plan.Enabled {
		target := s.planRunner.ResolveTarget(plan)
		info, err := s.svc.Core.InspectBackupDir(r.Context(), target)
		if err != nil {
			writeErr(w, http.StatusBadGateway,
				"后台服务没有响应，暂时无法确认目标目录："+err.Error())
			return
		}
		if !info.OK {
			note := info.Note
			if note == "" {
				note = "目标目录不可用"
			}
			writeErr(w, http.StatusBadRequest, note)
			return
		}
	}
	if err := s.planRunner.SavePlan(r.Context(), plan, time.Now(), actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out := s.planRunner.Status(r.Context(), time.Now())
	s.attachDirInfo(r, out)
	writeJSON(w, http.StatusOK, out)
}

// handleRunBackupPlan 立即执行一次计划备份。
//
// 执行交给**特权代理**，而不是界面进程自己写：目标目录是飞牛授权给应用的共享文件夹，
// 界面进程（fnwg）对它没有写权限 —— 自己写就会变成「保存检查通过、真写文件时被拒」，
// 用户看到的是「配置没问题，却总是失败」，而报错里的路径权限他又不知道从哪改。
//
// 执行结果（成功，或失败原因）都放在返回体里，不作为请求错误返回：
// 「这次没写进目标目录」是界面要显示的状态，而不是一个让用户重试的接口故障。
// 只有「代理本身没响应」才回请求错误。
func (s *Server) handleRunBackupPlan(w http.ResponseWriter, r *http.Request) {
	a := actorOf(r)
	res, err := s.svc.Core.RunBackupPlan(r.Context(), a.UserID, a.Username, a.SrcIP)
	if err != nil {
		writeErr(w, http.StatusBadGateway, "后台服务没有响应："+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDownloadPlanFile 下载目标目录里的一份副本。
func (s *Server) handleDownloadPlanFile(w http.ResponseWriter, r *http.Request) {
	plan := service.LoadBackupPlan(r.Context(), s.svc.Store)
	name := r.URL.Query().Get("name")
	// 由代理读：界面进程对授权目录可能连遍历都没有权限（真机上就是如此）
	raw, err := s.svc.Core.ReadBackupCopy(r.Context(), plan.Dir, name)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	_, _ = w.Write(raw)
}

// handleRestorePlanFile 用目标目录里的一份副本还原配置。
//
// 走「先导入成本地备份，再还原」两步：导入会把这份文件收进备份列表（可追溯、可重复使用），
// 还原则复用既有那条路径 —— 它已经处理了「还原前先给当前状态留一份」这类细节，
// 另写一条只会在边缘情况上慢慢跑偏。
func (s *Server) handleRestorePlanFile(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Note string `json:"note"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	plan := service.LoadBackupPlan(r.Context(), s.svc.Store)
	raw, err := s.svc.Core.ReadBackupCopy(r.Context(), plan.Dir, in.Name)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	note := in.Note
	if note == "" {
		note = "从计划备份的外部副本导入"
	}
	rec, err := s.svc.ImportBackup(r.Context(), s.shareDir, raw, in.Name, note, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	n, err := s.svc.RestoreBackup(r.Context(), s.shareDir, rec.ID, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored_interfaces": n, "backup_id": rec.ID})
}
