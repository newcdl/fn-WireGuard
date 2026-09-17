package api

import (
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// ---------------------------------------------------------------- 认证

func (s *Server) handleAuthState(w http.ResponseWriter, r *http.Request) {
	initialized, err := s.svc.HasUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := map[string]any{"initialized": initialized, "authenticated": false, "user": nil}
	if !initialized {
		writeJSON(w, http.StatusOK, out)
		return
	}
	if u, err := s.svc.Authenticate(r.Context(), extractToken(r)); err == nil {
		out["authenticated"] = true
		out["user"] = u
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.svc.Setup(r.Context(), in.Username, in.Password)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	token, _, err := s.svc.Login(r.Context(), in.Username, in.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	key := clientIP(r) + "|" + in.Username
	if s.loginBlocked(key) {
		writeErr(w, http.StatusTooManyRequests, "登录失败次数过多，请 5 分钟后再试")
		return
	}
	token, u, err := s.svc.Login(r.Context(), in.Username, in.Password, r.UserAgent(), clientIP(r))
	if err != nil {
		s.recordLoginFail(key)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.clearLoginFail(key)
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Logout(r.Context(), extractToken(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if u == nil {
		writeErr(w, http.StatusUnauthorized, "未登录")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        u,
		"permissions": model.PermissionsOf(u.Role),
		"version":     s.version,
	})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u := userOf(r)
	if err := s.svc.ChangePassword(r.Context(), u.ID, in.OldPassword, in.NewPassword, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "fnwg_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int((7 * 24 * time.Hour).Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: "fnwg_token", Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
	})
}

// ---------------------------------------------------------------- 概览与健康

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ov, err := s.svc.GetOverview(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, ov)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.Health(r.Context()))
}

// ---------------------------------------------------------------- NAS 系统网络安全

func (s *Server) handleNetworkCheck(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.CheckNetwork(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// handleDeleteForeignInterface 清理一个疑似残留的 WireGuard 网卡。
// 请求体需带 confirm（与 name 完全一致）作为二次确认。
func (s *Server) handleDeleteForeignInterface(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, "请求格式不正确")
		return
	}
	actions, err := s.svc.DeleteForeignInterface(r.Context(), in.Name, in.Confirm, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleNetworkRepair(w http.ResponseWriter, r *http.Request) {
	actions, err := s.svc.RepairNetwork(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleNetworkCleanup(w http.ResponseWriter, r *http.Request) {
	actions, err := s.svc.CleanupNetwork(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

func (s *Server) handleReconcile(w http.ResponseWriter, r *http.Request) {
	actions, err := s.svc.ReconcileNow(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": actions})
}

// ---------------------------------------------------------------- 通知（Webhook）

func (s *Server) handleNotifyStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.svc.NotifyStatus(r.Context()))
}

// handleNotifyTest 立即发送一条测试通知，让用户能在配置当场确认地址可用。
func (s *Server) handleNotifyTest(w http.ResponseWriter, r *http.Request) {
	res, err := s.svc.SendTestNotify(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// ---------------------------------------------------------------- 内网域名解析

func (s *Server) handleListDNSRecords(w http.ResponseWriter, r *http.Request) {
	items, err := s.svc.ListDNSRecords(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *Server) handleCreateDNSRecord(w http.ResponseWriter, r *http.Request) {
	var in service.DNSRecordInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.svc.CreateDNSRecord(r.Context(), in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleUpdateDNSRecord(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in service.DNSRecordInput
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.svc.UpdateDNSRecord(r.Context(), id, in, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleDeleteDNSRecord(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteDNSRecord(r.Context(), id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---------------------------------------------------------------- 审计与日志

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := model.AuditFilter{
		Username:   q.Get("username"),
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		Limit:      atoiDefault(q.Get("limit"), 100),
		Offset:     atoiDefault(q.Get("offset"), 0),
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}
	items, total, err := s.svc.ListAudit(r.Context(), f)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

func (s *Server) handleVerifyAudit(w http.ResponseWriter, r *http.Request) {
	ok, badID, err := s.svc.VerifyAudit(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"intact": ok, "first_broken_id": badID})
}

func (s *Server) handleListLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	items, total, err := s.svc.ListLogs(r.Context(), q.Get("level"), q.Get("scope"), q.Get("keyword"),
		atoiDefault(q.Get("limit"), 200), atoiDefault(q.Get("offset"), 0))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
}

// ---------------------------------------------------------------- 设置

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	kv, err := s.svc.GetSettings(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, kv)
}

func (s *Server) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	kv := map[string]string{}
	if err := decodeBody(r, &kv); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.SetSettings(r.Context(), kv, actorOf(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ---------------------------------------------------------------- 用户

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.svc.ListUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": users})
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	u, err := s.svc.CreateUser(r.Context(), in.Username, in.Password, in.Role, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, u)
}

func (s *Server) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in struct {
		Role     string `json:"role"`
		Status   *int   `json:"status"`
		Password string `json:"password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	status := -1
	if in.Status != nil {
		status = *in.Status
	}
	if err := s.svc.UpdateUser(r.Context(), id, in.Role, status, in.Password, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteUser(r.Context(), id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// ---------------------------------------------------------------- 备份

func (s *Server) handleListBackups(w http.ResponseWriter, r *http.Request) {
	items, err := s.svc.ListBackups(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "share_dir": s.shareDir})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Note string `json:"note"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	rec, err := s.svc.CreateBackup(r.Context(), s.shareDir, in.Note, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleDeleteBackup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.DeleteBackup(r.Context(), s.shareDir, id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
}

// handleDownloadBackup 下载一份备份文件（导出备份）。
func (s *Server) handleDownloadBackup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	raw, filename, err := s.svc.DownloadBackup(r.Context(), s.shareDir, id)
	if err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename="+url.QueryEscape(filename))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

// handleImportBackup 导入一份备份文件（备份 JSON 作为原始请求体）。
func (s *Server) handleImportBackup(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "读取上传内容失败: "+err.Error())
		return
	}
	rec, err := s.svc.ImportBackup(r.Context(), s.shareDir, raw, r.URL.Query().Get("filename"), r.URL.Query().Get("note"), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, rec)
}

func (s *Server) handleRestoreBackup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	n, err := s.svc.RestoreBackup(r.Context(), s.shareDir, id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"restored_interfaces": n})
}

func atoiDefault(v string, def int) int {
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return def
	}
	return n
}
