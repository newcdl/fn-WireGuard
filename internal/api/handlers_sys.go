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
	out := map[string]any{
		"initialized":   initialized,
		"authenticated": false,
		"user":          nil,
		// 正在运行的版本。放在这个免登录接口上，是为了让安装/升级脚本在收尾时
		// 能核对「设备上真正在跑的就是刚装上去的那个版本」——
		// 版本号是构建时从 manifest 编译进二进制的，读得到就一定准。
		// 少了这个自查，「升级成功了但仍在跑旧版本」只能靠用户事后猜。
		"version": s.version,
		// 网关入口（飞牛桌面图标那条通道）是否已监听。与登录无关，
		// 是给安装/升级脚本用的：只看端口就报「安装成功」，
		// 用户点桌面图标才发现是 502（见 apps/fn-wireguard/cmd/common 的 fnwg_gateway_check）。
		"socket_ready": s.gatewaySocketReady(),
	}
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
	step, err := s.svc.Login(r.Context(), service.LoginInput{
		Username:  in.Username,
		Password:  in.Password,
		UserAgent: r.UserAgent(),
		SrcIP:     clientIP(r),
	})
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if step.TOTPRequired() {
		// 账号是刚刚创建的，不可能已开启二次验证；走到这里说明数据被外部改动过
		writeErr(w, http.StatusInternalServerError, "账号状态异常，请手动登录")
		return
	}
	s.setSessionCookie(w, step.Token)
	out := map[string]any{"user": u}
	// 初始化时同时下发一枚安全码：它是所有登录途径都失效时的最后入口，
	// 必须在这一刻交给用户保存，否则将来无处可取。
	if code, codeErr := s.svc.IssueSecurityCode(r.Context(), service.Actor{Username: in.Username}); codeErr != nil {
		// 生成失败不该阻断初始化（账号已经建好了），但必须如实告知，
		// 不能让用户以为自己已经拿到了后手。稍后可在「账号管理」里重新生成。
		out["security_code_error"] = "安全码生成失败，请稍后到「账号管理」重新生成：" + codeErr.Error()
	} else {
		out["security_code"] = code
	}
	writeJSON(w, http.StatusOK, out)
}

// handleEmergencyLogin 用安全码应急登录（无需登录态，因为此时通常已经登不进来了）。
func (s *Server) handleEmergencyLogin(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Code        string `json:"code"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 与常规登录共用一套失败限流：安全码虽然强度极高，但没理由让它可以被无限次尝试。
	key := "emergency|" + clientIP(r)
	if s.loginBlocked(key) {
		writeErr(w, http.StatusTooManyRequests, "尝试次数过多，请 5 分钟后再试")
		return
	}
	res, err := s.svc.EmergencyLogin(r.Context(), in.Code, in.NewPassword, r.UserAgent(), clientIP(r), actorOf(r))
	if err != nil {
		s.recordLoginFail(key)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.clearLoginFail(key)
	s.setSessionCookie(w, res.Token)
	writeJSON(w, http.StatusOK, map[string]any{"user": res.User, "new_code": res.NewCode})
}

// handleSecurityCodeState 返回是否已设置安全码（不返回安全码本身，它无法取回）。
func (s *Server) handleSecurityCodeState(w http.ResponseWriter, r *http.Request) {
	configured, err := s.svc.SecurityCodeConfigured(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"configured": configured})
}

// handleIssueSecurityCode 重新生成安全码（旧码立即作废），返回新码明文。
func (s *Server) handleIssueSecurityCode(w http.ResponseWriter, r *http.Request) {
	code, err := s.svc.IssueSecurityCode(r.Context(), actorOf(r))
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"code": code})
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
	step, err := s.svc.Login(r.Context(), service.LoginInput{
		Username:    in.Username,
		Password:    in.Password,
		DeviceToken: extractDeviceToken(r),
		UserAgent:   r.UserAgent(),
		SrcIP:       clientIP(r),
	})
	if err != nil {
		s.recordLoginFail(key)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if step.TOTPRequired() {
		// 口令正确但还需二次验证：这里**绝不能设 Cookie**，
		// 否则「只过了一半」的登录就变成了已登录。
		writeJSON(w, http.StatusOK, map[string]any{
			"totp_required": true,
			"challenge":     step.Challenge,
			"username":      in.Username,
		})
		return
	}
	s.clearLoginFail(key)
	s.setSessionCookie(w, step.Token)
	writeJSON(w, http.StatusOK, step.User)
}

// handleLoginTOTP 是登录的第二步：用登录挑战 + 动态口令（或恢复码）换取会话。
func (s *Server) handleLoginTOTP(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Challenge   string `json:"challenge"`
		Code        string `json:"code"`
		TrustDevice bool   `json:"trust_device"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 失败计数归到「IP+账号」这个键上，与密码那一步共用一套限流：
	// 动态口令只有 6 位，若不限流，拿到口令的人可以靠反复重试撞开。
	key := ""
	if name, ok := s.svc.TOTPChallengeUser(r.Context(), in.Challenge); ok {
		key = clientIP(r) + "|" + name
		if s.loginBlocked(key) {
			writeErr(w, http.StatusTooManyRequests, "登录失败次数过多，请 5 分钟后再试")
			return
		}
	}
	step, err := s.svc.CompleteTOTPLogin(r.Context(), in.Challenge, in.Code, in.TrustDevice, r.UserAgent(), clientIP(r))
	if err != nil {
		if key != "" {
			s.recordLoginFail(key)
		}
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	if key != "" {
		s.clearLoginFail(key)
	}
	// 勾选了「信任本设备」时下发设备令牌；没勾选时不碰这个 Cookie，
	// 免得把上一次的信任状态莫名清掉（用户可能只是这次不想勾）。
	if step.DeviceToken != "" {
		s.setDeviceCookie(w, step.DeviceToken, step.DeviceExpiresAt)
	}
	s.setSessionCookie(w, step.Token)
	writeJSON(w, http.StatusOK, step.User)
}

// handleTOTPStatus 返回当前账号的二次验证状态。
func (s *Server) handleTOTPStatus(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	st, err := s.svc.TOTPStatusOf(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

// handleTOTPSetup 生成绑定密钥与 otpauth 扫码链接（此时尚未生效）。
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := s.svc.BeginTOTPSetup(r.Context(), userOf(r).ID, in.Password, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleTOTPEnable 用一次有效动态口令确认绑定并正式开启，返回一次性恢复码。
func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Secret   string `json:"secret"`
		Code     string `json:"code"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	codes, err := s.svc.EnableTOTP(r.Context(), userOf(r).ID, in.Password, in.Secret, in.Code, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
}

// handleTOTPDisable 关闭二次验证（需当前口令 + 一次动态口令或恢复码）。
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.DisableTOTP(r.Context(), userOf(r).ID, in.Password, in.Code, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 关闭二次验证会作废全部受信任设备，本地 Cookie 一起清掉。
	s.clearDeviceCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleListTrustedDevices 列出当前账号的受信任设备。
func (s *Server) handleListTrustedDevices(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	list, err := s.svc.ListTrustedDevices(r.Context(), u.ID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": list})
}

// handleRevokeTrustedDevice 撤销一台受信任设备。
func (s *Server) handleRevokeTrustedDevice(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.RevokeTrustedDevice(r.Context(), userOf(r).ID, id, actorOf(r)); err != nil {
		writeErr(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// handleRevokeAllTrustedDevices 撤销当前账号的全部受信任设备。
func (s *Server) handleRevokeAllTrustedDevices(w http.ResponseWriter, r *http.Request) {
	u := userOf(r)
	if err := s.svc.RevokeAllTrustedDevices(r.Context(), u.ID, actorOf(r)); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.clearDeviceCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"revoked": true})
}

// handleResetUserTOTP 管理员重置某个账号的二次验证。
func (s *Server) handleResetUserTOTP(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	if err := s.svc.ResetUserTOTP(r.Context(), id, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// handleAdminUserTOTPSetup 管理员为某个账号生成二次验证绑定信息（尚未生效）。
//
// 用于「账号主人自己操作不熟」的场景：管理员把二维码交给对方扫。
// 这里只生成、不启用 —— 对方扫完报回一次动态口令，再走 enable 才真正开启。
// 中间那一步不能省：启用了却其实没绑成功，账号主人下次登录就被锁在门外，
// 而那时他手里既没有验证器、也还没见过恢复码。
func (s *Server) handleAdminUserTOTPSetup(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	out, err := s.svc.AdminBeginTOTPSetup(r.Context(), id, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// handleAdminUserTOTPEnable 管理员用一次动态口令确认绑定并正式开启，返回一次性恢复码。
func (s *Server) handleAdminUserTOTPEnable(w http.ResponseWriter, r *http.Request) {
	id, ok := s.idOrFail(w, r)
	if !ok {
		return
	}
	var in struct {
		Secret string `json:"secret"`
		Code   string `json:"code"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	codes, err := s.svc.AdminEnableTOTP(r.Context(), id, in.Secret, in.Code, actorOf(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"recovery_codes": codes})
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
	// 传入当前会话令牌：改密码会登出其它设备，但必须保留正在操作的这一台。
	if err := s.svc.ChangePassword(r.Context(), u.ID, in.OldPassword, in.NewPassword, extractToken(r), actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	// 改密码已作废全部受信任设备，本地这枚 Cookie 也就失效了，顺手清掉。
	s.clearDeviceCookie(w)
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

// deviceCookieName 是「信任本设备」的设备令牌 Cookie 名。
//
// 刻意与会话 Cookie 分开：退出登录**不应该**清掉设备信任，
// 否则「记住本设备」就退化成「只在当前会话内免验证」，功能等于白做。
const deviceCookieName = "fnwg_device"

// extractDeviceToken 读取受信任设备令牌。
func extractDeviceToken(r *http.Request) string {
	if c, err := r.Cookie(deviceCookieName); err == nil {
		return c.Value
	}
	return ""
}

func (s *Server) setDeviceCookie(w http.ResponseWriter, token string, expires time.Time) {
	maxAge := int(time.Until(expires).Seconds())
	if maxAge <= 0 {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     deviceCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) clearDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: deviceCookieName, Value: "", Path: "/", HttpOnly: true, MaxAge: -1,
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
	items, err := s.svc.ListUserBackups(r.Context())
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
