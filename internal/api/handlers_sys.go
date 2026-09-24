// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"fnwg"
	"fnwg/internal/model"
	"fnwg/internal/service"
	"fnwg/internal/store"
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
		// 本次请求走的哪条通道、能不能用飞牛身份免密进入 —— 登录页据此决定要不要给指引
		// （例如「免密只在从飞牛桌面打开时可用」「回飞牛桌面重新点开」）。
		// 只回答「能不能」，不回答「你是谁」：登录前不该从这里拿到任何身份信息。
		"channel":           channelOf(r),
		"gateway_available": gatewayAvailable(r),
	}
	// 本次请求带着可用的飞牛身份就把用户名报出来，**与是否已登录、是否已初始化都无关**：
	//  - 登录页要在「刚退出登录」那一刻仍然显示「飞牛账号 XXX」这个入口，而那一刻恰好没有登录；
	//  - 初始化页要在「还没建任何账号」时就知道能不能走「用飞牛账号登录」这条路 ——
	//    早先这段写在初始化判断**之后**，于是全新安装时它永远拿不到身份，
	//    初始化页明明是从飞牛桌面点进来的，却不给飞牛账号这个选项（真机反馈）。
	if id, ok := gatewayIdentityIfTrusted(r); ok {
		out["gateway_user"] = map[string]any{
			"username": id.Username,
			"is_admin": id.IsAdmin,
		}
	}
	if !initialized {
		writeJSON(w, http.StatusOK, out)
		return
	}
	if u, err := s.svc.Authenticate(r.Context(), extractToken(r)); err == nil {
		out["authenticated"] = true
		out["user"] = u
		out["identity"] = "session"
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
		// GatewayOnly 对应初始化页面上的第二个选项：不建本地口令账号，直接用飞牛账号登录。
		GatewayOnly bool `json:"gateway_only"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if in.GatewayOnly {
		s.setupGatewayOnly(w, r)
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

// setupGatewayOnly 走「不建账号，直接用飞牛账号登录」这条路。
//
// 它不是绕开初始化，而是把「第一个管理员是谁」交给飞牛身份本身：发起这次初始化的
// 那个飞牛账号就是第一份管理员（管理员 → 管理员、普通成员 → 只读，与此后每次飞牛登录
// 完全同一套规则）。本地因此不落任何口令 —— 也就没有「用户的密码」这回事，
// 登录页与账号管理里都不该再出现「修改密码」。
//
// 安全码照发：它是所有登录途径都失效时的唯一退路，必须在这一刻交给用户；
// 而且此时账号已经建好（就是上面那份飞牛账号），应急登录有落点，不会发一枚无处可用的码。
func (s *Server) setupGatewayOnly(w http.ResponseWriter, r *http.Request) {
	// 只认通道可信的飞牛身份：端口入口上没有飞牛身份，也就谈不上「用飞牛账号登录」
	id, ok := gatewayIdentityIfTrusted(r)
	if !ok {
		writeErr(w, http.StatusBadRequest,
			"这次请求没有可用的飞牛身份，无法走「用飞牛账号登录」这条路：请从飞牛桌面点开本应用后初始化，或改用账号密码方式")
		return
	}
	has, err := s.svc.HasUsers(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if has {
		writeErr(w, http.StatusBadRequest, "系统已初始化，请直接登录")
		return
	}
	step, err := s.svc.LoginAsGatewayUser(r.Context(), id.UID, id.Username, id.IsAdmin, r.UserAgent(), clientIP(r))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	s.setSessionCookie(w, step.Token)
	out := map[string]any{
		"user":        step.User,
		"permissions": model.PermissionsOf(step.User.Role),
	}
	if code, codeErr := s.svc.IssueSecurityCode(r.Context(), service.Actor{Username: "setup"}); codeErr != nil {
		// 与账号密码方式一致：生成失败不阻断初始化，但必须如实告知，不能让人以为拿到了后手
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
		// 这次身份是怎么来的（本应用会话 / 飞牛网关注入），界面据此决定能不能「退出登录」
		"identity": identityKind(r),
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
	// 网关入口属于本进程的事实（socket 落在哪、现在还在不在），自检结果里补上这一段：
	// 「端口一切正常、只有飞牛桌面点图标 502」时，这是唯一能说清原因的地方。
	res.Gateway = s.gatewayEntryStatus()
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
	// 多带一个 missing：记录在数据库里，文件却可能已经被手动删掉或移走。
	// 让界面提前把这一行标出来并禁掉下载/还原，比等用户点了再报错省事 ——
	// 那种报错（open …: no such file）既不好读，也说不清该怎么办。
	type backupRow struct {
		store.BackupRecord
		Missing bool `json:"missing"`
	}
	rows := make([]backupRow, 0, len(items))
	for _, it := range items {
		_, statErr := os.Stat(filepath.Join(s.shareDir, it.Filename))
		rows = append(rows, backupRow{BackupRecord: it, Missing: os.IsNotExist(statErr)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "share_dir": s.shareDir})
}

func (s *Server) handleCreateBackup(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Note string `json:"note"`
		// Dir 是可选的「另存一份到」：留空表示只存到应用自己的备份目录（与历史行为一致）。
		// 只能选用户在飞牛里授权给本应用的目录；写入由特权代理执行，见 Core.WriteBackupCopy。
		Dir string `json:"dir"`
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
	out := map[string]any{"backup": rec}
	if strings.TrimSpace(in.Dir) != "" {
		// 另存也交给代理：写入发生在用户授权的共享文件夹上，而界面进程对它没有写权限。
		// 源按备份 ID 指定（代理自己去找文件），不给协议任何任意路径读写的能力。
		a := actorOf(r)
		_, derr := s.svc.Core.WriteBackupCopy(r.Context(), in.Dir, rec.ID, a.UserID, a.Username, a.SrcIP)
		if derr != nil {
			// 本地那份已经写好了，这里只是「另存一份」没成。不能整体报失败 ——
			// 那会让人以为没备份，而备份其实好好地在列表里。返回成功 + 单独说明。
			out["copy_error"] = derr.Error()
			writeJSON(w, http.StatusOK, out)
			return
		}
		out["copied_to"] = filepath.Clean(strings.TrimSpace(in.Dir))
	}
	writeJSON(w, http.StatusOK, out)
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

// ---------------------------------------------------------------- 开源许可

// handleLicenses 返回本应用的许可信息：「关于」页的「开源许可」据此展示。
//
// 文本取自二进制内嵌的内容（见根目录 licenses.go），不读磁盘也不依赖网络：
// 安装包里只有 apps 侧的 COPYING，而界面要同时给出 GPL 全文与第三方清单，
// 内嵌是唯一不会出现「装了什么、显示什么」对不上的做法。
func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"license":     fnwg.GPLText,
		"third_party": fnwg.ThirdPartyLicenses,
	})
}
