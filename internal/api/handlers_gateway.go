package api

import (
	"net/http"

	"fnwg/internal/model"
)

// ---------------------------------------------------------------- 飞牛统一网关

// gatewayState 描述「当前页面是从哪个入口打开的」，供登录页决定怎么展示。
//
// 只跟**通道**有关，与用户是否已登录无关：登录页在未登录时就需要知道
// 自己是不是飞牛桌面里打开的那一份。
func (s *Server) gatewayState(r *http.Request) map[string]any {
	p := gatewayPeer(r)
	out := map[string]any{
		"entry": p.Unix,
		// socket_ready 是「本进程有没有在监听统一网关入口」这个客观事实。
		// 它必须和 entry（这一次请求是怎么来的）一起给出去，因为两者合起来才能把
		// 「免密不生效」拆成两种完全不同的原因：
		//   entry=false 且 socket_ready=true  → 入口是好的，是这次请求没走那条通道
		//     （真机上对应「桌面图标被注册成了端口服务」，属于入口注册问题）；
		//   entry=false 且 socket_ready=false → 入口根本没建起来，与用户怎么打开无关，
		//     去点多少次飞牛桌面图标都不会有免密。
		// 不把这条事实交给登录页，用户就只会拿到一句「请从飞牛桌面打开」——
		// 而他本来就是从飞牛桌面打开的。
		"socket_ready": s.gatewaySocketReady(),
	}
	if gw, ok := gatewayIdentity(r); ok {
		out["available"] = true
		out["username"] = gw.Username
		out["is_admin"] = gw.IsAdmin
	}
	if p.Unix && !p.Verified {
		// 说清「为什么这个入口不可用」，否则用户只会看到一句无从下手的提示。
		out["blocked_reason"] = p.Detail
	}
	return out
}

// handleGatewayLogin 用飞牛网关身份换取本地会话（免密）。
//
// 这是唯一接受 `X-Trim-*` 的接口，可信性完全依赖 api 层的通道判定：
// 请求必须经由 Unix Socket 且连接方身份获信（见 gateway.go 的说明）。
func (s *Server) handleGatewayLogin(w http.ResponseWriter, r *http.Request) {
	if !gatewayTrusted(r) {
		p := gatewayPeer(r)
		if p.Unix && !p.Verified {
			// 前端自动免密登录是静默失败的，这里不记下来在界面上完全不可见。
			s.noteGatewayDiag(p.Detail + "；如确认这是飞牛网关，请在应用环境变量 " +
				envGatewayUIDs + " 中放行该用户 ID。")
			writeErr(w, http.StatusForbidden, p.Detail+
				"；如确认这是飞牛网关，请在应用环境变量 "+envGatewayUIDs+" 中放行该用户 ID")
			return
		}
		writeErr(w, http.StatusForbidden,
			"飞牛账号登录只能从飞牛桌面打开本应用时使用（当前是直接访问端口）")
		return
	}
	gw, ok := gatewayIdentity(r)
	if !ok {
		s.noteGatewayDiag("已从网关通道打开本应用，但没收到飞牛账号信息（身份头缺失）。" +
			"请从飞牛桌面重新点开本应用图标。")
		writeErr(w, http.StatusBadRequest, "未从飞牛网关获取到账号信息，请从飞牛桌面重新打开本应用")
		return
	}
	step, err := s.svc.GatewayLogin(r.Context(), gw, r.UserAgent(), clientIP(r))
	if err != nil {
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	s.setSessionCookie(w, step.Token)
	writeJSON(w, http.StatusOK, map[string]any{
		"user":          step.User,
		"permissions":   model.PermissionsOf(step.User.Role),
		"trim_username": gw.Username,
	})
}

// handleLoginModeState 返回登录方式与「网关是否已被验证可用」，供设置页展示与防自锁提示。
func (s *Server) handleLoginModeState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.loginModeState(r))
}

// loginModeState 是设置页判断「能不能关闭端口登录」所需的全部事实。
//
// gateway_socket 与 gateway_diagnosis 用来区分两种截然不同的失败：
// 入口本身就没起来（环境问题，用户从飞牛桌面点多少次都没用），
// 与入口正常但还没走过（用户确实该去飞牛桌面点一次）。
// 不区分的话，前者会得到「请从飞牛桌面打开一次」这种根本做不到的指引。
func (s *Server) loginModeState(r *http.Request) map[string]any {
	return map[string]any{
		"mode": s.svc.LoginMode(r.Context()),
		// 没证明过网关能进来之前不允许关闭端口登录，
		// 因此界面需要知道这个事实才能给出可操作的解释。
		"gateway_proven":    s.svc.GatewayEverLoggedIn(r.Context()),
		"gateway_entry":     gatewayPeer(r).Unix,
		"gateway_socket":    s.gatewaySocketReady(),
		"gateway_diagnosis": s.gatewayDiagnosis(),
	}
}

// handleSetLoginMode 修改登录方式。改动会影响「谁能进得来」，属管理员操作。
func (s *Server) handleSetLoginMode(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Mode string `json:"mode"`
	}
	if err := decodeBody(r, &in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.svc.SetLoginMode(r.Context(), in.Mode, actorOf(r)); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, s.loginModeState(r))
}
