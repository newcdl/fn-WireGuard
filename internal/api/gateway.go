// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// 本文件描述「一次请求是怎么来的」——即**通道**，与「请求者是谁」无关。
//
// 本应用不解析、也不信任飞牛网关注入的任何身份信息：没有免密登录，
// 每个浏览器会话都必须走本应用自己的账号密码登录（见 service/auth.go）。
// 因此这里的判断只用于两件事：
//
//	① 日志：把「从网关入口进来的」与「从端口进来的」区分开；
//	② WebSocket 握手的跨站判断（见 checkWSOrigin）：网关转发会改写 Host，
//	   只看 Host 会把飞牛桌面打开的正常握手误判成跨站，那是 0.8.17 修掉的毛病。
//
// 也就是说，通道判定只影响「要不要怀疑这是一次跨站握手」，不影响权限：
// 两条通道上的会话都必须先登录、且权限完全相同。
type GatewayPeer struct {
	// Unix 表示该连接来自 Unix Domain Socket（而非 TCP 端口）。
	Unix bool
	// UID 是对端进程的有效用户 ID（-1 表示取不到）。
	UID int
	// Verified 表示对端身份已在允许列表内。
	Verified bool
	// Detail 说明未被信任的原因，仅用于日志。
	Detail string
}

type ctxKeyGatewayPeer ctxKey

// ctxGatewayPeerKey 是存放连接方身份信息的上下文键。
const ctxGatewayPeerKey ctxKeyGatewayPeer = "fnwg.gateway_peer"

// gatewayConnContext 是 Unix Socket 监听器的 ConnContext：在连接建立时就把
// 对端身份记进上下文。放在连接阶段而不是每个请求里做，是因为 getsockopt
// 只需一次，且拿到的就是**连接方进程**的身份，与请求内容无关。
func (s *Server) gatewayConnContext(ctx context.Context, c net.Conn) context.Context {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return ctx
	}
	peer := GatewayPeer{Unix: true, UID: -1}
	uid, err := peerUID(uc)
	switch {
	case err != nil:
		peer.Detail = "无法读取连接方身份: " + err.Error()
	case uidAllowed(uid):
		peer.UID, peer.Verified = uid, true
	default:
		peer.UID = uid
		peer.Detail = "连接方用户 ID 不在允许列表内"
		s.log.Warn("拒绝了一个来自 Unix Socket 的请求：连接方身份未获信任",
			"对端用户ID", uid, "提示", "若这是飞牛网关本身，请把该用户 ID 加入环境变量 "+envGatewayUIDs)
	}
	return context.WithValue(ctx, ctxGatewayPeerKey, peer)
}

// gatewayPeer 取出连接阶段记录的对端信息。
func gatewayPeer(r *http.Request) GatewayPeer {
	if p, ok := r.Context().Value(ctxGatewayPeerKey).(GatewayPeer); ok {
		return p
	}
	return GatewayPeer{UID: -1}
}

// gatewayTrusted 表示当前请求可以作为「飞牛网关转发的请求」来对待。
//
// 它回答的是通道问题，不是身份问题：请求确实由网关进程经 socket 递过来。
// 别处不要用它来放宽任何权限判断。
func gatewayTrusted(r *http.Request) bool {
	p := gatewayPeer(r)
	return p.Unix && p.Verified
}

// envGatewayUIDs 允许额外信任的连接方用户 ID（逗号分隔）。
//
// 存在的意义：正常情况下飞牛网关以 root 运行，与「本进程自身的用户」一起
// 已足够；但如果某个 fnOS 版本用别的用户跑网关，运维可以在这里显式放行，
// 而不是被迫关掉这层校验。
const envGatewayUIDs = "FNWG_GATEWAY_UIDS"

// uidAllowed 判断连接方用户是否可信。
//
// 默认只信 root 与本进程自身的用户：可信集合越小越好，
// 需要放宽时由 envGatewayUIDs 显式指定。
func uidAllowed(uid int) bool {
	if uid < 0 {
		return false
	}
	if uid == 0 || uid == os.Getuid() {
		return true
	}
	for _, s := range strings.Split(os.Getenv(envGatewayUIDs), ",") {
		if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil && n == uid {
			return true
		}
	}
	return false
}

// gatewayIdentityHeaders 是飞牛统一网关注入的身份头（官方文档「统一网关 → 会话校验和用户 Header」）。
//
// 这里只登记**名字**，不代表信任：目前仅用于只读诊断（GET /auth/gateway-probe）显示「看到了哪些头」。
// 将来若启用免密登录，信任判定必须与通道绑定（见 gatewayTrusted），
// 并在端口通道上把这些头**删掉**——因为官方文档没有承诺网关会剥离客户端伪造的同名头，
// 「在端口上伪造管理员」必须从结构上不可能，而不是靠每处代码自觉。
var gatewayIdentityHeaders = []string{"X-Trim-Userid", "X-Trim-Username", "X-Trim-Isadmin"}

// GatewayIdentity 是网关注入的飞牛身份。
type GatewayIdentity struct {
	UID      int64
	Username string
	IsAdmin  bool
}

// gatewayIdentity 解析网关注入的身份头，ok=false 表示这次请求没有可用的飞牛身份。
//
// 取值校验刻意从严：三个头缺一不可，Isadmin 只认明确的 true/false
// （写成 "1"、"yes" 之类一律不认——不能让一个格式怪异的头被当成管理员凭据）。
// **调用前必须先确认通道可信**，用 gatewayIdentityIfTrusted 而不是直接调它。
func gatewayIdentity(r *http.Request) (GatewayIdentity, bool) {
	uidText := strings.TrimSpace(r.Header.Get("X-Trim-Userid"))
	isAdminText := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Trim-Isadmin")))
	name := strings.TrimSpace(r.Header.Get("X-Trim-Username"))
	if uidText == "" || name == "" {
		return GatewayIdentity{}, false
	}
	if isAdminText != "true" && isAdminText != "false" {
		return GatewayIdentity{}, false
	}
	uid, err := strconv.ParseInt(uidText, 10, 64)
	if err != nil || uid <= 0 {
		return GatewayIdentity{}, false
	}
	return GatewayIdentity{UID: uid, Username: name, IsAdmin: isAdminText == "true"}, true
}

// gatewayIdentityIfTrusted 只在通道可信时才解析飞牛身份。
//
// 故意做成「要用身份就必须经过它」：通道判断与身份解析绑在一起，
// 别处就没法只拿身份、忘了看通道。
func gatewayIdentityIfTrusted(r *http.Request) (GatewayIdentity, bool) {
	if !gatewayTrusted(r) {
		return GatewayIdentity{}, false
	}
	return gatewayIdentity(r)
}

type ctxKeyStrippedIdentity ctxKey

const ctxStrippedIdentityKey ctxKeyStrippedIdentity = "fnwg.stripped_identity_headers"

// stripUntrustedIdentityHeaders 在**通道不可信**时删掉身份头，并记下删过哪些。
//
// 为什么必须由我们删：官方文档只写了「不要信任客户端传入的用户 ID」，
// 从没承诺网关会剥离客户端伪造的同名头。把它放进中间件，
// 是为了让「在端口上伪造 X-Trim-Isadmin 冒充管理员」**在结构上不可能**，
// 而不是依赖每处代码自觉判断通道。
//
// 记下名字是给只读诊断用的：它同时是「伪造的头确实到了应用」与「我们确实剥掉了」两件事的证据。
func (s *Server) stripUntrustedIdentityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if gatewayTrusted(r) {
			next.ServeHTTP(w, r)
			return
		}
		var stripped []string
		for _, h := range gatewayIdentityHeaders {
			if r.Header.Get(h) == "" {
				continue
			}
			stripped = append(stripped, h)
			r.Header.Del(h)
		}
		if len(stripped) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		// 有人往端口上传身份头：这不是正常流量，值得留痕（只记名字，不记取值）。
		s.log.Warn("端口通道收到伪造的网关身份头，已忽略",
			"headers", strings.Join(stripped, ","), "ip", clientIP(r))
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxStrippedIdentityKey, stripped)))
	})
}

// strippedIdentityHeaders 取出被剥掉的头名字（只读诊断用）。
func strippedIdentityHeaders(r *http.Request) []string {
	if v, ok := r.Context().Value(ctxStrippedIdentityKey).([]string); ok {
		return v
	}
	return nil
}
