package api

import (
	"context"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"

	"fnwg/internal/service"
)

// 飞牛统一网关在完成会话校验后注入的身份头。
//
// ⚠️ 本应用的最高安全风险点就在这里：这三个头是**明文**的，谁都能往请求里塞。
// 因此信任它们需要**同时**满足两个条件，缺一不可：
//
//	① 请求经由 Unix Domain Socket 到达本进程（网关只能这么访问我们，
//	   而 socket 文件在应用目录内，普通客户端无法从网络到达）；
//	② 该 socket 连接的对端进程身份在允许列表内（见 peercred_*.go）——
//	   仅靠 ① 还不够：socket 是所有本地用户都可连接的文件，
//	   本机上一个别的应用进程同样能连上来伪造管理员头。
//
// 正面入口是 gatewayIdentity()；TCP 监听器上还有一道 stripGatewayHeaders
// 中间件把这些头直接删掉，构成「双保险」——即便将来有人误在 TCP 侧的
// 处理函数里读了这些头，读到的也只会是空值。
const (
	headerTrimUserID   = "X-Trim-Userid"
	headerTrimUsername = "X-Trim-Username"
	headerTrimIsAdmin  = "X-Trim-Isadmin"
)

// GatewayPeer 描述一次 Unix Socket 连接的对端进程。
type GatewayPeer struct {
	// Unix 表示该连接来自 Unix Domain Socket（而非 TCP 端口）。
	Unix bool
	// UID 是对端进程的有效用户 ID（-1 表示取不到）。
	UID int
	// Verified 表示对端身份已在允许列表内。
	Verified bool
	// Detail 说明未被信任的原因，仅用于日志与界面提示。
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
func gatewayTrusted(r *http.Request) bool {
	p := gatewayPeer(r)
	return p.Unix && p.Verified
}

// gatewayIdentity 从可信请求中取出飞牛身份。
// 只在 gatewayTrusted 为真时才会返回 ok=true，其余情况一律返回零值。
func gatewayIdentity(r *http.Request) (service.GatewayIdentity, bool) {
	if !gatewayTrusted(r) {
		return service.GatewayIdentity{}, false
	}
	uid := strings.TrimSpace(r.Header.Get(headerTrimUserID))
	if uid == "" {
		return service.GatewayIdentity{}, false
	}
	return service.GatewayIdentity{
		UID:      uid,
		Username: strings.TrimSpace(r.Header.Get(headerTrimUsername)),
		IsAdmin:  strings.EqualFold(strings.TrimSpace(r.Header.Get(headerTrimIsAdmin)), "true"),
	}, true
}

// stripGatewayHeaders 在 TCP 监听器上删除网关注入类请求头。
//
// 为什么必须删而不是「不读就行」：这些头的含义完全由读取方决定，
// 一旦将来任何一处代码图省事直接读了它们，TCP 端口立刻变成提权入口。
// 在入口处彻底删掉，是把「不能伪造」这件事从约定变成事实。
func stripGatewayHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerTrimUserID) != "" ||
			r.Header.Get(headerTrimUsername) != "" ||
			r.Header.Get(headerTrimIsAdmin) != "" {
			r.Header.Del(headerTrimUserID)
			r.Header.Del(headerTrimUsername)
			r.Header.Del(headerTrimIsAdmin)
		}
		next.ServeHTTP(w, r)
	})
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
