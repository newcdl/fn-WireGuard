package api

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// wsMessage 是推送到前端的消息信封。
type wsMessage struct {
	Type string `json:"type"`
	Data any    `json:"data,omitempty"`
	Ts   int64  `json:"ts"`
}

func (s *Server) upgrader() *websocket.Upgrader {
	return &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin:     s.checkWSOrigin,
	}
}

// checkWSOrigin 判断 WebSocket 握手是否放行。
//
// 这一层的作用是**防止第三方页面借用会话**，不是身份校验：真正的鉴权在
// requireAuth 中间件里，且它先于升级执行（见 router.go 的鉴权分组）。
// 所以判据只需要回答「来源是不是别人的网站」，不必去猜代理把地址改写成了什么样。
//
// 为什么不能只比 r.Host：浏览器发来的 Origin 永远是它地址栏里的那个地址，
// 而请求到达本进程时 Host 可能已被反向代理改写。飞牛桌面正是这种情况 ——
// 桌面按应用配置里的 gatewayPrefix 以 iframe 打开本应用（见 app/ui/config），
// 转发到应用目录下的 Unix Socket 时会改写 Host，于是每次握手都被误判成跨站：
// 前端实时状态永远连不上，日志里只剩每 10 秒一条「origin not allowed」，
// 从这个报错里既看不出是网关配置问题，也看不出该改哪里。
func (s *Server) checkWSOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// 非浏览器发起的握手（命令行排障工具等）不带 Origin，
		// 也就不存在「被第三方页面借用会话」这一风险。
		return true
	}
	if sameOrigin(origin, r.Host) {
		return true
	}
	// 代理透传的原始主机名。浏览器无法在 WebSocket 握手里自定义请求头，
	// 因此这里的值只可能来自代理本身，不构成伪造面。
	for _, h := range []string{r.Header.Get("X-Forwarded-Host"), r.Header.Get("X-Real-Host")} {
		if h == "" {
			continue
		}
		// 可能是逗号分隔的链，只取最靠近客户端的第一项。
		if i := strings.IndexByte(h, ','); i >= 0 {
			h = h[:i]
		}
		if sameOrigin(origin, strings.TrimSpace(h)) {
			return true
		}
	}
	// 飞牛统一网关通道：只有网关进程能连上这个 socket，且连接方身份已核验
	// （见 gateway.go），请求在到达本进程之前已由飞牛校验过会话 ——
	// 这条通道上的来源一律可信，与「身份头只在这条通道上可信」是同一条理由。
	return gatewayTrusted(r)
}

// sameOrigin 判断 Origin 头是否指向请求实际到达的主机。
func sameOrigin(origin, host string) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		// 请求没带 Host（例如 Unix Socket 上的 HTTP/1.0 请求）时无从比对，
		// 沿用「不作为拒绝理由」的原有取舍。
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	// Origin: null（沙箱/重定向场景）不会是 http/https，自然落在这里被拒。
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}
	return strings.EqualFold(u.Host, host)
}

// handleWS 推送实时状态。鉴权复用 Cookie / 查询参数令牌。
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader().Upgrade(w, r, nil)
	if err != nil {
		// 带上握手现场的四个关键值：仅凭 Upgrade 的错误文本无法区分
		// 「网关改写 Host」与「真的被第三方页面借用」，排障时只能靠这些字段定位。
		s.log.Warn("websocket 升级失败",
			"err", err,
			"origin", r.Header.Get("Origin"),
			"host", r.Host,
			"x_forwarded_host", r.Header.Get("X-Forwarded-Host"),
			"gateway_trusted", gatewayTrusted(r),
		)
		return
	}
	// 成功建立时**必须留一条痕**：此前这里只在失败时打日志，于是
	//「已经连上了」与「页面压根没打开」在日志里完全无法区分 —— 两种情况都是安静一片，
	// 排障的人只能对着这段安静猜，而这恰恰是最需要确定的一件事。
	// 失败看得见、成功也看得见，两个信号合起来才是可判定的。
	s.log.Info("websocket 已建立",
		"origin", r.Header.Get("Origin"),
		"host", r.Host,
		"gateway_trusted", gatewayTrusted(r),
	)

	started := time.Now()
	defer func() {
		conn.Close()
		// 断开同样要留痕：只有连接反复建立/断开，"实时状态时好时坏"才看得出来。
		s.log.Info("websocket 已断开", "duration", time.Since(started).Round(time.Second).String())
	}()

	ctx := r.Context()
	done := make(chan struct{})
	// 读循环：仅用于感知连接关闭与刷新触发
	go func() {
		defer close(done)
		conn.SetReadLimit(1024)
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	send := func() bool {
		_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		msg := wsMessage{Type: "status", Data: s.svc.Cache.Get(), Ts: time.Now().Unix()}
		return conn.WriteJSON(msg) == nil
	}
	if !send() {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			if !send() {
				return
			}
		}
	}
}
