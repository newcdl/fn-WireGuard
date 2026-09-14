package api

import (
	"net/http"
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
		// 同源策略：请求必须来自本服务（fnOS 桌面 iframe 属于同源）
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				return true
			}
			host := r.Host
			return containsHost(origin, host)
		},
	}
}

func containsHost(origin, host string) bool {
	if host == "" {
		return true
	}
	for _, prefix := range []string{"http://", "https://"} {
		if origin == prefix+host {
			return true
		}
	}
	return false
}

// handleWS 推送实时状态。鉴权复用 Cookie / 查询参数令牌。
func (s *Server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader().Upgrade(w, r, nil)
	if err != nil {
		s.log.Warn("websocket 升级失败", "err", err)
		return
	}
	defer conn.Close()

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
