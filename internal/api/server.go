// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

// Package api 提供 REST + WebSocket 接口层。
package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"

	"fnwg/internal/model"
	"fnwg/internal/service"
)

// Server 聚合业务服务与运行时依赖。
type Server struct {
	svc      *service.Service
	log      *slog.Logger
	assets   fs.FS
	version  string
	shareDir string

	loginMu    sync.Mutex
	loginFails map[string]loginFail

	// gatewaySockPath 是统一网关入口 socket 的实际监听路径（未监听时为空串）。
	//
	// 它只回答「飞牛桌面点图标这条通道建起来没有」，与登录无关：
	// 本应用不认任何外部身份。之所以要留着，是因为安装/升级脚本会读
	// /auth/state 的 socket_ready 来判断这次装完桌面入口能不能用 ——
	// 只看端口就报「安装成功」的话，用户点图标才发现是 502（见 0.8.16）。
	gatewaySockPath atomic.Pointer[string]
}

type loginFail struct {
	count int
	until time.Time
}

// NewServer 创建 API 服务。
func NewServer(svc *service.Service, logger *slog.Logger, version, shareDir string) *Server {
	// 配置快照与备份共用共享目录：那里已经被应用中心授予了组读写权限，
	// 另开子目录还得再走一遍权限自愈，不如同目录、靠文件名前缀区分。
	svc.SetSnapshotDir(shareDir)
	return &Server{
		svc:        svc,
		log:        logger,
		version:    version,
		shareDir:   shareDir,
		loginFails: map[string]loginFail{},
	}
}

type ctxKey string

const (
	ctxUser ctxKey = "fnwg.user"
)

// authUser 是请求上下文中的登录态。
type authUser struct {
	User  *model.User
	Token string
	SrcIP string
}

// actorOf 构造审计主体。
func actorOf(r *http.Request) service.Actor {
	if u, ok := r.Context().Value(ctxUser).(*authUser); ok && u != nil {
		return service.Actor{UserID: u.User.ID, Username: u.User.Username, SrcIP: u.SrcIP}
	}
	return service.Actor{Username: "anonymous", SrcIP: clientIP(r)}
}

func userOf(r *http.Request) *model.User {
	if u, ok := r.Context().Value(ctxUser).(*authUser); ok && u != nil {
		return u.User
	}
	return nil
}

func clientIP(r *http.Request) string {
	if v := r.Header.Get("X-Real-IP"); v != "" {
		return v
	}
	if v := r.Header.Get("X-Forwarded-For"); v != "" {
		if i := strings.Index(v, ","); i > 0 {
			return strings.TrimSpace(v[:i])
		}
		return strings.TrimSpace(v)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// ---------------------------------------------------------------- 响应

type apiResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Code: 0, Message: "ok", Data: data})
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(apiResponse{Code: status, Message: msg})
}

func decodeBody(r *http.Request, out any) error {
	defer io.Copy(io.Discard, r.Body)
	dec := json.NewDecoder(io.LimitReader(r.Body, 2<<20))
	if err := dec.Decode(out); err != nil {
		return errors.New("请求体格式错误: " + err.Error())
	}
	return nil
}

func pathID(r *http.Request) (int64, error) {
	raw := chi.URLParam(r, "id")
	if raw == "" {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) > 0 {
			raw = parts[len(parts)-1]
		}
	}
	id, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, errors.New("路径参数非法")
	}
	return id, nil
}

// ---------------------------------------------------------------- 登录限流

func (s *Server) loginBlocked(key string) bool {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	f, ok := s.loginFails[key]
	if !ok {
		return false
	}
	if time.Now().After(f.until) {
		delete(s.loginFails, key)
		return false
	}
	return f.count >= 5
}

func (s *Server) recordLoginFail(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	f := s.loginFails[key]
	f.count++
	f.until = time.Now().Add(5 * time.Minute)
	s.loginFails[key] = f
}

func (s *Server) clearLoginFail(key string) {
	s.loginMu.Lock()
	defer s.loginMu.Unlock()
	delete(s.loginFails, key)
}

// extractToken 依次从 Bearer 头、Cookie、查询参数中提取令牌。
func extractToken(r *http.Request) string {
	if v := r.Header.Get("Authorization"); strings.HasPrefix(v, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(v, "Bearer "))
	}
	if c, err := r.Cookie("fnwg_token"); err == nil && c.Value != "" {
		return c.Value
	}
	return r.URL.Query().Get("token")
}

// ---------------------------------------------------------------- 中间件

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		u, err := s.svc.Authenticate(r.Context(), token)
		if err != nil {
			// 被拒的请求必须留痕。此前这里是静默 401，于是「请求压根没到达服务端」
			// 与「到达了但没通过鉴权」在日志里一模一样 —— 都是一片安静，
			// 排障的人只会得出「什么都没发生」这个错误结论。
			// 前端还有几处会自动重连（App.vue 在未登录时也会先连一次 /ws），
			// 一次拒绝就会变成每 8 秒一轮的静默重试，正是最难被发现的那种失效。
			// 只记方法与路径与原因；令牌本身绝不落日志。
			s.log.Info("请求未通过鉴权",
				"method", r.Method, "path", r.URL.Path,
				"reason", err.Error(), "ip", clientIP(r))
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, &authUser{User: u, Token: token, SrcIP: clientIP(r)})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------------------------------------------------------------- 网关入口自检

// SetGatewaySocket 记录网关入口 socket 的落点（由启动方给出）。
//
// 注意它**不表示「已就绪」**：就绪与否一律以现场探测为准（见 probeGatewaySocket），
// 因为文件可能在运行期消失，而「记下过路径」不会随之改变。
func (s *Server) SetGatewaySocket(path string) {
	s.gatewaySockPath.Store(&path)
}

// gatewaySocketReady 表示统一网关入口此刻确实可用。
//
// 判定落在**现场事实**上（文件在、是 socket、且真能连上），而不是「本进程启动时
// 绑过一次」这个记忆。原因见 0.8.22 修的那次 502：socket 文件被外部删掉之后，
// 进程照常运行、端口照常工作、自报也照常「已就绪」，而飞牛桌面点图标只能是 502 ——
// 唯一的线索就是这个不存在的文件。
//
// 这个字段是安装/升级/启动脚本判断入口能不能用的依据，因此必须能反映上述状态，
// 否则「自动修一次再判」的兜底永远不会触发。
func (s *Server) gatewaySocketReady() bool {
	p := s.gatewaySockPath.Load()
	return p != nil && probeGatewaySocket(*p) == gatewaySocketOK
}

func requirePerm(perm string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u := userOf(r)
			if u == nil {
				writeErr(w, http.StatusUnauthorized, "未登录")
				return
			}
			if !model.PermissionsOf(u.Role)[perm] {
				writeErr(w, http.StatusForbidden, "当前角色无此操作权限")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
