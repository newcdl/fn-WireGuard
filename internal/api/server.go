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
			writeErr(w, http.StatusUnauthorized, err.Error())
			return
		}
		ctx := context.WithValue(r.Context(), ctxUser, &authUser{User: u, Token: token, SrcIP: clientIP(r)})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
