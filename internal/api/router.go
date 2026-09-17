package api

import (
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"fnwg/internal/model"
)

// Router 构建完整路由表（REST + 内嵌前端资源）。
func (s *Server) Router(assets fs.FS) http.Handler {
	s.assets = assets

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.Recoverer)
	r.Use(s.accessLog)
	r.Use(securityHeaders)

	r.Route("/api/v1", func(r chi.Router) {
		// 无需登录
		r.Get("/auth/state", s.handleAuthState)
		r.Post("/auth/setup", s.handleAuthSetup)
		r.Post("/auth/login", s.handleLogin)
		// 二次验证登录的第二步：凭登录挑战提交动态口令（同样无需登录，因为此时还没有会话）
		r.Post("/auth/login/totp", s.handleLoginTOTP)

		// 需要登录
		r.Group(func(r chi.Router) {
			r.Use(s.requireAuth)

			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/logout", s.handleLogout)
			r.Post("/auth/password", s.handleChangePassword)
			// 二次验证：管理「自己的」账号，因此只要求登录、不额外要求 user.manage
			r.Get("/auth/totp", s.handleTOTPStatus)
			r.Post("/auth/totp/setup", s.handleTOTPSetup)
			r.Post("/auth/totp/enable", s.handleTOTPEnable)
			r.Post("/auth/totp/disable", s.handleTOTPDisable)

			r.Get("/overview", s.handleOverview)
			r.Get("/health", s.handleHealth)

			// NAS 系统网络自检与修复（只处理本应用造成的残留，不触碰系统设置）
			r.Get("/system/network", s.handleNetworkCheck)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/system/network/repair", s.handleNetworkRepair)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/system/network/cleanup", s.handleNetworkCleanup)
			// 清理「不是本应用创建的」WireGuard 网卡（疑似历史残留，需二次确认）
			r.With(requirePerm(model.PermIfaceWrite)).Post("/system/network/foreign-interface/delete", s.handleDeleteForeignInterface)

			// 事件通知：状态查询（含最近一次发送结果）与测试发送
			r.Get("/system/notify", s.handleNotifyStatus)
			r.With(requirePerm(model.PermUserManage)).Post("/system/notify/test", s.handleNotifyTest)

			// 接口
			r.Get("/interfaces", s.handleListInterfaces)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces", s.handleCreateInterface)
			r.Get("/interfaces/{id}", s.handleGetInterface)
			r.With(requirePerm(model.PermIfaceWrite)).Patch("/interfaces/{id}", s.handleUpdateInterface)
			r.With(requirePerm(model.PermIfaceWrite)).Delete("/interfaces/{id}", s.handleDeleteInterface)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces/{id}/toggle", s.handleToggleInterface)
			// 一键切换「允许设备访问家里内网」（不必进编辑表单）
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces/{id}/lan-access", s.handleSetLanAccess)
			// 一键切换「设备间隔离」
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces/{id}/isolate", s.handleSetPeerIsolation)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces/{id}/apply", s.handleApplyInterface)
			r.With(requirePerm(model.PermKeyReveal)).Post("/interfaces/{id}/reveal-key", s.handleRevealInterfaceKey)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/interfaces/{id}/rotate-key", s.handleRotateInterfaceKey)
			r.Get("/interfaces/{id}/conf", s.handleInterfaceConf)
			r.Get("/interfaces/{id}/peers", s.handleInterfacePeers)

			// 节点
			r.Get("/peers", s.handleListPeers)
			r.With(requirePerm(model.PermPeerWrite)).Post("/peers", s.handleCreatePeer)
			r.With(requirePerm(model.PermPeerWrite)).Post("/peers/batch", s.handleBatchPeers)
			r.With(requirePerm(model.PermPeerWrite)).Post("/peers/import", s.handleImportPeers)
			r.Get("/peers/{id}", s.handleGetPeer)
			r.With(requirePerm(model.PermPeerWrite)).Patch("/peers/{id}", s.handleUpdatePeer)
			r.With(requirePerm(model.PermPeerWrite)).Delete("/peers/{id}", s.handleDeletePeer)
			r.Get("/peers/{id}/config", s.handlePeerConfig)
			r.With(requirePerm(model.PermKeyReveal)).Get("/peers/{id}/secrets", s.handlePeerSecrets)
			r.Get("/peers/{id}/history", s.handlePeerHistory)

			// 密钥
			r.With(requirePerm(model.PermPeerWrite)).Post("/keys/pair", s.handleKeyPair)
			r.With(requirePerm(model.PermPeerWrite)).Post("/keys/psk", s.handleKeyPSK)

			// 配置导入导出与备份
			r.Post("/config/import", s.handleImportConfig)
			r.Get("/config/export", s.handleExportAll)
			r.Get("/config/export/{id}", s.handleExportInterface)
			r.Get("/backups", s.handleListBackups)
			r.With(requirePerm(model.PermBackupRestore)).Post("/backups", s.handleCreateBackup)
			r.With(requirePerm(model.PermBackupRestore)).Post("/backups/import", s.handleImportBackup)
			r.With(requirePerm(model.PermBackupRestore)).Get("/backups/{id}/download", s.handleDownloadBackup)
			r.With(requirePerm(model.PermBackupRestore)).Delete("/backups/{id}", s.handleDeleteBackup)
			r.With(requirePerm(model.PermBackupRestore)).Post("/backups/{id}/restore", s.handleRestoreBackup)

			// 内网域名解析（设备用主机名访问家里设备）
			r.Get("/dns/records", s.handleListDNSRecords)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/dns/records", s.handleCreateDNSRecord)
			r.With(requirePerm(model.PermIfaceWrite)).Patch("/dns/records/{id}", s.handleUpdateDNSRecord)
			r.With(requirePerm(model.PermIfaceWrite)).Delete("/dns/records/{id}", s.handleDeleteDNSRecord)

			// 审计与日志
			r.Get("/audit", s.handleListAudit)
			r.Get("/audit/verify", s.handleVerifyAudit)
			r.Get("/logs", s.handleListLogs)

			// 设置
			r.Get("/settings", s.handleGetSettings)
			r.With(requirePerm(model.PermUserManage)).Put("/settings", s.handleUpdateSettings)
			r.With(requirePerm(model.PermIfaceWrite)).Post("/system/reconcile", s.handleReconcile)

			// 用户
			r.With(requirePerm(model.PermUserManage)).Get("/users", s.handleListUsers)
			r.With(requirePerm(model.PermUserManage)).Post("/users", s.handleCreateUser)
			r.With(requirePerm(model.PermUserManage)).Patch("/users/{id}", s.handleUpdateUser)
			r.With(requirePerm(model.PermUserManage)).Delete("/users/{id}", s.handleDeleteUser)

			// 实时推送
			r.Get("/ws", s.handleWS)
		})
	})

	r.Handle("/*", s.spaHandler())
	return r
}

// accessLog 记录访问日志（不记录敏感路径的响应体）。
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			start := time.Now()
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			s.log.Debug("http",
				"method", r.Method, "path", r.URL.Path, "status", ww.Status(),
				"ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// securityHeaders 收紧浏览器侧安全策略。
//
// 注意：刻意不发送 X-Frame-Options，也不设置 CSP 的 frame-ancestors。
// fnOS 桌面把应用以 iframe 形式嵌入，而桌面端口（如 5666）与本应用端口（34567）
// 属于不同源，SAMEORIGIN 会导致桌面窗口内白屏。本应用仅监听局域网并强制登录，
// 因此接受被同主机页面嵌入的取舍。
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self' ws: wss:; font-src 'self' data:")
		next.ServeHTTP(w, r)
	})
}

// spaHandler 托管前端单页应用，未命中的路径回退到 index.html。
func (s *Server) spaHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") {
			writeErr(w, http.StatusNotFound, "接口不存在")
			return
		}
		if s.assets == nil {
			http.NotFound(w, r)
			return
		}
		p := path.Clean(strings.TrimPrefix(r.URL.Path, "/"))
		if p == "." || p == "/" {
			p = "index.html"
		}
		if _, err := fs.Stat(s.assets, p); err != nil {
			p = "index.html"
		}
		if p != "index.html" && strings.HasPrefix(p, "assets/") {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeFileFS(w, r, s.assets, p)
	})
}
