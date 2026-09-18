// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Command fnwg-web 是面向用户的服务进程：以普通用户运行，提供 Web 界面与 REST API。
// 所有需要内核能力的操作都通过 Unix Domain Socket 委派给 fnwg-agent，
// 从而把 root 权限收敛在一个不监听 TCP 的进程里。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"fnwg/internal/agentapi"
	"fnwg/internal/api"
	"fnwg/internal/config"
	"fnwg/internal/core"
	"fnwg/internal/model"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/service"
	"fnwg/internal/store"
	"fnwg/internal/sysutil"
	"fnwg/internal/webui"
	"fnwg/internal/wgback"
)

// buildVersion 由构建脚本通过 -ldflags "-X main.buildVersion=..." 注入。
var buildVersion string

func main() {
	cfg := config.Load(os.Args[1:])
	switch {
	case buildVersion != "":
		cfg.Version = buildVersion
	case os.Getenv("FNWG_BUILD_VERSION") != "":
		cfg.Version = os.Getenv("FNWG_BUILD_VERSION")
	}
	// 与 agent 共享数据库文件，使用 0002 umask 保证同组可写
	sysutil.Umask(0o002)

	if err := cfg.EnsureDirs(); err != nil {
		fmt.Fprintln(os.Stderr, "创建数据目录失败:", err)
		os.Exit(1)
	}
	logger := newLogger(cfg)
	slog.SetDefault(logger)

	box, err := secretbox.LoadOrCreate(cfg.MasterKeyPath())
	if err != nil {
		logger.Error("加载主密钥失败", "err", err)
		os.Exit(1)
	}
	st, err := store.Open(cfg.DBPath(), box)
	if err != nil {
		logger.Error("打开数据库失败", "err", err)
		os.Exit(1)
	}
	defer st.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := applyBootstrap(ctx, st, cfg, logger); err != nil {
		logger.Warn("导入安装向导配置失败", "err", err)
	}

	var kore agentapi.Core
	if cfg.Dev {
		// 开发模式：进程内使用内存后端，不依赖特权代理
		backend := wgback.New(cfg.NetStatePath())
		engine := reconcile.New(st, backend, logger)
		go engine.Run(ctx)
		kore = core.NewLocal(engine)
		logger.Warn("开发模式已启用：使用内存后端，不会操作真实网络", "backend", backend.Kind())
		if err := ensureDevAdmin(ctx, st, logger); err != nil {
			logger.Warn("初始化开发账号失败", "err", err)
		}
	} else {
		client := agentapi.NewClient(cfg.SocketPath)
		if err := client.WaitReady(ctx, 10*time.Second); err != nil {
			logger.Warn("等待特权代理就绪失败，界面可用但无法下发配置", "err", err)
		}
		kore = client
	}

	svc := service.New(st, kore, logger, cfg.Version)
	go svc.Cache.Run(ctx, 2*time.Second)

	assets, err := webui.FS()
	if err != nil {
		logger.Warn("前端资源不可用", "err", err)
	}
	srv := api.NewServer(svc, logger, cfg.Version, cfg.ShareDir())

	httpSrv := &http.Server{
		Addr: fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port),
		// 端口通道与网关通道共用同一份路由与同一套登录要求（见 api.Router）。
		Handler:           srv.Router(assets),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		logger.Info("Web 服务已启动", "addr", httpSrv.Addr, "version", cfg.Version, "dev", cfg.Dev)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Web 服务异常退出", "err", err)
			stop()
		}
	}()

	// 飞牛统一网关通道（飞牛桌面点图标走的就是这里）：由 fnOS 校验飞牛账号会话后
	// 经 Unix Socket 转发过来，进入本应用仍需自己登录。
	//
	// 交给守护者而不是在这里一次性绑定：入口是一个文件，可能在运行期被外部删掉，
	// 而启动时的自查不会再看第二眼 —— 那正是「进程一切正常、只有桌面图标 502」
	// 这类故障能长期存在的原因。守护者会定期确认入口还在，不在就地重建。
	if sockPath := cfg.AppSockPath(); sockPath != "" {
		// 先记下落点：/auth/state 的 socket_ready 与自检页都从这里取路径，
		// 而就绪与否一律由现场探测决定（文件可能在运行期消失）。
		srv.SetGatewaySocket(sockPath)
		keeper := srv.NewGatewayKeeper(sockPath, srv.Router(assets))
		go func() {
			if err := keeper.Run(ctx); err != nil {
				logger.Error("飞牛统一网关入口守护异常退出", "err", err)
			}
		}()
	} else {
		// 正常启动路径不会走到这里：AppSockPath 会兜底到可执行文件所在目录。
		srv.SetGatewaySocket("")
		logger.Warn("无法定位应用目录，飞牛统一网关入口不可用：从飞牛桌面点图标将报 Bad Gateway",
			"appdest", cfg.AppDest)
	}

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	logger.Info("Web 服务已退出")
}

// bootstrapPayload 是安装/配置向导写入的引导配置。
type bootstrapPayload struct {
	ServerEndpoint string `json:"server_endpoint"`
	DefaultDNS     string `json:"default_dns"`
}

// applyBootstrap 把向导输入的配置导入应用设置，随后删除引导文件。
func applyBootstrap(ctx context.Context, st *store.Store, cfg *config.Config, logger *slog.Logger) error {
	path := filepath.Join(cfg.EtcDir, "bootstrap.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var p bootstrapPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		_ = os.Remove(path)
		return err
	}
	if p.ServerEndpoint != "" {
		if err := st.SetSetting(ctx, "server_endpoint", p.ServerEndpoint); err != nil {
			return err
		}
	}
	if p.DefaultDNS != "" {
		if err := st.SetSetting(ctx, "default_dns", p.DefaultDNS); err != nil {
			return err
		}
	}
	_ = os.Remove(path)
	logger.Info("已导入安装向导配置",
		"server_endpoint", p.ServerEndpoint, "default_dns", p.DefaultDNS)
	return nil
}

// ensureDevAdmin 在开发模式且无任何账号时创建默认管理员，便于本地调试。
func ensureDevAdmin(ctx context.Context, st *store.Store, logger *slog.Logger) error {
	n, err := st.CountUsers(ctx)
	if err != nil || n > 0 {
		return err
	}
	hash, err := service.HashPassword("admin12345")
	if err != nil {
		return err
	}
	if err := st.CreateUser(ctx, &model.User{
		Username:     "admin",
		PasswordHash: hash,
		Role:         model.RoleAdmin,
		Status:       1,
	}); err != nil {
		return err
	}
	logger.Warn("已创建开发用管理员账号：admin / admin12345（请勿在生产环境使用）")
	return nil
}

// newLogger 同时写 stderr（systemd 下即 journald）与 ${TRIM_PKGVAR}/log/web.log。
//
// 日志文件打不开时**必须留下痕迹**：以前这里是静默降级成"只写 stderr"，
// 于是 web.log 停在某个时间点不再增长，而排障的人只会去读这个文件 ——
// 「日志里什么都没有」被读成「程序什么都没发生」，方向被彻底带偏。
// 现在降级依然允许（进程不能因为写不了日志就起不来），但降级本身要在 journal 里说清楚。
//
// 创建模式用 0660 而非 0640：安装脚本会对整个数据目录执行 chown -R root:fnwg，
// 文件属主随之变成 root，只有「属组可写」才能让以 fnwg 运行的 Web 进程继续追加。
func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}
	path := cfg.LogDir() + "/web.log"
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o660)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"警告：无法写入日志文件 %s（%v）。本次运行的日志只在 journalctl 中可见，"+
				"该文件将保持旧内容，请勿以它判断服务是否正常（journalctl -u fnwg-web）\n", path, err)
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, f), opts))
}
