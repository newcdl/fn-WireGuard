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
		Addr:              fmt.Sprintf("%s:%d", cfg.Bind, cfg.Port),
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

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	f, err := os.OpenFile(cfg.LogDir()+"/web.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, f), opts))
}
