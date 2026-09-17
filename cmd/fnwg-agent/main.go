// Command fnwg-agent 是特权代理进程：以 root 运行，负责把数据库中的期望态
// 收敛到内核（netlink / wgctrl），并通过 Unix Domain Socket 对外提供最小化的能力集。
//
// 该进程不监听任何 TCP 端口，不做业务鉴权，所有外部输入都会经过白名单校验。
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"fnwg/internal/agentapi"
	"fnwg/internal/config"
	"fnwg/internal/core"
	"fnwg/internal/reconcile"
	"fnwg/internal/secretbox"
	"fnwg/internal/store"
	"fnwg/internal/sysutil"
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

	// 共享文件（数据库、主密钥、socket）需要同组可写，因此使用 0002 umask。
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

	gid := sysutil.LookupGID(cfg.Group)
	if gid < 0 {
		logger.Warn("运行用户组不存在，共享文件将仅对当前用户可读", "group", cfg.Group)
	}
	fixSharedPerms(cfg, gid)

	backend := wgback.New(cfg.NetStatePath())
	engine := reconcile.New(st, backend, logger)
	logger.Info("特权代理初始化完成",
		"backend", backend.Kind(), "caps", fmt.Sprintf("%+v", backend.Caps()), "version", cfg.Version)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// 停用/卸载清理：删除本应用创建的全部内核对象（只删自己的，不碰系统任何东西）。
	// 该路径刻意不依赖数据库，确保任何情况下都能把我们的痕迹清干净。
	if cfg.Cleanup {
		actions, err := backend.Cleanup(ctx)
		for _, a := range actions {
			fmt.Println("·", a)
		}
		if err != nil {
			logger.Error("清理失败", "err", err)
			os.Exit(1)
		}
		if len(actions) == 0 {
			fmt.Println("没有需要清理的对象")
		}
		return
	}

	if cfg.Once {
		diff, err := engine.Reconcile(ctx)
		if err != nil {
			logger.Error("收敛失败", "err", err)
			os.Exit(1)
		}
		if len(diff.Actions) == 0 {
			fmt.Println("配置已是最新，无需变更")
			return
		}
		for _, a := range diff.Actions {
			fmt.Println("·", a)
		}
		return
	}

	// 采样与收敛循环：进程启动即执行一次全量收敛，实现重启自恢复。
	go engine.Run(ctx)

	// 周期性修正共享文件权限，覆盖 SQLite 自行创建 -wal/-shm 的情况
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				fixSharedPerms(cfg, gid)
			}
		}
	}()

	srv := agentapi.NewServer(cfg.SocketPath, cfg.Group, core.NewLocal(engine), logger)
	if err := srv.Listen(); err != nil {
		logger.Error("监听 socket 失败", "err", err)
		os.Exit(1)
	}
	defer srv.Close()

	if err := srv.Serve(ctx); err != nil {
		logger.Error("代理服务异常退出", "err", err)
		os.Exit(1)
	}
	logger.Info("特权代理已退出")
}

// fixSharedPerms 保证数据库、主密钥与共享导出目录对运行用户组可读写。
//
// share 目录单独在这里修正，是为了「自愈」历史安装：早期版本只在启动脚本里
// 给顶层数据目录 chmod，share 子目录可能仍是 755，导致 Web 进程（fnwg 用户）
// 写备份报 permission denied。agent 以 root 运行，每 5 分钟顺手把它改回 770。
func fixSharedPerms(cfg *config.Config, gid int) {
	sysutil.FixGroup(cfg.DBPath(), gid, 0o660)
	sysutil.FixGroup(cfg.DBPath()+"-wal", gid, 0o660)
	sysutil.FixGroup(cfg.DBPath()+"-shm", gid, 0o660)
	sysutil.FixGroup(cfg.MasterKeyPath(), gid, 0o640)
	sysutil.FixGroup(cfg.ShareDir(), gid, 0o770)
}

func newLogger(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.SlogLevel()}
	f, err := os.OpenFile(cfg.LogDir()+"/agent.log", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	if err != nil {
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	}
	return slog.New(slog.NewTextHandler(io.MultiWriter(os.Stderr, f), opts))
}
