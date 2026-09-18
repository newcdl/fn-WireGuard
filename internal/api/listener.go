package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// GatewayListener 是飞牛统一网关用的 Unix Domain Socket 监听器。
type GatewayListener struct {
	// Path 是 socket 文件路径（= 应用 target 目录下的 app.sock）。
	Path string

	ln  net.Listener
	srv *http.Server
}

// ListenGateway 绑定网关 socket 并做好准备，但不开始提供服务。
//
// 与端口监听相比只有两点事实上的不同：
//  1. 请求只能来自本机（网络不可达），由网关校验过飞牛会话后转发过来；
//  2. 能够查到连接方进程的身份（SO_PEERCRED），因此「这条连接确实来自网关」
//     是一个可核实的事实 —— 见 gatewayConnContext。
//
// 这里刻意与 TCP 监听共用同一套路由：业务逻辑只能有一份。
// 这两点差异都只关乎**通道**，不关乎权限：本应用不解析网关注入的任何身份，
// 两条通道上的会话都必须先自己登录、权限完全相同。
func (s *Server) ListenGateway(path string, h http.Handler) (*GatewayListener, error) {
	if path == "" {
		return nil, errors.New("未指定网关 socket 路径")
	}
	// 上一次进程退出时留下的 socket 文件会让 bind 直接失败（address already in use），
	// 必须先清理。路径由本应用自己指定，不存在误删他人文件的问题。
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("清理旧的网关 socket 失败: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("创建网关 socket 目录失败: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("监听网关 socket 失败: %w", err)
	}
	// socket 文件设为可读写：网关以哪个用户运行不由本应用决定，靠文件权限
	// 拦不住也认不出人。因此文件权限不承担准入职责 —— 能连上不代表能做什么，
	// 会话都必须先自己登录；对端身份只用来判断「这次请求是不是走的网关通道」。
	if err := os.Chmod(path, 0o666); err != nil {
		_ = ln.Close()
		return nil, fmt.Errorf("设置网关 socket 权限失败: %w", err)
	}

	return &GatewayListener{
		Path: path,
		ln:   ln,
		srv: &http.Server{
			Handler:           h,
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       120 * time.Second,
			ConnContext:       s.gatewayConnContext,
		},
	}, nil
}

// Serve 开始服务，直到 ctx 结束或发生不可恢复的错误。
func (g *GatewayListener) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = g.srv.Shutdown(shutdownCtx)
	}()
	if err := g.srv.Serve(g.ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Close 关闭监听并删除 socket 文件，避免留下一个「看起来在监听」的残骸。
func (g *GatewayListener) Close() error {
	err := g.srv.Close()
	_ = os.Remove(g.Path)
	return err
}
