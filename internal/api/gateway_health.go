package api

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"fnwg/internal/model"
)

// 本文件管的是网关入口（飞牛桌面点图标那条通道）在**运行期**的存活。
//
// 为什么需要它：入口是一个文件（appdir/app.sock），在不在由外部因素决定 ——
// 可能被启动脚本顺手删掉、被重新部署清掉，而进程毫无察觉。0.8.22 的真机 502
// 就是这么来的：端口一切正常、进程一直在跑、日志里只有一次启动记录，
// 只有 socket 不见了；而安装/升级/启动时的自查那一刻早就过去了，
// 没有任何人会再检查第二次，于是用户点图标只能看到 502。
//
// 所以这里补上第二道保险：进程自己定期确认入口还在，不在就地重建；
// 并把「失效过」与「已恢复」都写进日志 —— 这类故障的全部线索就是那两行。

// gatewayProbeInterval 是巡检间隔。
//
// 取 15 秒：巡检只是 stat + 连一次本机 socket（微秒级），代价可以忽略；
// 而入口失效期间用户点一次图标就是一次 502，恢复得越快越好。
const gatewayProbeInterval = 15 * time.Second

// 入口 socket 的几种状态。
type gatewaySocketState int

const (
	// gatewaySocketOK：文件在，且确实有人在监听。
	gatewaySocketOK gatewaySocketState = iota
	// gatewaySocketMissing：文件不存在（没绑上，或被外部删掉）。
	gatewaySocketMissing
	// gatewaySocketStale：文件在，但连不上（上次进程被强杀后残留的空壳）。
	gatewaySocketStale
	// gatewaySocketOccupied：路径被一个非 socket 的文件占着。
	gatewaySocketOccupied
)

// probeGatewaySocket 判断入口此刻是否真的可用。
//
// 两步缺一不可：
//  1. 文件在、且是 socket —— 只回答「有没有这个入口」；
//  2. 真去连一次 —— 回答「有没有人在听」。
//
// 只看文件是不够的：进程被 kill -9 之后 socket 文件会残留，那时文件在、
// 却没有任何人监听，从飞牛桌面点进来依然是 502。反之只看「进程启动时绑过一次」
// 也不够：文件可能在运行期被删掉（0.8.22 修的正是这种情况）。
func probeGatewaySocket(path string) gatewaySocketState {
	if path == "" {
		return gatewaySocketMissing
	}
	fi, err := os.Stat(path)
	if err != nil {
		return gatewaySocketMissing
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return gatewaySocketOccupied
	}
	c, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return gatewaySocketStale
	}
	_ = c.Close()
	return gatewaySocketOK
}

// describe 把状态翻译成面向用户的事实与处置办法，供自检页原样展示。
func (st gatewaySocketState) describe(path string) (detail, fix string) {
	switch st {
	case gatewaySocketMissing:
		return fmt.Sprintf("本机没有网关入口 socket（%s），从飞牛桌面点图标会显示 502。", path),
			"应用每 15 秒会自动检查并重建一次；若长期如此，请到应用中心重启本应用，并把这句说明反馈给维护者。"
	case gatewaySocketStale:
		return fmt.Sprintf("网关入口 socket（%s）在，但已经没有进程在监听它，从飞牛桌面点图标会显示 502。", path),
			"应用每 15 秒会自动重建一次；若反复出现，请把这句说明反馈给维护者。"
	case gatewaySocketOccupied:
		return fmt.Sprintf("网关入口的路径（%s）被一个非 socket 的文件占用，入口无法建立。", path),
			"应用只管理自己的对象，不会删除不认识的文件。请确认该文件的来源后手工清理，或重新安装本应用。"
	}
	return "", ""
}

// GatewayKeeper 守护网关入口：首次绑定、定期巡检、失效就地重建。
type GatewayKeeper struct {
	srv     *Server
	path    string
	handler http.Handler
	log     *slog.Logger

	mu      sync.Mutex
	current *GatewayListener
	// lastProblem 记录上一次的失败原因，用于「只在变化时告警」。
	// 少了它，一个持续存在的故障会每 15 秒刷一条同样的日志，把真正有用的那一条淹掉。
	lastProblem string
}

// NewGatewayKeeper 创建入口守护者。path 为入口 socket 的绝对路径。
func (s *Server) NewGatewayKeeper(path string, h http.Handler) *GatewayKeeper {
	return &GatewayKeeper{srv: s, path: path, handler: h, log: s.log}
}

// Run 阻塞地守护入口，直到 ctx 结束。
//
// 首次绑定失败**不算致命**：端口入口照常服务，用户仍能用 IP:端口 访问，
// 日志里如实说明后果即可 —— 这正是这条通道一直以来的定位（桌面图标是便捷入口，
// 不是唯一入口）。
func (k *GatewayKeeper) Run(ctx context.Context) error {
	if err := k.bind(ctx); err != nil {
		k.report(err)
	} else {
		k.log.Info("飞牛统一网关入口已就绪", "socket", k.path)
	}

	t := time.NewTicker(gatewayProbeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// 退出时收掉监听并删除 socket 文件，避免留下一个「看起来在监听」的残骸；
			// 下一次启动由 ExecStartPre 与 ListenGateway 负责清理与重建。
			k.mu.Lock()
			if k.current != nil {
				_ = k.current.Close()
			}
			k.mu.Unlock()
			return nil
		case <-t.C:
			k.patrol(ctx)
		}
	}
}

// patrol 是巡检的一次执行：入口不在就重建。
func (k *GatewayKeeper) patrol(ctx context.Context) {
	st := probeGatewaySocket(k.path)
	if st == gatewaySocketOK {
		if k.lastProblem != "" {
			k.log.Info("飞牛统一网关入口已恢复正常", "socket", k.path)
			k.lastProblem = ""
		}
		return
	}

	if st == gatewaySocketOccupied {
		_, fix := st.describe(k.path)
		k.report(fmt.Errorf("%s", fix))
		return
	}

	// 文件没了，或文件在却没人监听：两种情况都只需重建。
	if err := k.bind(ctx); err != nil {
		k.report(err)
		return
	}
	reason := "socket 文件已不存在"
	if st == gatewaySocketStale {
		reason = "socket 文件在，但已无人监听"
	}
	k.log.Warn("飞牛统一网关入口曾失效，已就地重建（此前从飞牛桌面点图标会显示 502）",
		"socket", k.path, "原因", reason)
	k.lastProblem = ""
}

// bind 建立（或重建）入口监听并开始服务。
func (k *GatewayKeeper) bind(ctx context.Context) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// 旧的先收掉：走到这里说明它已经不可用（文件没了或没人监听），
	// 而它的 socket 文件会挡住即将进行的一次 bind。
	if k.current != nil {
		_ = k.current.Close()
		k.current = nil
	}

	gw, err := k.srv.ListenGateway(k.path, k.handler)
	if err != nil {
		return fmt.Errorf("监听网关入口失败: %w", err)
	}
	k.current = gw
	go func() {
		if err := gw.Serve(ctx); err != nil {
			k.report(fmt.Errorf("网关入口监听异常退出: %w", err))
		}
	}()
	return nil
}

// report 记录一次入口不可用。只在原因变化时写日志。
func (k *GatewayKeeper) report(err error) {
	msg := err.Error()
	if msg == k.lastProblem {
		return
	}
	k.lastProblem = msg
	k.log.Warn("飞牛统一网关入口不可用：从飞牛桌面点图标将报 Bad Gateway（端口入口不受影响）",
		"path", k.path, "err", msg)
}

// gatewayEntryStatus 汇总入口此刻的状态，供自检接口与界面展示。
func (s *Server) gatewayEntryStatus() model.GatewayEntry {
	path := ""
	if p := s.gatewaySockPath.Load(); p != nil {
		path = *p
	}
	if path == "" {
		// 定位不到应用目录时不作断言：这台机器可能根本不走网关这条通道。
		return model.GatewayEntry{
			Detail: "本机未能定位应用目录，未建立网关入口（因此从飞牛桌面点图标不可用）。",
			Fix:    "请重新安装或重启本应用；若反复出现，请把本说明反馈给维护者。",
		}
	}
	st := probeGatewaySocket(path)
	if st == gatewaySocketOK {
		return model.GatewayEntry{Configured: true, Path: path, Ready: true}
	}
	detail, fix := st.describe(path)
	return model.GatewayEntry{Configured: true, Path: path, Detail: detail, Fix: fix}
}
