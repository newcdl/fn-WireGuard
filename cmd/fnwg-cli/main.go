// Command fnwg-cli 提供命令行运维能力（状态查询、手动收敛、配置导出）。
// 由 config/resource 的 usr-local-linker 暴露到 /usr/local/bin，便于脚本化运维。
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"fnwg/internal/agentapi"
	"fnwg/internal/config"
	"fnwg/internal/secretbox"
	"fnwg/internal/service"
	"fnwg/internal/store"
	"fnwg/internal/wgback"
)

// buildVersion 由构建脚本通过 -ldflags "-X main.buildVersion=..." 注入。
// 缺少这个变量时 -ldflags 会被静默忽略，`fnwg-cli version` 就会报出错误的版本号。
var buildVersion string

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cfg := config.Load(os.Args[2:])
	switch {
	case buildVersion != "":
		cfg.Version = buildVersion
	case os.Getenv("FNWG_BUILD_VERSION") != "":
		cfg.Version = os.Getenv("FNWG_BUILD_VERSION")
	}
	cmd := os.Args[1]

	switch cmd {
	case "version", "-v", "--version":
		fmt.Println("WireGuard 管理工具", cfg.Version)
	case "status":
		runStatus(cfg)
	case "reconcile":
		runReconcile(cfg)
	case "export":
		runExport(cfg, os.Args[2:])
	case "cleanup":
		runCleanup(cfg)
	case "cleanup-foreign":
		name := ""
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		runCleanupForeign(cfg, name)
	case "netcheck":
		runNetCheck(cfg)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Print(`WireGuard 管理工具 命令行工具

用法:
  fnwg-cli status                 查看接口与节点实时状态
  fnwg-cli netcheck               检查 NAS 系统上网路线是否被本应用影响
  fnwg-cli cleanup                删除本应用创建的全部网络对象（停用/卸载使用）
  fnwg-cli cleanup-foreign <名称> 清理不是本应用创建的 WireGuard 网卡（疑似残留）
  fnwg-cli reconcile              立即把数据库期望态下发到内核
  fnwg-cli export --all --out DIR 导出全部接口的 wg-quick 配置
  fnwg-cli version                输出版本

环境变量与 fnOS 一致（TRIM_PKGVAR / TRIM_PKGETC 等），也可用 --var / --socket 覆盖。

本工具位于 /usr/local/bin/fnwg-cli。sudo 会按自己的 secure_path 查找命令，
若提示 "sudo: fnwg-cli: command not found"，请改用绝对路径调用：
  sudo /usr/local/bin/fnwg-cli <命令>
`)
}

// runCleanup 只清理本应用创建的内核对象，绝不触碰系统或其他应用的对象。
func runCleanup(cfg *config.Config) {
	backend := wgback.New(cfg.NetStatePath())
	actions, err := backend.Cleanup(context.Background())
	for _, a := range actions {
		fmt.Println("·", a)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "清理未完全成功:", err)
		os.Exit(1)
	}
	if len(actions) == 0 {
		fmt.Println("没有需要清理的对象")
	}
}

// runCleanupForeign 清理一个不是本应用创建的 WireGuard 网卡（疑似历史残留）。
//
// 这是命令行里唯一会触碰非受管对象的能力，因此数据面后端会再次校验
// 该网卡的 link 类型必须是 wireguard —— 普通网卡一律拒绝。
func runCleanupForeign(cfg *config.Config, name string) {
	if name == "" {
		fmt.Fprintln(os.Stderr, "用法: fnwg-cli cleanup-foreign <网卡名称>")
		fmt.Fprintln(os.Stderr, "可用 fnwg-cli netcheck 查看当前有哪些疑似残留。")
		os.Exit(2)
	}
	backend := wgback.New(cfg.NetStatePath())
	actions, err := backend.DeleteForeignInterface(name)
	for _, a := range actions {
		fmt.Println("·", a)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "清理失败:", err)
		os.Exit(1)
	}
}

// runNetCheck 网络自检（只读）。
func runNetCheck(cfg *config.Config) {
	backend := wgback.New(cfg.NetStatePath())
	rep, err := backend.Inspect(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "自检失败:", err)
		os.Exit(1)
	}
	fmt.Printf("本应用创建的连接: %v\n", rep.ManagedInterfaces)
	if len(rep.ForeignInterfaces) > 0 {
		fmt.Println("疑似残留（不是本应用创建的 WireGuard 网卡）:")
		for _, fi := range rep.ForeignInterfaces {
			state := "已停止"
			if fi.Up {
				state = "运行中"
			}
			port := "未监听"
			if fi.ListenPort > 0 {
				port = fmt.Sprintf("占用 UDP 端口 %d", fi.ListenPort)
			}
			fmt.Printf("  · %s（%s，%s，%d 个节点，地址 %v）\n", fi.Name, state, port, fi.PeerCount, fi.Addresses)
		}
		fmt.Println("  它们可能是早期版本卸载时没清理干净的残留，也可能是其它工具（如手工 wg-quick）在用。")
		fmt.Println("  确认无用后可用：fnwg-cli cleanup-foreign <名称>  清理")
	}
	if rep.NAT.Active {
		src := "无"
		if len(rep.NAT.Sources) > 0 {
			src = strings.Join(rep.NAT.Sources, "、")
		}
		wan := "无"
		if len(rep.NAT.WANs) > 0 {
			wan = strings.Join(rep.NAT.WANs, "、")
		}
		fmt.Printf("内网访问: 已开启（%s 的设备经 %s 访问 NAS 所在局域网）\n", src, wan)
	} else if rep.NAT.Note != "" {
		fmt.Println("内网访问: 异常 -", rep.NAT.Note)
	} else {
		fmt.Println("内网访问: 未开启（连进来的设备只能访问 NAS 本身）")
	}
	// 逐项自检：访问不了家里其它设备时，看哪一项是「未通过」
	if len(rep.NAT.Checks) > 0 {
		fmt.Println("内网访问链路自检:")
		for _, c := range rep.NAT.Checks {
			mark := "通过  "
			if !c.OK {
				mark = "未通过"
			}
			fmt.Printf("  [%s] %s：%s\n", mark, c.Label, c.Detail)
			if !c.OK && c.Fix != "" {
				fmt.Printf("            → %s\n", c.Fix)
			}
		}
	}
	fmt.Println("NAS 自身的上网路线:")
	for _, d := range rep.Defaults {
		fmt.Printf("  · dev=%s via=%s metric=%d\n", d.Dev, d.Gw, d.Metric)
	}
	if len(rep.Defaults) == 0 {
		if rep.RouteInfoReadable {
			fmt.Println("  （没有可用默认路由，请到系统网络设置中重新保存网卡配置）")
		} else {
			fmt.Println("  （当前为演示模式，无法读取真实路由表）")
		}
	}
	if len(rep.StrayDefaults) > 0 {
		fmt.Println("发现异常：以下默认路由指向本应用的连接，应当清除：")
		for _, d := range rep.StrayDefaults {
			fmt.Printf("  · dev=%s via=%s\n", d.Dev, d.Gw)
		}
		fmt.Println("请执行 fnwg-cli cleanup，或在界面「系统设置 → 运行状态」中点击立即修复。")
	} else {
		fmt.Println("未发现影响 NAS 系统网络的异常。")
	}
}

func openStore(cfg *config.Config) (*store.Store, error) {
	box, err := secretbox.LoadOrCreate(cfg.MasterKeyPath())
	if err != nil {
		return nil, err
	}
	return store.Open(cfg.DBPath(), box)
}

func runStatus(cfg *config.Config) {
	client := agentapi.NewClient(cfg.SocketPath)
	ctx := context.Background()
	health, err := client.Health(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "无法连接特权代理:", err)
		os.Exit(1)
	}
	fmt.Printf("后端: %s  内核模块: %v  用户态 TUN: %v  版本: %s\n",
		health.Backend, health.KernelModule, health.TunDevice, health.AgentVersion)

	st, err := client.Status(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "获取状态失败:", err)
		os.Exit(1)
	}
	if len(st.Interfaces) == 0 {
		fmt.Println("当前没有任何 WireGuard 接口")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "接口\t状态\t监听端口\t节点数\t接收\t发送")
	for _, it := range st.Interfaces {
		up := "down"
		if it.Up {
			up = "up"
		}
		var rx, tx int64
		for _, p := range it.Peers {
			rx += p.RxBytes
			tx += p.TxBytes
		}
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n", it.Name, up, it.ListenPort, len(it.Peers), human(rx), human(tx))
	}
	_ = w.Flush()
}

func runReconcile(cfg *config.Config) {
	client := agentapi.NewClient(cfg.SocketPath)
	actions, err := client.Reconcile(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "收敛失败:", err)
		os.Exit(1)
	}
	if len(actions) == 0 {
		fmt.Println("配置已是最新，无需变更")
		return
	}
	for _, a := range actions {
		fmt.Println("·", a)
	}
}

func runExport(cfg *config.Config, args []string) {
	outDir := "."
	all := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--out", "-o":
			if i+1 < len(args) {
				outDir = args[i+1]
				i++
			}
		case "--all":
			all = true
		}
	}
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer st.Close()
	svc := service.New(st, nil, nil, cfg.Version)
	ctx := context.Background()
	ifaces, err := svc.ListInterfaces(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if !all && len(ifaces) > 1 {
		fmt.Fprintln(os.Stderr, "存在多个接口，请显式指定 --all 以确认导出全部")
		os.Exit(1)
	}
	if err := os.MkdirAll(outDir, 0o770); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, it := range ifaces {
		name, conf, err := svc.InterfaceConf(ctx, it.ID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "导出 %s 失败: %v\n", it.Name, err)
			continue
		}
		path := filepath.Join(outDir, name+".conf")
		if err := os.WriteFile(path, []byte(conf), 0o600); err != nil {
			fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
			continue
		}
		fmt.Println("已导出", path)
	}
}

func human(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(n)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return fmt.Sprintf("%.1f%s", v, units[i])
}
