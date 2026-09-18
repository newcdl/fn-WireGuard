// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

// Command fnwg-cli 提供命令行运维能力（状态查询、手动收敛、配置导出）。
// 由 config/resource 的 usr-local-linker 暴露到 /usr/local/bin，便于脚本化运维。
package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"fnwg/internal/agentapi"
	"fnwg/internal/config"
	"fnwg/internal/model"
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
	case "user":
		runUser(cfg, os.Args[2:])
	case "security-code":
		runSecurityCode(cfg, os.Args[2:])
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
  fnwg-cli status                 查看连接与设备实时状态
  fnwg-cli netcheck               系统上网路线 + 内网访问链路逐层自检 + 疑似残留网卡
  fnwg-cli cleanup                删除本应用创建的全部网络对象（停用/卸载使用）
  fnwg-cli cleanup-foreign <名称> 清理不是本应用创建的 WireGuard 网卡（疑似残留）
  fnwg-cli reconcile              立即把当前配置下发到内核
  fnwg-cli export --all --out DIR 导出全部连接的 wg-quick 配置
  fnwg-cli version                输出版本

账号与安全码（界面进不去时的后手，需 root / sudo）:
  fnwg-cli user list
      列出全部账号，含是否开启二次验证。
  fnwg-cli user reset-password <账号> [--password <新密码>]
      重置指定账号的密码；不指定新密码时随机生成并显示一次。
      同时作废该账号的受信任设备与全部在线会话。
  fnwg-cli user reset-2fa <账号>
      关闭指定账号的二次验证（清空动态口令、恢复码与受信任设备）。
      适用于用户手机丢失且恢复码也遗失的情况。
  fnwg-cli security-code
      重新生成应急「安全码」（旧码立即作废）。

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
			fmt.Printf("  · %s（%s，%s，%d 台设备，地址 %v）\n", fi.Name, state, port, fi.PeerCount, fi.Addresses)
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

// ---------------------------------------------------------------- 账号与安全码
//
// 这组命令是「后手」的一部分：当界面已经进不去（管理员忘密码、手机丢了、恢复码也没了），
// 只要能 SSH 上来，就能靠它们把控制权收回来。
// 所有操作都会写入审计日志（操作人记为 fnwg-cli），保证后手操作同样可追溯。

// passwordAlphabet 去掉了 0/O、1/l/I 这类易混字符，方便用户照着屏幕手输。
const passwordAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

// randomPassword 生成 20 位随机密码（约 116 位熵），用于重置密码时不想自己想的场景。
func randomPassword() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, len(buf))
	for i, b := range buf {
		out[i] = passwordAlphabet[int(b)%len(passwordAlphabet)]
	}
	return string(out), nil
}

// cliAudit 记录一条来自命令行的操作。
func cliAudit(ctx context.Context, st *store.Store, action, targetID, detail string) {
	_ = st.AddAudit(ctx, &model.AuditEntry{
		Ts:         time.Now(),
		Username:   "fnwg-cli",
		SrcIP:      "local",
		Action:     action,
		TargetType: "user",
		TargetID:   targetID,
		Result:     "ok",
		Message:    detail,
	})
}

func runUser(cfg *config.Config, args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "用法: fnwg-cli user <list|reset-password|reset-2fa>")
		os.Exit(2)
	}
	sub, rest := args[0], args[1:]

	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开数据库失败:", err)
		os.Exit(1)
	}
	defer st.Close()
	ctx := context.Background()

	switch sub {
	case "list":
		users, err := st.ListUsers(ctx)
		if err != nil {
			fmt.Fprintln(os.Stderr, "读取账号失败:", err)
			os.Exit(1)
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ID\t账号\t角色\t状态\t二次验证\t最近登录")
		for _, u := range users {
			status, totp := "启用", "未开启"
			if u.Status != 1 {
				status = "停用"
			}
			if u.TOTPEnabled {
				totp = "已开启"
			}
			last := "-"
			if u.LastLoginAt != nil {
				last = u.LastLoginAt.Local().Format("2006-01-02 15:04")
			}
			fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s\t%s\n", u.ID, u.Username, u.Role, status, totp, last)
		}
		w.Flush()

	case "reset-password":
		name, newPw := "", ""
		for i := 0; i < len(rest); i++ {
			switch rest[i] {
			case "--password", "-p":
				if i+1 < len(rest) {
					newPw = rest[i+1]
					i++
				}
			default:
				if name == "" {
					name = rest[i]
				}
			}
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "用法: fnwg-cli user reset-password <账号> [--password <新密码>]")
			os.Exit(2)
		}
		u, err := st.GetUserByUsername(ctx, name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "账号不存在: %s\n", name)
			os.Exit(1)
		}
		generated := false
		if newPw == "" {
			if newPw, err = randomPassword(); err != nil {
				fmt.Fprintln(os.Stderr, "生成随机密码失败:", err)
				os.Exit(1)
			}
			generated = true
		}
		h, err := service.HashPassword(newPw)
		if err != nil {
			fmt.Fprintln(os.Stderr, "密码不符合要求:", err)
			os.Exit(1)
		}
		u.PasswordHash = h
		if err := st.UpdateUser(ctx, u); err != nil {
			fmt.Fprintln(os.Stderr, "写入失败:", err)
			os.Exit(1)
		}
		// 与界面上「改密码」保持同一条安全约束：作废受信任设备、清掉全部在线会话。
		_ = st.DeleteAllTrustedDevices(ctx, u.ID)
		_ = st.DeleteUserSessions(ctx, u.ID)
		cliAudit(ctx, st, "user.reset_password", u.Username, "通过命令行重置口令")
		if generated {
			fmt.Printf("已将「%s」的密码重置为：%s\n", u.Username, newPw)
			fmt.Println("（此密码只显示这一次，请立即登录并修改）")
		} else {
			fmt.Printf("已重置「%s」的密码。\n", u.Username)
		}
		fmt.Println("该账号的受信任设备与全部在线会话已一并作废。")

	case "reset-2fa":
		if len(rest) == 0 || rest[0] == "" {
			fmt.Fprintln(os.Stderr, "用法: fnwg-cli user reset-2fa <账号>")
			os.Exit(2)
		}
		u, err := st.GetUserByUsername(ctx, rest[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "账号不存在: %s\n", rest[0])
			os.Exit(1)
		}
		if !u.TOTPEnabled {
			fmt.Printf("「%s」未开启二次验证，无需重置。\n", u.Username)
			return
		}
		if err := st.ClearUserTOTP(ctx, u.ID); err != nil {
			fmt.Fprintln(os.Stderr, "重置失败:", err)
			os.Exit(1)
		}
		_ = st.DeleteUserSessions(ctx, u.ID)
		cliAudit(ctx, st, "totp.admin_reset", u.Username, "通过命令行重置二次验证")
		fmt.Printf("已重置「%s」的二次验证：动态口令、恢复码与受信任设备均已清空。\n", u.Username)
		fmt.Println("该账号现在仅凭密码即可登录，请尽快重新绑定。")

	default:
		fmt.Fprintf(os.Stderr, "未知子命令: user %s\n", sub)
		os.Exit(2)
	}
}

func runSecurityCode(cfg *config.Config, _ []string) {
	st, err := openStore(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "打开数据库失败:", err)
		os.Exit(1)
	}
	defer st.Close()
	ctx := context.Background()

	code, err := service.GenerateSecurityCode()
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成安全码失败:", err)
		os.Exit(1)
	}
	h, err := service.HashPassword(code)
	if err != nil {
		fmt.Fprintln(os.Stderr, "生成安全码失败:", err)
		os.Exit(1)
	}
	if err := st.SetSecurityCode(ctx, h); err != nil {
		fmt.Fprintln(os.Stderr, "写入失败:", err)
		os.Exit(1)
	}
	cliAudit(ctx, st, "security.code_issue", "", "通过命令行重新生成安全码")

	fmt.Println("已生成新的安全码（旧的立即作废）：")
	fmt.Println()
	fmt.Println("  " + service.GroupSecurityCode(code))
	fmt.Println()
	fmt.Println("请离线保存（密码管理器或纸质）。它用于「所有登录方式都进不去」时的应急登录，")
	fmt.Println("只能使用一次；用过之后系统会立即下发新的一码，界面也会强提示你保存。")
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
		fmt.Println("当前没有任何连接")
		return
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "连接\t状态\t监听端口\t设备数\t接收\t发送")
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
		fmt.Fprintln(os.Stderr, "存在多个连接，请显式指定 --all 以确认导出全部")
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
