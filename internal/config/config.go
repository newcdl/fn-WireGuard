// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package config 负责加载 fn-WireGuard 的运行期配置。
// 配置来源优先级：命令行参数 > TRIM_* 环境变量（fnOS 注入）> 默认值。
package config

import (
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config 是 fnwg-web / fnwg-agent 共用的运行期配置。
type Config struct {
	// Version 由构建脚本通过 -ldflags 注入
	Version string
	// Group 是运行用户组名，Web 进程以该用户运行，Agent 用它调整共享文件属组。
	Group string

	// Port 是 Web 服务监听端口，来自 manifest 的 service_port / TRIM_SERVICE_PORT。
	Port int
	// Bind 是监听地址，默认 0.0.0.0。
	Bind string

	// EtcDir 静态配置目录（TRIM_PKGETC）。
	EtcDir string
	// VarDir 动态数据目录（TRIM_PKGVAR），数据库与密钥落在此处。
	VarDir string
	// HomeDir 用户数据目录（TRIM_PKGHOME）。
	HomeDir string
	// AppDest 可执行文件目录（TRIM_APPDEST）。
	AppDest string

	// SocketPath 特权代理的 Unix Domain Socket 路径。
	SocketPath string

	// Dev 为本地开发模式：不依赖 fnwg-agent，直接使用内存后端。
	Dev bool

	// Timezone 仅用于日志展示，留空使用系统时区。
	Timezone string

	// LogLevel 控制日志详细程度：debug / info / warn / error，默认 info。
	LogLevel string

	// Once 仅用于 fnwg-agent：执行一次收敛后退出（便于排查与脚本化）。
	Once bool
	// Cleanup 仅用于 fnwg-agent：删除本应用创建的全部内核对象后退出（停用/卸载使用）。
	Cleanup bool
}

// Load 解析命令行参数与环境变量。
func Load(args []string) *Config {
	defaultVar := envOr("TRIM_PKGVAR", filepath.Join(os.TempDir(), "fn-wireguard"))
	c := &Config{
		Version:    "0.1.0-dev",
		Group:      envOr("FNWG_GROUP", "fnwg"),
		Port:       envInt("TRIM_SERVICE_PORT", 0),
		Bind:       "0.0.0.0",
		EtcDir:     envOr("TRIM_PKGETC", filepath.Join(defaultVar, "etc")),
		VarDir:     defaultVar,
		HomeDir:    envOr("TRIM_PKGHOME", filepath.Join(defaultVar, "home")),
		AppDest:    envOr("TRIM_APPDEST", "."),
		SocketPath: "",
		Dev:        false,
		Timezone:   envOr("TRIM_SYS_LANGUAGE", ""),
		LogLevel:   envOr("FNWG_LOG_LEVEL", "info"),
	}

	fs := flag.NewFlagSet("fnwg", flag.ContinueOnError)
	fs.IntVar(&c.Port, "port", c.Port, "Web 监听端口")
	fs.StringVar(&c.Bind, "bind", c.Bind, "Web 监听地址")
	fs.StringVar(&c.EtcDir, "etc", c.EtcDir, "静态配置目录")
	fs.StringVar(&c.VarDir, "var", c.VarDir, "动态数据目录")
	fs.StringVar(&c.HomeDir, "home", c.HomeDir, "用户数据目录")
	fs.StringVar(&c.AppDest, "appdest", c.AppDest, "可执行文件目录")
	fs.StringVar(&c.SocketPath, "socket", "", "特权代理 socket 路径")
	fs.StringVar(&c.Group, "group", c.Group, "运行用户组（共享文件属组）")
	fs.BoolVar(&c.Dev, "dev", false, "开发模式：使用内存后端，不连接特权代理")
	fs.BoolVar(&c.Once, "once", false, "只执行一次收敛后退出（fnwg-agent）")
	fs.BoolVar(&c.Cleanup, "cleanup", false, "删除本应用创建的全部网络对象后退出（fnwg-agent）")
	fs.StringVar(&c.LogLevel, "log-level", c.LogLevel, "日志级别：debug / info / warn / error")
	_ = fs.Parse(args)

	if c.Port == 0 {
		c.Port = 8080
	}
	if c.SocketPath == "" {
		c.SocketPath = filepath.Join(c.VarDir, "agent.sock")
	}
	return c
}

// SlogLevel 把 LogLevel 文本转成 slog 级别，无法识别时回退 info。
//
// 之所以要有这个开关：像「请求到底有没有到达服务端」这类问题，只有 Debug 级的
// 访问日志（见 api.accessLog）能回答，而它平时必须保持关闭 —— 每个请求记一行
// 会把真正重要的日志淹掉。做成运行期可调，排障时改一行 systemd 环境变量即可，
// 不必为了看一眼请求轨迹重新打包发版。
func (c *Config) SlogLevel() slog.Level {
	switch strings.ToLower(strings.TrimSpace(c.LogLevel)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// DBPath 返回 SQLite 数据库文件路径。
func (c *Config) DBPath() string { return filepath.Join(c.VarDir, "fnwg.db") }

// MasterKeyPath 返回主密钥文件路径（AES-256-GCM，用于加密私钥落库）。
func (c *Config) MasterKeyPath() string { return filepath.Join(c.VarDir, "master.key") }

// NetStatePath 返回网络安全状态文件路径。
// 该文件记录本应用创建过的接口与接管前的系统路由基线，用于限定清理范围、避免误改系统。
func (c *Config) NetStatePath() string { return filepath.Join(c.VarDir, "netstate.json") }

// LogDir 返回日志目录。
func (c *Config) LogDir() string { return filepath.Join(c.VarDir, "log") }

// AppSockFile 是飞牛统一网关约定的 socket 文件名。
//
// 官方要求 gatewaySocket 只填文件名（不能带路径），且文件必须落在应用的
// target 目录下，因此这里只暴露文件名，路径由 AppSockPath 拼出来。
const AppSockFile = "app.sock"

// AppSockPath 返回飞牛统一网关使用的 Unix Socket 路径。
//
// 位置由网关约定：必须是应用 target 目录下的 app.sock，写成别处网关就找不到。
// 取址顺序是「显式传入的 --appdest / TRIM_APPDEST → 可执行文件所在目录」。
//
// 为什么必须有第二级兜底：二进制本身就装在 target 目录里，所以「可执行文件在哪，
// socket 就在哪」恒成立；而 TRIM_APPDEST 只存在于安装/配置脚本的进程环境里，
// **systemd 不会继承它**。只认 TRIM_APPDEST 的话，服务由 systemd 拉起时会退化成
// 「相对当前工作目录」——systemd 下即 /，普通用户无权在那里建 socket，bind 直接失败，
// 最终表现为「从飞牛桌面点图标只有 502」，而日志里只有一句容易被忽略的警告。
func (c *Config) AppSockPath() string {
	if dir := c.appDestDir(); dir != "" {
		return filepath.Join(dir, AppSockFile)
	}
	return ""
}

// appDestDir 返回应用 target 目录；两种来源都拿不到时返回空串。
func (c *Config) appDestDir() string {
	if d := strings.TrimSpace(c.AppDest); filepath.IsAbs(d) {
		return d
	}
	// 回退到可执行文件目录。先解析软链：网关找的是真实 target 目录，
	// 而不是软链所在的位置（fnOS 会在 /usr/local/bin 下建软链）。
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	dir := filepath.Dir(exe)
	if dir == "" || dir == "." || dir == string(filepath.Separator) {
		return ""
	}
	return dir
}

// ShareDir 返回面向用户的共享导出目录（fnOS data-share）。
// 优先使用 fnOS 依据 config/resource 创建的共享目录，其次回退到 var/share。
func (c *Config) ShareDir() string {
	for _, name := range []string{"fn-wireguard", "wireguard"} {
		p := filepath.Join(c.VarDir, "shares", name)
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			return p
		}
	}
	return filepath.Join(c.VarDir, "share")
}

// AuthorizedDirs 返回用户在飞牛里授予本应用访问权限的目录。
//
// 它和 config/resource 里声明的 data-share 不是一回事：那是「本应用把自己的数据暴露出去」，
// 这里是「用户允许本应用碰他的哪些目录」。应用只能写进这两类目录，别处一律 permission denied——
// 所以计划备份的目标目录只能从这份清单里选：让用户手填一个看起来对、实际写不进去的路径，
// 结果就是开关打开、每天失败一次，而界面上什么都看不出来。
//
// 两个来源，按顺序取：
//  1. TRIM_DATA_ACCESSIBLE_PATHS —— 官方变量，只在「飞牛调用我们脚本」的那个环境里有；
//  2. FNWG_AUTHORIZED_DIRS —— 我们自己转写的同名值，写进 systemd 单元（见 cmd/common 的
//     fnwg_authorized_env_line）。**服务进程必须要它**：systemd 拉起的进程不继承
//     调用者的环境，只看第 1 个来源的话，服务永远读到空值，用户就会看到
//     「明明授权了、也重启了，界面里还是一个目录都没有」。
//
// 变量按官方约定用半角冒号分隔、不是 JSON，可能为空或含空项（例如结尾多一个冒号），都要挡住。
func (c *Config) AuthorizedDirs() []string {
	raw := strings.TrimSpace(os.Getenv("TRIM_DATA_ACCESSIBLE_PATHS"))
	if raw == "" {
		raw = strings.TrimSpace(os.Getenv("FNWG_AUTHORIZED_DIRS"))
	}
	if raw == "" {
		return nil
	}
	out := make([]string, 0, 4)
	seen := map[string]bool{}
	for _, p := range strings.Split(raw, ":") {
		p = strings.TrimSpace(p)
		if p == "" || !filepath.IsAbs(p) || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, filepath.Clean(p))
	}
	return out
}

// EnsureDirs 创建所有必需目录。
func (c *Config) EnsureDirs() error {
	for _, d := range []string{c.VarDir, c.EtcDir, c.HomeDir, c.LogDir(), c.ShareDir()} {
		if err := os.MkdirAll(d, 0o770); err != nil {
			return err
		}
	}
	return nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
