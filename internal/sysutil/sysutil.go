// Package sysutil 提供与操作系统权限相关的小工具。
//
// 背景：fnfg-agent 以 root 运行、fnwg-web 以普通用户 fnwg 运行，两者共享同一份
// SQLite 数据库与主密钥文件。为保证两个进程都能读写，需要统一属组与权限位，
// 并以 0002 的 umask 让新建文件（如 SQLite 的 -wal/-shm）默认对同组可写。
package sysutil

import (
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// Umask 设置进程 umask 并返回旧值。
func Umask(mask int) int { return syscall.Umask(mask) }

// LookupGID 解析用户组 ID，失败返回 -1。
func LookupGID(name string) int {
	if name == "" {
		return -1
	}
	g, err := user.LookupGroup(name)
	if err != nil {
		return -1
	}
	v, err := strconv.Atoi(g.Gid)
	if err != nil {
		return -1
	}
	return v
}

// FixGroup 把路径的属组调整为 gid，并把权限设置为 mode。
// 路径不存在时静默跳过（例如 SQLite 的 -wal 文件尚未创建）。
func FixGroup(path string, gid int, mode os.FileMode) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	if gid >= 0 {
		_ = os.Chown(path, -1, gid)
	}
	if mode != 0 {
		_ = os.Chmod(path, mode)
	}
}
