//go:build linux

package api

import (
	"net"

	"golang.org/x/sys/unix"
)

// peerUID 读取 Unix Domain Socket 连接对端进程的有效用户 ID。
//
// 为什么必须做这件事：socket 文件在应用目录里，被 chmod 成网关可写；
// 而 Linux 上**任何有权限打开该文件的本地进程**都能连上来，包括别的第三方应用。
// 只凭「请求是从 socket 来的」就相信 X-Trim-Isadmin，等于把管理员权限交给
// 本机所有用户。SO_PEERCRED 拿到的是内核记录的对端凭据，客户端无法伪造。
func peerUID(c *net.UnixConn) (int, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return -1, err
	}
	uid := -1
	var sockErr error
	err = raw.Control(func(fd uintptr) {
		cred, cerr := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if cerr != nil {
			sockErr = cerr
			return
		}
		uid = int(cred.Uid)
	})
	if err != nil {
		return -1, err
	}
	if sockErr != nil {
		return -1, sockErr
	}
	return uid, nil
}
