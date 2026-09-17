//go:build !linux

package api

import (
	"errors"
	"net"
)

// peerUID 在非 Linux 平台取不到 Unix Socket 对端凭据。
//
// 生产环境（飞牛 NAS）只跑 Linux，这里的存在只是为了让开发机上的
// go build / go test 能通过。返回错误而不是「假装可信」：
// 宁可让开发环境里的网关免密登录不可用，也不要在真实环境里悄悄放行。
func peerUID(*net.UnixConn) (int, error) {
	return -1, errors.New("当前平台不支持读取 Unix Socket 对端身份")
}
