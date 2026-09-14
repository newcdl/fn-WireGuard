package service

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strings"

	"fnwg/internal/wgconf"
	"fnwg/internal/wgkey"
)

// newUUID 生成 UUID v4 形式的随机标识。
func newUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]), hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]), hex.EncodeToString(b[10:16]))
}

// newToken 生成不可预测的会话/接口令牌。
func newToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// newPSK 生成预共享密钥。
func newPSK() (string, error) { return wgkey.GeneratePSK() }

// detectLocalSubnets 探测本机局域网网段（用于「只访问家里设备」模式下的客户端配置）。
// 会刻意排除容器/虚拟网卡与隧道网段，避免把 Docker 网络等暴露给客户端。
func detectLocalSubnets() []string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	out := []string{}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isVirtualInterface(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			if cgnat.Contains(ip4) {
				continue
			}
			masked := &net.IPNet{IP: ip4.Mask(ipnet.Mask), Mask: ipnet.Mask}
			if ones, _ := masked.Mask.Size(); ones >= 31 {
				continue // /31、/32 视为点对点地址
			}
			out = append(out, masked.String())
		}
	}
	return wgconf.MergeCIDRs(out)
}

// cgnat 运营商级 NAT 网段（内网穿透类服务常用），不作为"家里内网"暴露给客户端。
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isVirtualInterface(name string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "wg", "tun", "tap", "kube", "flannel", "cni"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// detectLocalIPv4 尝试探测本机可用于对外连接的 IPv4 地址。
func detectLocalIPv4() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			return ip.String()
		}
	}
	return ""
}
