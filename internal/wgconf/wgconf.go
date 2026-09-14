// Package wgconf 负责 wg-quick 配置文件的解析与渲染，实现与官方工具的互操作。
package wgconf

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"fnwg/internal/model"
)

// File 是一份解析后的 wg-quick 配置。
type File struct {
	Interface InterfaceSection
	Peers     []PeerSection
}

// InterfaceSection 对应 [Interface] 段。
type InterfaceSection struct {
	PrivateKey string
	Addresses  []string
	ListenPort int
	MTU        int
	Table      string
	DNS        []string
	FwMark     string
	PreUp      []string
	PostUp     []string
	PreDown    []string
	PostDown   []string
}

// PeerSection 对应一个 [Peer] 段。
type PeerSection struct {
	Name         string
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
}

// Parse 解析 wg-quick 配置文本，兼容官方 `wg-quick` 的常见写法。
func Parse(text string) (*File, error) {
	f := &File{}
	section := ""
	// pending 保存最近一条注释，用于还原节点备注名。
	// 兼容两种常见写法：[Peer] 之前的注释，以及段内 PublicKey 之前的注释。
	var pending string
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			pending = strings.TrimSpace(strings.TrimLeft(line, "#;"))
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if section == "peer" {
				f.Peers = append(f.Peers, PeerSection{Name: pending})
			}
			pending = ""
			continue
		}
		kv := strings.SplitN(line, "=", 2)
		if len(kv) != 2 {
			return nil, fmt.Errorf("无法解析的行: %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(kv[0]))
		val := strings.TrimSpace(kv[1])
		switch section {
		case "interface":
			if err := applyInterfaceKey(&f.Interface, key, val); err != nil {
				return nil, err
			}
		case "peer":
			if len(f.Peers) == 0 {
				f.Peers = append(f.Peers, PeerSection{Name: pending})
			}
			p := &f.Peers[len(f.Peers)-1]
			if key == "publickey" && p.Name == "" && pending != "" {
				p.Name = pending
			}
			if err := applyPeerKey(p, key, val); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("键 %q 出现在任何段之外", key)
		}
		pending = ""
	}
	if f.Interface.PrivateKey == "" {
		return nil, fmt.Errorf("缺少 Interface.PrivateKey")
	}
	for i, p := range f.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("第 %d 个 [Peer] 缺少 PublicKey", i+1)
		}
	}
	return f, nil
}

func applyInterfaceKey(s *InterfaceSection, key, val string) error {
	switch key {
	case "privatekey":
		s.PrivateKey = val
	case "address":
		s.Addresses = append(s.Addresses, splitList(val)...)
	case "listenport":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("ListenPort 非法: %q", val)
		}
		s.ListenPort = n
	case "mtu":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("MTU 非法: %q", val)
		}
		s.MTU = n
	case "table":
		s.Table = val
	case "dns":
		s.DNS = append(s.DNS, splitList(val)...)
	case "fwmark":
		s.FwMark = val
	case "preup":
		s.PreUp = append(s.PreUp, val)
	case "postup":
		s.PostUp = append(s.PostUp, val)
	case "predown":
		s.PreDown = append(s.PreDown, val)
	case "postdown":
		s.PostDown = append(s.PostDown, val)
	}
	return nil
}

func applyPeerKey(p *PeerSection, key, val string) error {
	switch key {
	case "publickey":
		p.PublicKey = val
	case "presharedkey":
		p.PresharedKey = val
	case "endpoint":
		p.Endpoint = val
	case "allowedips":
		p.AllowedIPs = append(p.AllowedIPs, splitList(val)...)
	case "persistentkeepalive":
		n, err := strconv.Atoi(val)
		if err != nil {
			return fmt.Errorf("PersistentKeepalive 非法: %q", val)
		}
		p.Keepalive = n
	}
	return nil
}

func splitList(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RenderServer 渲染服务端 wg-quick 配置（可直接被 wg-quick 加载）。
func RenderServer(it *model.Interface, peers []model.Peer) string {
	var b strings.Builder
	b.WriteString("# 由 fn-WireGuard 生成，请勿直接手工修改（改动会被收敛引擎覆盖）\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", it.PrivateKey)
	if len(it.Addresses) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(it.Addresses, ", "))
	}
	if it.ListenPort > 0 {
		fmt.Fprintf(&b, "ListenPort = %d\n", it.ListenPort)
	}
	if it.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", it.MTU)
	}
	if it.RouteTable != "" && it.RouteTable != "auto" {
		fmt.Fprintf(&b, "Table = %s\n", it.RouteTable)
	}
	if it.FWMark > 0 {
		fmt.Fprintf(&b, "FwMark = 0x%x\n", it.FWMark)
	}
	for _, line := range splitScripts(it.PostUp) {
		fmt.Fprintf(&b, "PostUp = %s\n", line)
	}
	for _, line := range splitScripts(it.PostDown) {
		fmt.Fprintf(&b, "PostDown = %s\n", line)
	}

	for _, p := range peers {
		b.WriteString("\n[Peer]\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# %s\n", p.Name)
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if ep := p.EndpointString(); ep != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", ep)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Keepalive > 0 {
			fmt.Fprintf(&b, "PersistentKeepalive = %d\n", p.Keepalive)
		}
	}
	return b.String()
}

func splitScripts(s string) []string {
	out := []string{}
	for _, line := range strings.Split(s, "\n") {
		if line = strings.TrimSpace(line); line != "" {
			out = append(out, line)
		}
	}
	return out
}

// RenderClientOptions 控制客户端配置渲染。
type RenderClientOptions struct {
	// Endpoint 是服务端对外地址（host:port）。
	Endpoint string
	// ClientPrivateKey 是客户端私钥。
	ClientPrivateKey string
	// ClientAddress 是分配给客户端的隧道地址（CIDR）。
	ClientAddress []string
	// AllowedIPs 是客户端侧的路由（决定全局代理或分流）。
	AllowedIPs []string
	// DNS 下发给客户端的 DNS。
	DNS []string
	// MTU 可选。
	MTU int
	// Keepalive 保活间隔。
	Keepalive int
}

// RenderClient 渲染客户端配置。
func RenderClient(serverPublicKey string, it *model.Interface, p *model.Peer, opt RenderClientOptions) string {
	if opt.Keepalive == 0 {
		opt.Keepalive = 25
	}
	if len(opt.AllowedIPs) == 0 {
		opt.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	if len(opt.DNS) == 0 {
		opt.DNS = it.DNS
	}
	var b strings.Builder
	b.WriteString("# 由 fn-WireGuard 生成\n")
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", opt.ClientPrivateKey)
	if len(opt.ClientAddress) > 0 {
		fmt.Fprintf(&b, "Address = %s\n", strings.Join(opt.ClientAddress, ", "))
	}
	if len(opt.DNS) > 0 {
		fmt.Fprintf(&b, "DNS = %s\n", strings.Join(opt.DNS, ", "))
	}
	if opt.MTU > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", opt.MTU)
	}
	b.WriteString("\n[Peer]\n")
	if p != nil && p.Name != "" {
		fmt.Fprintf(&b, "# %s\n", p.Name)
	}
	fmt.Fprintf(&b, "PublicKey = %s\n", serverPublicKey)
	if p != nil && p.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
	}
	if opt.Endpoint != "" {
		fmt.Fprintf(&b, "Endpoint = %s\n", opt.Endpoint)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(opt.AllowedIPs, ", "))
	if opt.Keepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", opt.Keepalive)
	}
	return b.String()
}

// SplitClientAndServerIPs 把节点的 AllowedIPs 拆成「客户端自身地址」与「客户端可见网段」。
func SplitClientAndServerIPs(it *model.Interface, p *model.Peer) (clientAddrs []string, routes []string) {
	subnets := make([]*net.IPNet, 0, len(it.Addresses))
	for _, a := range it.Addresses {
		if _, n, err := net.ParseCIDR(a); err == nil {
			subnets = append(subnets, n)
		}
	}
	for _, a := range p.AllowedIPs {
		ip, _, err := net.ParseCIDR(a)
		if err != nil {
			continue
		}
		inTunnel := false
		for _, sn := range subnets {
			if sn.Contains(ip) {
				inTunnel = true
				break
			}
		}
		if inTunnel {
			// 落在隧道网段内 → 该地址属于客户端自身
			clientAddrs = append(clientAddrs, a)
		} else {
			// 隧道外网段 → 客户端可通过该节点访问的目标
			routes = append(routes, a)
		}
	}
	if len(clientAddrs) == 0 && len(p.AllowedIPs) > 0 {
		clientAddrs = []string{p.AllowedIPs[0]}
	}
	return clientAddrs, routes
}

func prefixLen(n *net.IPNet) int {
	ones, _ := n.Mask.Size()
	return ones
}

// MergeCIDRs 去重并排序网段列表。
func MergeCIDRs(in []string) []string {
	set := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || set[s] {
			continue
		}
		set[s] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		ai, an, errA := net.ParseCIDR(a)
		bi, bn, errB := net.ParseCIDR(b)
		if errA != nil || errB != nil {
			return a < b
		}
		if (ai.To4() == nil) != (bi.To4() == nil) {
			return ai.To4() != nil
		}
		if c := bytesCompare(an.IP, bn.IP); c != 0 {
			return c < 0
		}
		ao, _ := an.Mask.Size()
		bo, _ := bn.Mask.Size()
		return ao < bo
	})
	return out
}

func bytesCompare(a, b net.IP) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}
