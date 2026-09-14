package wgback

import (
	"net"
	"sort"
	"strings"
)

// 本文件实现「节点增量下发」。
//
// 背景（曾经导致隧道抖动的真实故障）：
// 早期实现每轮收敛都用 wgtypes.Config{ReplacePeers: true} 全量下发节点。
// 内核收到 WGDEVICE_F_REPLACE_PEERS 后会执行 wg_peer_remove_all()，
// 把该接口的所有节点删掉再按新配置重建 —— 这会一并丢弃：
//   - 已经协商好的会话密钥（noise 握手状态），客户端必须重新握手；
//   - 内核动态学习到的对端 endpoint（客户端在 NAT 后主动连入时才知道的地址）；
//   - last_handshake / rx / tx 等统计。
// 由于收敛每 10 秒跑一轮，客户端因此被周期性强制重新握手，
// 表现为「隧道是通的，但抖动、突发连续丢包」。
//
// 同理，对已有节点重新下发 PresharedKey 也会触发
// wg_noise_expire_current_peer_keypairs()，同样会销毁当前会话密钥。
//
// 修复原则：只下发**真正发生变化**的节点与字段。
// 没有变化的节点完全不进入下发请求，内核就不会触碰它的任何状态。

// PeerDiffKind 是节点变更类型。
type PeerDiffKind string

const (
	// PeerDiffAdd 新增节点（需要下发完整字段）。
	PeerDiffAdd PeerDiffKind = "add"
	// PeerDiffUpdate 已有节点，仅部分字段变化。
	PeerDiffUpdate PeerDiffKind = "update"
	// PeerDiffRemove 从配置中移除节点。
	PeerDiffRemove PeerDiffKind = "remove"
)

// PeerWant 是期望态里的一个节点。
// Endpoint 必须是已解析好的 ip:port；为空表示「交给内核动态学习」，绝不覆盖。
type PeerWant struct {
	PublicKey    string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
	HasPreshared bool
}

// PeerHave 是内核当前状态里的一个节点。
type PeerHave struct {
	PublicKey    string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
	HasPreshared bool
}

// PeerDiff 是一次需要下发到内核的节点变更。
//
// 这里刻意不携带任何密钥明文：需要重新下发口令时只置位 SetPresharedKey，
// 由调用方按 PublicKey 自行取值，避免密钥在多个结构体之间搬运。
type PeerDiff struct {
	Kind      PeerDiffKind
	PublicKey string
	// Fields 是发生变化的字段（中文），用于说明「为什么下发」。
	Fields []string

	Endpoint      string
	SetEndpoint   bool
	AllowedIPs    []string
	SetAllowedIPs bool
	Keepalive     int
	SetKeepalive  bool

	// SetPresharedKey 表示需要重新下发二次加密口令。
	SetPresharedKey bool
	// PresharedWanted 为真表示期望「有口令」，为假表示期望「清除口令」。
	PresharedWanted bool
}

// DiffPeers 比较期望态与内核现状，返回最小必要变更集合。
//
// pskNeedsPush 用于判断「两边都有二次加密口令时，内容是否已经变化」：
// 内核不返回口令明文，只能由调用方用本地指纹判断；传 nil 表示无法判断（按未变化处理）。
func DiffPeers(want []PeerWant, have []PeerHave, pskNeedsPush func(publicKey string) bool) []PeerDiff {
	haveIdx := make(map[string]PeerHave, len(have))
	for _, h := range have {
		if h.PublicKey != "" {
			haveIdx[h.PublicKey] = h
		}
	}

	seen := make(map[string]bool, len(want))
	out := []PeerDiff{}

	for _, w := range want {
		if w.PublicKey == "" {
			continue
		}
		seen[w.PublicKey] = true

		h, exists := haveIdx[w.PublicKey]
		if !exists {
			out = append(out, PeerDiff{
				Kind:            PeerDiffAdd,
				PublicKey:       w.PublicKey,
				Fields:          []string{"新节点"},
				Endpoint:        w.Endpoint,
				SetEndpoint:     w.Endpoint != "",
				AllowedIPs:      w.AllowedIPs,
				SetAllowedIPs:   true,
				Keepalive:       w.Keepalive,
				SetKeepalive:    true,
				SetPresharedKey: w.HasPreshared,
				PresharedWanted: w.HasPreshared,
			})
			continue
		}

		d := PeerDiff{Kind: PeerDiffUpdate, PublicKey: w.PublicKey}

		if !sameCIDRSet(w.AllowedIPs, h.AllowedIPs) {
			d.SetAllowedIPs = true
			d.AllowedIPs = w.AllowedIPs
			d.Fields = append(d.Fields, "通行范围")
		}
		if w.Keepalive != h.Keepalive {
			d.SetKeepalive = true
			d.Keepalive = w.Keepalive
			d.Fields = append(d.Fields, "保活心跳")
		}
		// Endpoint：期望为空表示交给内核动态学习，绝不覆盖。
		// 服务端场景（客户端在 NAT 后主动连入）正是靠这一点保住已建立的连接。
		if w.Endpoint != "" && !sameEndpoint(w.Endpoint, h.Endpoint) {
			d.SetEndpoint = true
			d.Endpoint = w.Endpoint
			d.Fields = append(d.Fields, "对端地址")
		}
		switch {
		case w.HasPreshared && !h.HasPreshared:
			d.SetPresharedKey = true
			d.PresharedWanted = true
			d.Fields = append(d.Fields, "二次加密口令")
		case !w.HasPreshared && h.HasPreshared:
			d.SetPresharedKey = true
			d.PresharedWanted = false
			d.Fields = append(d.Fields, "清除二次加密口令")
		case w.HasPreshared && h.HasPreshared && pskNeedsPush != nil && pskNeedsPush(w.PublicKey):
			// 两边都有口令但内容已变（用户轮换了口令）——
			// 内核不返回明文，只能靠调用方的本地指纹判断。
			d.SetPresharedKey = true
			d.PresharedWanted = true
			d.Fields = append(d.Fields, "轮换二次加密口令")
		}

		if len(d.Fields) > 0 {
			out = append(out, d)
		}
	}

	for _, h := range have {
		if h.PublicKey == "" || seen[h.PublicKey] {
			continue
		}
		out = append(out, PeerDiff{
			Kind:      PeerDiffRemove,
			PublicKey: h.PublicKey,
			Fields:    []string{"已从配置中移除"},
		})
	}
	return out
}

// sameCIDRSet 比较两组网段是否等价（忽略书写顺序与主机位差异）。
func sameCIDRSet(a, b []string) bool {
	na, nb := normalizeCIDRs(a), normalizeCIDRs(b)
	if len(na) != len(nb) {
		return false
	}
	for i := range na {
		if na[i] != nb[i] {
			return false
		}
	}
	return true
}

func normalizeCIDRs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			out = append(out, s)
			continue
		}
		out = append(out, n.String())
	}
	sort.Strings(out)
	return out
}

// sameEndpoint 比较两个 ip:port 是否指向同一地址。
func sameEndpoint(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return a == b
	}
	ua, errA := net.ResolveUDPAddr("udp", a)
	ub, errB := net.ResolveUDPAddr("udp", b)
	if errA != nil || errB != nil {
		return a == b
	}
	return ua.IP.Equal(ub.IP) && ua.Port == ub.Port
}
