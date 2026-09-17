package wgback

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// 本文件实现 wireguard-go UAPI 的编解码。
//
// UAPI 是配置的文本协议：每行 `key=value`，空行结束；密钥用十六进制而非 base64。
// 之所以自己编码而不直接复用 wireguard-go 的内部解析器，是因为它只提供
// 「整包 set」这一个入口，没有「只改某个字段」的公开能力 ——
// 而「只把真正变化的行写进去」正是防抖动的关键（见 peerdiff.go 的说明）。

// encodeUAPISet 把一次增量下发编码为 UAPI set 文本。
//
// 刻意**绝不输出 replace_peers**：它会删光全部节点再按新配置重建，
// 与内核模式的 ReplacePeers 一样会摧毁已协商的会话密钥、内核学到的对端地址与统计，
// 表现就是「隧道通但周期性抖动」。同理，没有变化的节点压根不会出现在文本里。
func encodeUAPISet(cfg wgtypes.Config) string {
	var b strings.Builder

	if cfg.PrivateKey != nil {
		writeUAPIKey(&b, "private_key", *cfg.PrivateKey)
	}
	// fwmark 放在 listen_port 之前：wireguard-go 每次设置 fwmark 都会重新绑定套接字，
	// 先定标记再定端口，端口就只绑定一次、不出现无谓的抖动。
	if cfg.FirewallMark != nil {
		fmt.Fprintf(&b, "fwmark=%d\n", *cfg.FirewallMark)
	}
	if cfg.ListenPort != nil {
		fmt.Fprintf(&b, "listen_port=%d\n", *cfg.ListenPort)
	}

	for _, p := range cfg.Peers {
		writeUAPIKey(&b, "public_key", p.PublicKey)
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.PresharedKey != nil {
			writeUAPIKey(&b, "preshared_key", *p.PresharedKey)
		}
		if p.Endpoint != nil {
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint.String())
		}
		if p.PersistentKeepaliveInterval != nil {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n",
				int(p.PersistentKeepaliveInterval.Seconds()))
		}
		if p.ReplaceAllowedIPs {
			b.WriteString("replace_allowed_ips=true\n")
			// 排序只为让文本稳定：同样的配置每次生成同样的请求，便于日志比对与排查。
			ips := make([]string, 0, len(p.AllowedIPs))
			for _, ip := range p.AllowedIPs {
				ips = append(ips, ip.String())
			}
			sort.Strings(ips)
			for _, ip := range ips {
				fmt.Fprintf(&b, "allowed_ip=%s\n", ip)
			}
		}
	}

	// 空行结束本次配置。
	b.WriteString("\n")
	return b.String()
}

// writeUAPIKey 写一行 32 字节密钥（UAPI 用十六进制，不是 base64）。
func writeUAPIKey(b *strings.Builder, field string, k wgtypes.Key) {
	fmt.Fprintf(b, "%s=%s\n", field, hex.EncodeToString(k[:]))
}

// decodeUAPIGet 解析 UAPI get 回显，得到与内核模式同构的设备视图。
//
// 这样上层的差异比较、快照采集、握手展示都无需区分后端，
// 「内核看到什么」与「用户态看到什么」在数据结构上完全一致。
func decodeUAPIGet(name, raw string) (*wgtypes.Device, error) {
	dev := &wgtypes.Device{Name: name}

	var cur *wgtypes.Peer
	var handshakeSec, handshakeNsec int64

	flush := func() {
		if cur == nil {
			return
		}
		// 从没见过握手的节点，UAPI 会回 0；据此保持零值，
		// 界面就能如实显示「尚未握手」，而不是 1970 年。
		if handshakeSec > 0 {
			cur.LastHandshakeTime = time.Unix(handshakeSec, handshakeNsec)
		}
		dev.Peers = append(dev.Peers, *cur)
		cur = nil
		handshakeSec, handshakeNsec = 0, 0
	}

	for _, line := range strings.Split(raw, "\n") {
		if line == "" {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "private_key":
			key, err := parseUAPIKey(v)
			if err != nil {
				return nil, err
			}
			dev.PrivateKey = key
			// 用户态实现能读回私钥，于是可以像内核模式一样推导公钥，
			// 从而具备「本机密钥有没有变化」的比较能力。
			dev.PublicKey = key.PublicKey()
		case "listen_port":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("解析 listen_port 失败: %w", err)
			}
			dev.ListenPort = n
		case "fwmark":
			n, err := strconv.Atoi(v)
			if err != nil {
				return nil, fmt.Errorf("解析 fwmark 失败: %w", err)
			}
			dev.FirewallMark = n
		case "public_key":
			flush()
			key, err := parseUAPIKey(v)
			if err != nil {
				return nil, err
			}
			cur = &wgtypes.Peer{PublicKey: key}
		case "preshared_key":
			if cur == nil {
				continue
			}
			key, err := parseUAPIKey(v)
			if err != nil {
				return nil, err
			}
			cur.PresharedKey = key
		case "endpoint":
			if cur == nil {
				continue
			}
			addr, err := net.ResolveUDPAddr("udp", v)
			if err != nil {
				// 地址回读失败只影响「对端地址变了没有」的判断，不影响已建立的连接；
				// 留空即视为未知，与内核模式读不到地址时的处理一致。
				continue
			}
			cur.Endpoint = addr
		case "persistent_keepalive_interval":
			if cur == nil {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil {
				continue
			}
			cur.PersistentKeepaliveInterval = time.Duration(n) * time.Second
		case "allowed_ip":
			if cur == nil {
				continue
			}
			_, ipnet, err := net.ParseCIDR(v)
			if err != nil {
				continue
			}
			cur.AllowedIPs = append(cur.AllowedIPs, *ipnet)
		case "last_handshake_time_sec":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			handshakeSec = n
		case "last_handshake_time_nsec":
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			handshakeNsec = n
		case "tx_bytes":
			if cur == nil {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			cur.TransmitBytes = n
		case "rx_bytes":
			if cur == nil {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				continue
			}
			cur.ReceiveBytes = n
		}
	}
	flush()
	return dev, nil
}

// parseUAPIKey 解析 UAPI 的十六进制密钥。
func parseUAPIKey(v string) (wgtypes.Key, error) {
	var key wgtypes.Key
	raw, err := hex.DecodeString(strings.TrimSpace(v))
	if err != nil {
		return key, fmt.Errorf("密钥不是合法的十六进制: %w", err)
	}
	if len(raw) != len(key) {
		return key, fmt.Errorf("密钥长度应为 %d 字节，实际 %d 字节", len(key), len(raw))
	}
	copy(key[:], raw)
	return key, nil
}
