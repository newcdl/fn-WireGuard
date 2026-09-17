package wgback

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// mustPrivKey 生成一个随机私钥，生成失败时直接终止用例。
func mustPrivKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	return k
}

// mustKey 生成一个随机密钥（用于二次加密口令）。
func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GenerateKey()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	return k
}

func TestParseUAPIKeyRejectsBadInput(t *testing.T) {
	if _, err := parseUAPIKey("not-hex"); err == nil {
		t.Fatal("非十六进制输入应当报错")
	}
	short := strings.Repeat("ab", 16) // 16 字节，不足 32 字节
	if _, err := parseUAPIKey(short); err == nil {
		t.Fatal("长度不足的密钥应当报错")
	}
}

// 用户态模式最关键的一条：下发文本里绝不能出现 replace_peers。
// 一旦出现，wireguard-go 会删光全部节点重建，会话密钥与动态对端地址同样会丢，
// 这就是当年「隧道通但抖动」的成因。
func TestEncodeUAPISetNeverReplacesPeers(t *testing.T) {
	priv := mustPrivKey(t)
	psk := mustKey(t)
	peer := mustPrivKey(t).PublicKey()
	dead := mustPrivKey(t).PublicKey()

	mark := 0x1234
	port := 51820
	keepalive := 25 * time.Second
	_, ipA, _ := net.ParseCIDR("10.0.0.0/24")
	_, ipB, _ := net.ParseCIDR("192.168.5.0/24")

	out := encodeUAPISet(wgtypes.Config{
		PrivateKey:   &priv,
		FirewallMark: &mark,
		ListenPort:   &port,
		Peers: []wgtypes.PeerConfig{
			{PublicKey: dead, Remove: true},
			{
				PublicKey:                   peer,
				PresharedKey:                &psk,
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("203.0.113.7"), Port: 51820},
				PersistentKeepaliveInterval: &keepalive,
				ReplaceAllowedIPs:           true,
				// 故意乱序，验证输出会排序
				AllowedIPs: []net.IPNet{*ipB, *ipA},
			},
		},
	})

	if strings.Contains(out, "replace_peers") {
		t.Fatalf("下发文本不应包含 replace_peers:\n%s", out)
	}
	if !strings.HasSuffix(out, "\n\n") {
		t.Fatalf("UAPI set 必须以空行结束，实际为 %q", out)
	}
	if !strings.Contains(out, "private_key="+hex.EncodeToString(priv[:])+"\n") {
		t.Fatalf("私钥应以十六进制下发:\n%s", out)
	}
	// fwmark 必须在 listen_port 之前，避免套接字被无谓地重新绑定一次。
	if strings.Index(out, "fwmark=") > strings.Index(out, "listen_port=") {
		t.Fatalf("fwmark 应排在 listen_port 之前:\n%s", out)
	}
	if !strings.Contains(out, "public_key="+hex.EncodeToString(dead[:])+"\nremove=true\n") {
		t.Fatalf("移除节点应只下发 public_key + remove=true:\n%s", out)
	}
	if strings.Index(out, "allowed_ip=10.0.0.0/24") > strings.Index(out, "allowed_ip=192.168.5.0/24") {
		t.Fatalf("allowed_ip 应排序以保证文本稳定:\n%s", out)
	}
	if !strings.Contains(out, "persistent_keepalive_interval=25\n") {
		t.Fatalf("保活心跳应以秒下发:\n%s", out)
	}
}

// 没有变化的节点不应出现在下发文本里 —— 这是「不动它就不会抖」的前提。
func TestEncodeUAPISetOmitsUntouchedPeers(t *testing.T) {
	out := encodeUAPISet(wgtypes.Config{})
	if strings.TrimSpace(out) != "" {
		t.Fatalf("空配置不应产生任何下发内容，实际为 %q", out)
	}
}

func TestDecodeUAPIGet(t *testing.T) {
	priv := mustPrivKey(t)
	peer := mustPrivKey(t).PublicKey()
	psk := mustKey(t)

	raw := strings.Join([]string{
		"private_key=" + hex.EncodeToString(priv[:]),
		"listen_port=51820",
		"fwmark=4660",
		"public_key=" + hex.EncodeToString(peer[:]),
		"preshared_key=" + hex.EncodeToString(psk[:]),
		"endpoint=203.0.113.7:51820",
		"persistent_keepalive_interval=25",
		"allowed_ip=10.0.0.0/24",
		"allowed_ip=192.168.5.0/24",
		"last_handshake_time_sec=1700000000",
		"last_handshake_time_nsec=500",
		"tx_bytes=1024",
		"rx_bytes=2048",
		"protocol_version=1",
		"errno=0",
		"",
	}, "\n")

	dev, err := decodeUAPIGet("wg0", raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if dev.Name != "wg0" {
		t.Fatalf("设备名不符: %q", dev.Name)
	}
	if dev.PrivateKey != priv {
		t.Fatal("私钥解析不符")
	}
	// 用户态实现能读回私钥，因此可以像内核模式一样推导公钥做比较。
	if dev.PublicKey != priv.PublicKey() {
		t.Fatal("应由私钥推导出公钥")
	}
	if dev.ListenPort != 51820 || dev.FirewallMark != 4660 {
		t.Fatalf("端口/标记解析不符: port=%d mark=%d", dev.ListenPort, dev.FirewallMark)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("节点数应为 1，实际 %d", len(dev.Peers))
	}
	p := dev.Peers[0]
	if p.PublicKey != peer || p.PresharedKey != psk {
		t.Fatal("节点密钥解析不符")
	}
	if p.Endpoint == nil || p.Endpoint.Port != 51820 || !p.Endpoint.IP.Equal(net.ParseIP("203.0.113.7")) {
		t.Fatalf("对端地址解析不符: %v", p.Endpoint)
	}
	if p.PersistentKeepaliveInterval != 25*time.Second {
		t.Fatalf("保活心跳解析不符: %v", p.PersistentKeepaliveInterval)
	}
	if len(p.AllowedIPs) != 2 {
		t.Fatalf("通行范围应为 2 条，实际 %d", len(p.AllowedIPs))
	}
	if p.TransmitBytes != 1024 || p.ReceiveBytes != 2048 {
		t.Fatalf("流量统计解析不符: tx=%d rx=%d", p.TransmitBytes, p.ReceiveBytes)
	}
	want := time.Unix(1700000000, 500)
	if !p.LastHandshakeTime.Equal(want) {
		t.Fatalf("握手时间解析不符: %v", p.LastHandshakeTime)
	}
	// 未知字段（protocol_version / errno）应被安静忽略，不能当成错误。
}

// 从未握手的节点，UAPI 会回 0，绝不能显示成 1970 年。
func TestDecodeUAPIGetKeepsZeroHandshake(t *testing.T) {
	peer := mustPrivKey(t).PublicKey()
	raw := "public_key=" + hex.EncodeToString(peer[:]) + "\n" +
		"last_handshake_time_sec=0\n" +
		"last_handshake_time_nsec=0\n\n"

	dev, err := decodeUAPIGet("wg0", raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(dev.Peers) != 1 {
		t.Fatalf("节点数应为 1，实际 %d", len(dev.Peers))
	}
	if !dev.Peers[0].LastHandshakeTime.IsZero() {
		t.Fatalf("未握手节点应保持零值，实际 %v", dev.Peers[0].LastHandshakeTime)
	}
}

// 多节点解析：每个 public_key 都应开启新的一段，不能把字段串到上一个节点上。
func TestDecodeUAPIGetSplitsPeers(t *testing.T) {
	a := mustPrivKey(t).PublicKey()
	b := mustPrivKey(t).PublicKey()
	raw := "public_key=" + hex.EncodeToString(a[:]) + "\n" +
		"allowed_ip=10.0.0.0/24\n" +
		"tx_bytes=1\n" +
		"public_key=" + hex.EncodeToString(b[:]) + "\n" +
		"allowed_ip=10.0.1.0/24\n" +
		"tx_bytes=2\n\n"

	dev, err := decodeUAPIGet("wg0", raw)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(dev.Peers) != 2 {
		t.Fatalf("节点数应为 2，实际 %d", len(dev.Peers))
	}
	if dev.Peers[0].PublicKey != a || dev.Peers[1].PublicKey != b {
		t.Fatal("节点顺序或公钥不符")
	}
	if dev.Peers[0].TransmitBytes != 1 || dev.Peers[1].TransmitBytes != 2 {
		t.Fatalf("字段被串到了相邻节点: %d / %d", dev.Peers[0].TransmitBytes, dev.Peers[1].TransmitBytes)
	}
}
