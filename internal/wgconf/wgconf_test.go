package wgconf

import (
	"strings"
	"testing"

	"fnwg/internal/model"
)

// TestClientFingerprint 指纹是「设备里那份配置是否过期」的唯一依据，
// 因此它必须同时满足三件事：与列表顺序无关、对每个影响设备侧内容的字段敏感、
// 完全不含密钥。任何一条不成立，用户看到的就是错误的过期提示。
func TestClientFingerprint(t *testing.T) {
	base := ClientConfigInputs{
		Endpoint:    "home.example.com:51820",
		ClientAddrs: []string{"10.10.0.2/32"},
		AllowedIPs:  []string{"192.168.3.0/24", "10.10.0.0/24"},
		DNS:         []string{"223.5.5.5", "119.29.29.29"},
		MTU:         1420,
		Keepalive:   25,
		ServerPub:   "SERVERPUBKEY",
	}
	want := ClientFingerprint(base)

	// ① 顺序无关：界面上调整范围顺序不该被当成「配置变了」
	reordered := base
	reordered.AllowedIPs = []string{"10.10.0.0/24", "192.168.3.0/24"}
	reordered.DNS = []string{"119.29.29.29", "223.5.5.5"}
	if got := ClientFingerprint(reordered); got != want {
		t.Fatalf("顺序不同不应改变指纹：%s vs %s", got, want)
	}

	// ② 心跳为 0 时按默认值归一，与渲染出来的配置保持一致
	zeroKeepalive := base
	zeroKeepalive.Keepalive = 0
	defKeepalive := base
	defKeepalive.Keepalive = DefaultKeepalive
	if ClientFingerprint(zeroKeepalive) != ClientFingerprint(defKeepalive) {
		t.Fatal("心跳为 0 应按默认值归一，否则会出现「没改配置却提示过期」")
	}

	// ③ 每个影响设备侧内容的字段都要敏感
	cases := map[string]func(ClientConfigInputs) ClientConfigInputs{
		"对外地址":  func(in ClientConfigInputs) ClientConfigInputs { in.Endpoint = "other.example.com:51820"; return in },
		"隧道地址":  func(in ClientConfigInputs) ClientConfigInputs { in.ClientAddrs = []string{"10.10.0.3/32"}; return in },
		"通行范围":  func(in ClientConfigInputs) ClientConfigInputs { in.AllowedIPs = []string{"0.0.0.0/0"}; return in },
		"DNS":   func(in ClientConfigInputs) ClientConfigInputs { in.DNS = []string{"1.1.1.1"}; return in },
		"MTU":   func(in ClientConfigInputs) ClientConfigInputs { in.MTU = 1380; return in },
		"心跳":    func(in ClientConfigInputs) ClientConfigInputs { in.Keepalive = 15; return in },
		"服务端公钥": func(in ClientConfigInputs) ClientConfigInputs { in.ServerPub = "OTHERPUBKEY"; return in },
	}
	for name, mutate := range cases {
		if ClientFingerprint(mutate(base)) == want {
			t.Fatalf("%s 变化后指纹必须变化，否则设备上的旧配置不会被标记为过期", name)
		}
	}

	// ④ 指纹是定长的短串：它要落库、要下发给前端，不能携带任何可用于还原密钥的信息
	if len(want) != 16 {
		t.Fatalf("指纹应为 16 位十六进制短串，实际 %d 位: %s", len(want), want)
	}
}

const sample = `# 服务端配置
[Interface]
PrivateKey = aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qga2V5ISE=
Address = 10.10.0.1/24, fd00::1/64
ListenPort = 51820
MTU = 1420
DNS = 223.5.5.5, 119.29.29.29
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT

[Peer]
# 我的笔记本
PublicKey = d29ybGQgaGVsbG8gdGhpcyBpcyBhIHRlc3Qga2V5ISE=
PresharedKey = cHNrIHRlc3QgdmFsdWUgMzIgYnl0ZXMgbG9uZyEhIQ==
AllowedIPs = 10.10.0.2/32, 10.20.0.0/24
PersistentKeepalive = 25
`

func TestParseAndRenderRoundTrip(t *testing.T) {
	f, err := Parse(sample)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if f.Interface.ListenPort != 51820 {
		t.Fatalf("ListenPort 解析错误: %d", f.Interface.ListenPort)
	}
	if len(f.Interface.Addresses) != 2 {
		t.Fatalf("地址解析数量错误: %v", f.Interface.Addresses)
	}
	if len(f.Interface.DNS) != 2 {
		t.Fatalf("DNS 解析数量错误: %v", f.Interface.DNS)
	}
	if len(f.Peers) != 1 {
		t.Fatalf("节点解析数量错误: %d", len(f.Peers))
	}
	p := f.Peers[0]
	if p.Name != "我的笔记本" {
		t.Fatalf("节点备注名解析错误: %q", p.Name)
	}
	if len(p.AllowedIPs) != 2 || p.Keepalive != 25 {
		t.Fatalf("节点字段解析错误: %+v", p)
	}

	it := &model.Interface{
		Name:       "wg0",
		PrivateKey: f.Interface.PrivateKey,
		ListenPort: f.Interface.ListenPort,
		MTU:        f.Interface.MTU,
		Addresses:  f.Interface.Addresses,
		RouteTable: "auto",
		PostUp:     strings.Join(f.Interface.PostUp, "\n"),
	}
	peers := []model.Peer{{
		Name:         p.Name,
		PublicKey:    p.PublicKey,
		PresharedKey: p.PresharedKey,
		AllowedIPs:   p.AllowedIPs,
		Keepalive:    p.Keepalive,
	}}
	rendered := RenderServer(it, peers)
	if !strings.Contains(rendered, "[Interface]") || !strings.Contains(rendered, "ListenPort = 51820") {
		t.Fatalf("渲染结果缺少接口段内容:\n%s", rendered)
	}
	if !strings.Contains(rendered, "AllowedIPs = 10.10.0.2/32, 10.20.0.0/24") {
		t.Fatalf("渲染结果缺少节点 AllowedIPs:\n%s", rendered)
	}
	// 渲染结果应能被自身再次解析（保证导出与导入闭环一致）
	if _, err := Parse(rendered); err != nil {
		t.Fatalf("渲染结果无法被重新解析: %v\n%s", err, rendered)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse("[Interface]\nAddress = 10.0.0.1/24\n"); err == nil {
		t.Fatal("缺少私钥时应报错")
	}
	if _, err := Parse("[Peer]\nAllowedIPs = 10.0.0.2/32\n"); err == nil {
		t.Fatal("缺少 Interface 段时应报错")
	}
	if _, err := Parse("[Interface]\nPrivateKey = x\n[Peer]\n# 无名节点\nAllowedIPs = 10.0.0.2/32\n"); err == nil {
		t.Fatal("节点缺少公钥时应报错")
	}
}

func TestSplitClientAndServerIPs(t *testing.T) {
	it := &model.Interface{Addresses: []string{"10.10.0.1/24"}}
	p := &model.Peer{AllowedIPs: []string{"10.10.0.2/32", "192.168.1.0/24"}}
	addrs, routes := SplitClientAndServerIPs(it, p)
	if len(addrs) != 1 || addrs[0] != "10.10.0.2/32" {
		t.Fatalf("客户端地址拆分错误: %v", addrs)
	}
	if len(routes) != 1 || routes[0] != "192.168.1.0/24" {
		t.Fatalf("路由拆分错误: %v", routes)
	}
}

func TestRenderClient(t *testing.T) {
	it := &model.Interface{DNS: []string{"223.5.5.5"}, MTU: 1420}
	p := &model.Peer{Name: "手机", PresharedKey: "psk", Keepalive: 25}
	out := RenderClient("serverpub", it, p, RenderClientOptions{
		Endpoint:         "vpn.example.com:51820",
		ClientPrivateKey: "clientpriv",
		ClientAddress:    []string{"10.10.0.2/32"},
		AllowedIPs:       []string{"0.0.0.0/0", "::/0"},
	})
	for _, want := range []string{
		"PrivateKey = clientpriv",
		"Address = 10.10.0.2/32",
		"DNS = 223.5.5.5",
		"PublicKey = serverpub",
		"Endpoint = vpn.example.com:51820",
		"AllowedIPs = 0.0.0.0/0, ::/0",
		"PersistentKeepalive = 25",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("客户端配置缺少 %q:\n%s", want, out)
		}
	}
}

func TestMergeCIDRs(t *testing.T) {
	got := MergeCIDRs([]string{"10.0.0.0/24", "10.0.0.0/24", " 192.168.0.0/16 ", "", "10.0.0.0/8"})
	if len(got) != 3 {
		t.Fatalf("去重结果数量错误: %v", got)
	}
	if got[0] != "10.0.0.0/8" {
		t.Fatalf("排序结果错误: %v", got)
	}
}
