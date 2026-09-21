// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

// Package model 定义贯穿数据层、收敛引擎与 API 的领域模型。
package model

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// 角色常量。
const (
	RoleAdmin    = "admin"    // 全部权限
	RoleOperator = "operator" // 运维：接口/节点/路由/防火墙读写，不可管理用户与查看私钥
	RoleViewer   = "viewer"   // 只读审计
)

// 设备上网方式。
//
// 关键概念纠正：AllowedIPs 在不同方向含义完全不同。
//   - 服务端 Peer 的 AllowedIPs = 允许从该设备进来的源地址（准入），主机侧不需要任何路由；
//   - 客户端配置的 AllowedIPs = 该设备哪些流量走隧道（上网方式）。
//
// 早期版本把两者混为一个字段，导致服务端填 0.0.0.0/0 时往 NAS 上写了默认路由，
// 抢占系统默认路由并影响 fnOS 自身网络（含 FN Connect）。现在两者彻底分离。
const (
	// 设备的内网访问范围（见 Peer.LANPolicy）。
	//
	// 为什么需要它：连接级的「允许设备访问家里内网」是一刀切的，而设备侧那份配置
	// （ClientAllowedIPs）只是**建议** —— 设备完全可以自己改路由绕过去。
	// 真正说了算的是服务端规则，这三个取值就是那条规则的开关。
	//
	// 默认值必须与升级前的行为完全一致（inherit），否则升级会顺手收紧或放开用户的网络。
	LANPolicyInherit  = "inherit"
	LANPolicyRestrict = "restrict"
	LANPolicyDeny     = "deny"

	RouteModeFull = "full"
	// RouteModeLAN 仅访问本端网段，其余流量走设备本地网络。
	RouteModeLAN = "lan"
	// RouteModeCustom 由 ClientAllowedIPs 指定。
	RouteModeCustom = "custom"

	// RouteTableOff 本应用不管理本机路由（默认，安全底线）。
	RouteTableOff = "off"
	// RouteTableClient 仅当本机作为客户端时才为对端网段添加路由。
	RouteTableClient = "client"

	// PeerDisabledQuota / PeerDisabledExpired 是设备被**自动**停用的原因（Peer.DisabledReason 的取值）。
	//
	// 只记「为什么停用」，不记具体数值或期限：那些会随管理员调整而变，
	// 而能不能自动恢复取决于原因 —— 条件解除时（到了新的一月、额度提高、期限延长）
	// 只有这两个原因会被自动放开，管理员手工停用的（原因为空）绝不自动恢复。
	PeerDisabledQuota   = "quota"
	PeerDisabledExpired = "expire"
)

// 权限点，用于 RBAC 粗粒度校验。
const (
	PermIfaceWrite    = "iface.write"
	PermPeerWrite     = "peer.write"
	PermKeyReveal     = "key.reveal"
	PermFirewallWrite = "firewall.write"
	PermBackupRestore = "backup.restore"
	PermUserManage    = "user.manage"
)

// PermissionsOf 返回角色对应的权限点集合。
func PermissionsOf(role string) map[string]bool {
	switch role {
	case RoleAdmin:
		return map[string]bool{
			PermIfaceWrite: true, PermPeerWrite: true, PermKeyReveal: true,
			PermFirewallWrite: true, PermBackupRestore: true, PermUserManage: true,
		}
	case RoleOperator:
		return map[string]bool{
			PermIfaceWrite: true, PermPeerWrite: true,
			PermFirewallWrite: true, PermBackupRestore: true,
		}
	default: // viewer
		return map[string]bool{}
	}
}

// SettingDNSResolve 是「内网域名解析」总开关的设置名。
//
// 放在 model 里而不是各写一遍字面量：Web 进程读它决定下发给设备的 DNS，
// 代理进程读它决定要不要起解析服务，两边写错一个字就是「开关打开但不生效」。
const SettingDNSResolve = "dns_resolve_enabled"

// OnlineWindow 是判定设备在线的时间窗：最近一次握手落在窗口内视为在线。
//
// 单点定义。此前这个阈值在收敛引擎与状态缓存里各写了一遍，
// 现在还要供「上下线通知」使用——三处各写一遍迟早会出现
// 「界面显示在线、通知却说设备已离线」这种自相矛盾的提示。
const OnlineWindow = 3 * time.Minute

// Interface 表示一个 WireGuard 接口（内核 link）。
type Interface struct {
	ID         int64    `json:"id"`
	Name       string   `json:"name"`        // wg0
	UUID       string   `json:"uuid"`        // 稳定标识，导出/导入时使用
	PrivateKey string   `json:"private_key"` // 明文字段仅在明确授权时下发
	ListenPort int      `json:"listen_port"`
	FWMark     int      `json:"fwmark"`
	MTU        int      `json:"mtu"`
	Addresses  []string `json:"addresses"`   // ["10.10.0.1/24","fd00::1/64"]
	DNS        []string `json:"dns"`         // 下发给客户端的 DNS
	DNSMode    string   `json:"dns_mode"`    // client | host | off
	RouteTable string   `json:"route_table"` // auto | off | <n>
	PreUp      string   `json:"pre_up"`
	PostUp     string   `json:"post_up"`
	PreDown    string   `json:"pre_down"`
	PostDown   string   `json:"post_down"`
	Enabled    bool     `json:"enabled"`
	Autostart  bool     `json:"autostart"`
	// AllowLAN 为真时启用「允许设备访问家里内网」：
	// 为这条连接的隧道网段做源地址改写，让连进来的设备能访问局域网中的其它设备。
	AllowLAN bool `json:"allow_lan"`
	// IsolatePeers 为真时启用「设备间隔离」：
	// 这条连接里的设备之间不能互相访问，但都能访问 NAS 与内网。
	//
	// 与 AllowLAN 相互独立：隔离只依赖隧道网段，不依赖出口网卡，
	// 因此内网访问因为探测不到出口网卡而无法启用时，隔离仍然照常生效。
	IsolatePeers bool      `json:"isolate_peers"`
	Revision     int64     `json:"revision"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`

	// 以下为运行时字段，不落库
	PublicKey  string  `json:"public_key,omitempty"`
	Up         bool    `json:"up,omitempty"`
	PeerCount  int     `json:"peer_count,omitempty"`
	PeerOnline int     `json:"peer_online,omitempty"`
	RxBytes    int64   `json:"rx_bytes,omitempty"`
	TxBytes    int64   `json:"tx_bytes,omitempty"`
	RxRate     float64 `json:"rx_rate,omitempty"`
	TxRate     float64 `json:"tx_rate,omitempty"`
	Backend    string  `json:"backend,omitempty"`
}

// Peer 表示一个对等节点。
type Peer struct {
	ID            int64  `json:"id"`
	InterfaceID   int64  `json:"interface_id"`
	InterfaceName string `json:"interface_name,omitempty"`
	Name          string `json:"name"`
	PublicKey     string `json:"public_key"`
	PresharedKey  string `json:"preshared_key,omitempty"`
	// ClientPrivateKey 是本工具代客户端保管的私钥（加密落库），
	// 仅用于重复下发客户端配置/二维码，可随时清除。
	ClientPrivateKey string `json:"client_private_key,omitempty"`
	// RouteMode 决定该设备（客户端）哪些流量走本连接，取值见 RouteMode* 常量。
	RouteMode string `json:"route_mode"`
	// ClientAllowedIPs 仅在 RouteMode=custom 时生效，表示客户端侧的通行范围。
	ClientAllowedIPs []string `json:"client_allowed_ips"`
	// AllowedIPs 是服务端准入地址：允许该设备使用哪些源地址，主机侧不据此添加任何路由。
	AllowedIPs []string `json:"allowed_ips"`
	// LANPolicy 是该设备的「内网访问范围」，取值见 LANPolicy* 常量。
	//
	// 与 ClientAllowedIPs 的区别（最容易混的一处）：
	//   - ClientAllowedIPs 写在**设备那份配置**里，决定设备哪些流量进隧道 —— 设备侧可以改；
	//   - LANPolicy 落在**服务端的转发规则**上，决定这台设备实际能访问内网的哪些目标 —— 设备改不了。
	// 前者管「进不进隧道」，后者管「进了隧道之后能去哪」。
	LANPolicy string `json:"lan_policy"`
	// LANTargets 仅在 LANPolicy=restrict 时有意义：允许该设备访问的内网目标，
	// 写法见 ParseLANTarget：192.168.1.10、192.168.1.0/24、192.168.1.10:445。
	LANTargets   []string   `json:"lan_targets"`
	EndpointHost string     `json:"endpoint_host"`
	EndpointPort int        `json:"endpoint_port"`
	Keepalive    int        `json:"persistent_keepalive"`
	GroupTag     string     `json:"group_tag"`
	Remark       string     `json:"remark"`
	QuotaRx      int64      `json:"quota_rx"`
	QuotaTx      int64      `json:"quota_tx"`
	ExpireAt     *time.Time `json:"expire_at,omitempty"`
	Enabled      bool       `json:"enabled"`
	// DisabledReason 是「被自动停用的原因」：quota（流量用尽）或 expire（已到期），
	// 空表示不是自动停用（在用的、或管理员手工停用的）。
	//
	// 必须落库：月度额度要到月初自动恢复，而恢复的前提正是知道当初为什么停用 ——
	// 光看 enabled=false 分不清「管理员手工停的」与「流量用尽自动停的」，
	// 分不清就会把前者也一并放开。
	DisabledReason string    `json:"disabled_reason,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	// ConfigFingerprint 是这台设备**上次拿到配置时**的客户端配置指纹
	// （由 wgconf.ClientFingerprint 计算，不含任何密钥）。空表示从未生成过配置。
	//
	// 为什么需要它：改通行范围、对外地址、DNS 都只影响「之后新生成」的配置，
	// 设备里已经导入的那份不会自动变。没有这个指纹，用户会以为改完就生效了，
	// 然后对着「明明改了范围却还是访问不了」困惑很久。
	ConfigFingerprint string `json:"config_fingerprint,omitempty"`

	// 运行时字段
	Online        bool      `json:"online,omitempty"`
	LastHandshake time.Time `json:"last_handshake,omitempty"`
	Endpoint      string    `json:"endpoint,omitempty"`
	RxBytes       int64     `json:"rx_bytes,omitempty"`
	TxBytes       int64     `json:"tx_bytes,omitempty"`
	RxRate        float64   `json:"rx_rate,omitempty"`
	TxRate        float64   `json:"tx_rate,omitempty"`
	// ConfigStale 表示设备里那份配置与当前设置已经不一致，需要重新扫码导入。
	// 仅在读取设备列表/详情时计算，不落库。
	ConfigStale bool `json:"config_stale,omitempty"`
}

// Endpoint 返回 "host:port" 形式的端点地址。
func (p *Peer) EndpointString() string {
	if p.EndpointHost == "" || p.EndpointPort == 0 {
		return ""
	}
	return p.EndpointHost + ":" + itoa(p.EndpointPort)
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		n--
		b[n] = '-'
	}
	return string(b[n:])
}

// PeerStatus 是内核返回的单个 Peer 实时状态。
type PeerStatus struct {
	PublicKey     string    `json:"public_key"`
	Endpoint      string    `json:"endpoint"`
	AllowedIPs    []string  `json:"allowed_ips"`
	Keepalive     int       `json:"keepalive"`
	LastHandshake time.Time `json:"last_handshake"`
	RxBytes       int64     `json:"rx_bytes"`
	TxBytes       int64     `json:"tx_bytes"`
	RxRate        float64   `json:"rx_rate"`
	TxRate        float64   `json:"tx_rate"`
	PresharedKey  bool      `json:"preshared_key"`
}

// InterfaceStatus 是内核返回的单个接口实时状态。
type InterfaceStatus struct {
	Name       string       `json:"name"`
	Up         bool         `json:"up"`
	PublicKey  string       `json:"public_key"`
	ListenPort int          `json:"listen_port"`
	FWMark     int          `json:"fwmark"`
	MTU        int          `json:"mtu"`
	Addresses  []string     `json:"addresses"`
	Peers      []PeerStatus `json:"peers"`
}

// Status 是一次完整的状态快照。
type Status struct {
	Backend    string            `json:"backend"`
	Interfaces []InterfaceStatus `json:"interfaces"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// Health 描述 agent 与内核能力健康度。
type Health struct {
	AgentUp      bool   `json:"agent_up"`
	AgentVersion string `json:"agent_version"`
	Backend      string `json:"backend"` // kernel | userspace | mock
	KernelModule bool   `json:"kernel_module"`
	TunDevice    bool   `json:"tun_device"`
	UptimeSec    int64  `json:"uptime_sec"`
	Error        string `json:"error,omitempty"`
}

// NetworkReport 是网络自检结果（只读，不做任何修改）。
type NetworkReport struct {
	// RouteInfoReadable 表示当前后端能读取真实的系统路由表。
	// 演示模式（非 Linux 开发环境）为 false，此时不应把"没有默认路由"当作异常。
	RouteInfoReadable bool `json:"route_info_readable"`
	// ManagedInterfaces 本应用创建过的接口。
	ManagedInterfaces []string `json:"managed_interfaces"`
	// Defaults 系统自身管理的默认路由。
	Defaults []DefaultRoute `json:"defaults"`
	// StrayDefaults 指向本应用接口的异常默认路由（会被自动清除）。
	StrayDefaults []DefaultRoute `json:"stray_defaults"`
	// ForeignInterfaces 内核里存在、但不属于本应用的 WireGuard 接口。
	ForeignInterfaces []ForeignInterface `json:"foreign_interfaces"`
	// NAT 内网访问（设备访问家里其它机器）的规则状态。
	NAT NATStatus `json:"nat"`
	// ForwardPolicyDrop 系统转发链策略是否为丢弃（装过 Docker 的机器常见），
	// 为真时即使规则正确也可能被系统拦下。
	ForwardPolicyDrop bool `json:"forward_policy_drop"`
	// DNS 内网域名解析（设备用主机名访问家里设备）的运行状态。
	DNS DNSStatus `json:"dns"`
}

// DNSStatus 是内网域名解析的运行状态。
type DNSStatus struct {
	// Enabled 用户是否打开了「内网域名解析」开关。
	Enabled bool `json:"enabled"`
	// Listen 实际在监听的地址（形如 10.10.0.1:53）。
	Listen []string `json:"listen"`
	// Records 已加载的域名记录条数。
	Records int `json:"records"`
	// Queries / Failed 累计查询次数与失败次数，用于判断解析是否真的在工作。
	Queries int64 `json:"queries"`
	Failed  int64 `json:"failed"`
	// Note 监听失败等异常的原因（为空表示正常）。
	Note string `json:"note,omitempty"`
}

// ForeignInterface 描述一个不是本应用创建的 WireGuard 接口。
//
// 典型来源：
//   - 早期版本卸载时没清理干净的残留（netstate.json 丢失后本应用不再认领它）；
//   - 用户手工用 wg-quick 或其他工具创建的接口。
//
// 这些接口会占住 UDP 端口，并让本应用无法使用同名接口（安全起见不接管他人对象）。
// 本应用只做**只读上报**，删除必须由用户在界面上明确确认。
type ForeignInterface struct {
	Name       string   `json:"name"`
	ListenPort int      `json:"listen_port"`
	Up         bool     `json:"up"`
	PeerCount  int      `json:"peer_count"`
	Addresses  []string `json:"addresses"`
}

// DefaultRoute 是一条默认路由的描述。
type DefaultRoute struct {
	Family    int    `json:"family"`
	Gw        string `json:"gw,omitempty"`
	Dev       string `json:"dev,omitempty"`
	Metric    int    `json:"metric"`
	Table     int    `json:"table"`
	OwnedByUs bool   `json:"owned_by_us"`
}

// StatSample 是写入历史统计表的一条采样。
type StatSample struct {
	InterfaceID   int64
	InterfaceName string
	PeerPublicKey string
	Ts            time.Time
	RxBytes       int64
	TxBytes       int64
}

// User 是应用内账号。
type User struct {
	ID           int64      `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	TOTPSecret   string     `json:"-"`
	Role         string     `json:"role"`
	Status       int        `json:"status"` // 1 启用 0 禁用
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	// TOTPEnabled 是派生给人看的字段：TOTPSecret 本身必须用 `json:"-"` 隐藏
	// （它落在 /users 响应里就等于把二次验证密钥泄给了任何能读账号列表的人），
	// 但「这个账号有没有开二次验证」需要让管理员看得到。
	// 由 store 在扫描时按 TOTPSecret 是否为空填充，不是数据库列。
	TOTPEnabled bool `json:"totp_enabled"`
}

// GatewayEntry 描述飞牛统一网关入口（从飞牛桌面点图标那条通道）此刻的状态。
//
// 单独成一个自检项的理由：这类故障最容易被误判 —— 端口能打开、进程在跑、
// 日志里也一切正常，唯独从飞牛桌面点图标是 502，差别只在这个 socket 文件上。
// 不主动报出来，用户就只能对着一个无法解释的 502 猜。
type GatewayEntry struct {
	// Configured 表示本机确实配置了网关入口（能定位到应用目录并落点）。
	// 为 false 时界面不作任何断言：这台机器可能根本不走这条通道。
	Configured bool `json:"configured"`
	// Path 是入口 socket 的路径。
	Path string `json:"path"`
	// Ready 表示 socket 文件在、且确实有人在监听（判定方式是真去连一次）。
	Ready bool `json:"ready"`
	// Detail 是面向用户的事实说明；正常时为空。
	Detail string `json:"detail,omitempty"`
	// Fix 是不可用时的处置办法；正常时为空。
	Fix string `json:"fix,omitempty"`
}

// TOTPChallenge 是一次二次验证登录挑战。
//
// 口令校验通过、动态口令尚未校验的这段时间里没有会话，只有这条挑战记录；
// 因此它必须短命（见 service 里的 TTL）且只能用一次。
type TOTPChallenge struct {
	TokenHash string
	UserID    int64
	ExpiresAt time.Time
	Attempts  int
	CreatedAt time.Time
}

// RecoveryCode 是一条恢复码记录（只含哈希，明文不落库）。
type RecoveryCode struct {
	ID        int64
	UserID    int64
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

// TrustedDevice 是一条「受信任设备」记录：用户在二次验证界面勾选「信任本设备」后
// 下发给该设备的凭据，之后从这台设备登录可跳过动态口令。
//
// 只保存令牌的 SHA-256，明文仅在签发时返回一次。Name / SrcIP 是给用户看的——
// 用户要靠它们判断列表里有没有自己不认识的设备，从而发现异常登录。
type TrustedDevice struct {
	ID     int64  `json:"id"`
	UserID int64  `json:"user_id"`
	Name   string `json:"name"`
	SrcIP  string `json:"src_ip"`
	// TokenHash 只用于落库与比对，绝不出现在接口响应里
	// （与 User.PasswordHash 同样的处理方式）。
	TokenHash  string    `json:"-"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// Session 是登录会话。
type Session struct {
	TokenHash string
	UserID    int64
	ExpiresAt time.Time
	CreatedAt time.Time
	UserAgent string
	SrcIP     string
}

// AuditEntry 是一条审计记录，采用哈希链防篡改。
type AuditEntry struct {
	ID         int64     `json:"id"`
	Ts         time.Time `json:"ts"`
	UserID     int64     `json:"user_id"`
	Username   string    `json:"username"`
	SrcIP      string    `json:"src_ip"`
	Action     string    `json:"action"`
	TargetType string    `json:"target_type"`
	TargetID   string    `json:"target_id"`
	Before     string    `json:"before,omitempty"`
	After      string    `json:"after,omitempty"`
	Result     string    `json:"result"`
	Message    string    `json:"message,omitempty"`
	PrevHash   string    `json:"prev_hash"`
	Hash       string    `json:"hash"`
}

// LogEntry 是一条应用日志。
type LogEntry struct {
	ID      int64     `json:"id"`
	Ts      time.Time `json:"ts"`
	Level   string    `json:"level"`
	Scope   string    `json:"scope"`
	Message string    `json:"message"`
	Fields  string    `json:"fields,omitempty"`
}

// AuditFilter 审计查询条件。
type AuditFilter struct {
	Username   string
	Action     string
	TargetType string
	From       *time.Time
	To         *time.Time
	Limit      int
	Offset     int
}

// InterfaceSpec 是下发给内核的接口期望态。
type InterfaceSpec struct {
	Name       string
	PrivateKey string
	ListenPort int
	FWMark     int
	MTU        int
	Addresses  []string
	// RouteTable 取 off（默认，不动系统路由）或 client（本机作为客户端时才下发路由）。
	RouteTable string
	// AllowLAN 为真时启用内网访问：为这条连接的隧道网段做源地址改写，
	// 让连进来的设备能够访问 NAS 所在局域网中的其它设备。
	AllowLAN bool
	// IsolatePeers 为真时禁止这条连接里的设备互相访问。
	IsolatePeers bool
	// DNS 是连接里配置的 DNS 服务器地址（下发给设备，同时作为内网域名解析的上游）。
	DNS []string
	Up  bool
	// Peers 是下发给内核的节点集合。
	Peers []PeerSpec
}

// NATStatus 描述内网访问（NAT 转发）的当前状态，用于界面诊断。
type NATStatus struct {
	// Active 规则是否已生效。
	Active bool `json:"active"`
	// Sources 当前放行的源网段（各连接的隧道网段）。
	Sources []string `json:"sources"`
	// WANs 转发出口网卡。
	WANs []string `json:"wans"`
	// IPForward 内核是否允许转发（net.ipv4.ip_forward）。
	// 为假时数据包在进入转发链之前就被丢掉，转发规则再正确也没用。
	IPForward bool `json:"ip_forward"`
	// IPForwardEnabledByUs 该开关是否由本应用开启。
	IPForwardEnabledByUs bool `json:"ip_forward_enabled_by_us"`
	// Note 异常说明（为空表示正常）。
	Note string `json:"note,omitempty"`
	// IsolateActive 设备间隔离规则是否已生效。
	IsolateActive bool `json:"isolate_active"`
	// IsolateNets 当前被隔离的隧道网段（为空表示没有连接开启隔离或规则未生效）。
	IsolateNets []string `json:"isolate_nets"`
	// IsolateRules 内核里实际的阻断规则条数，便于对照 `nft list table` 核对。
	IsolateRules int `json:"isolate_rules"`
	// Checks 是内网访问链路的逐项自检结果。
	// 「设备连上了但访问不了家里其它设备」在界面上只是一个现象，
	// 成因可能有好几层，这里把每层都查一遍并给出修复建议。
	Checks []NATCheck `json:"checks"`
}

// NATCheck 是内网访问链路上某一层的检查结果，用于把
// 「设备连上了但访问不了家里其它设备」精确定位到具体环节。
type NATCheck struct {
	// Key 是检查项的稳定标识。
	Key string `json:"key"`
	// Label 是面向用户的名称。
	Label string `json:"label"`
	// OK 表示该项通过。
	OK bool `json:"ok"`
	// Detail 是实测到的具体情况。
	Detail string `json:"detail"`
	// Fix 是未通过时的处置建议（可为空）。
	Fix string `json:"fix,omitempty"`
}

// PeerSpec 是下发给内核的节点期望态。
type PeerSpec struct {
	// Name 仅用于日志与提示（内核不认识节点名）。
	Name         string
	PublicKey    string
	PresharedKey string
	Endpoint     string
	AllowedIPs   []string
	Keepalive    int
	// LANPolicy / LANTargets 见 Peer.LANPolicy：服务端按设备限制内网访问目标。
	// 只有这两项进内核 —— 客户端那份配置（ClientAllowedIPs）不下发。
	LANPolicy  string
	LANTargets []string
}

// ParseLANTarget 解析一条内网目标：192.168.1.10、192.168.1.0/24、192.168.1.10:445。
//
// 返回归一化后的地址/网段与端口（无端口为 0）。放在 model 里而不是各层各写一份：
// 服务层要校验它、数据面要按它生成规则，两处各写一份解析器，迟早出现
// 「界面能填、规则不认」这种最难查的偏差。
//
// 刻意只接受 IPv4 单主机或网段：目标为空、写成默认路由都会被拒绝 ——
// 这个字段的语义是「允许去哪」，写成 0.0.0.0/0 等于不做限制，必须让用户明确表达。
func ParseLANTarget(raw string) (string, int, error) {
	v := strings.TrimSpace(raw)
	if v == "" {
		return "", 0, fmt.Errorf("目标不能为空")
	}
	addr, portStr := v, ""
	// 端口分隔：只在「最后一个冒号、右侧是纯数字」时当成端口。
	if i := strings.LastIndex(v, ":"); i >= 0 {
		if _, err := strconv.Atoi(strings.TrimSpace(v[i+1:])); err == nil {
			addr, portStr = v[:i], strings.TrimSpace(v[i+1:])
		}
	}
	port := 0
	if portStr != "" {
		n, err := strconv.Atoi(portStr)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("端口要写 1 到 65535 之间的数字")
		}
		port = n
	}
	out := ""
	if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil {
		out = ip.To4().String()
	} else if _, n, err := net.ParseCIDR(addr); err == nil && n.IP.To4() != nil {
		if ones, _ := n.Mask.Size(); ones == 0 {
			return "", 0, fmt.Errorf("不能写 0.0.0.0/0：那是「所有地址」，等于不做限制")
		}
		out = (&net.IPNet{IP: n.IP.Mask(n.Mask), Mask: n.Mask}).String()
	} else {
		return "", 0, fmt.Errorf("%q 不是合法的 IPv4 地址或网段，写成 192.168.1.10 或 192.168.1.0/24", v)
	}
	return out, port, nil
}

// LANTargetString 把一条目标还原成可读文本（用于回显与提示）。
func LANTargetString(addr string, port int) string {
	if port > 0 {
		return fmt.Sprintf("%s:%d", addr, port)
	}
	return addr
}

// LANDevice 是内网里的一台设备（从内核邻居表读到的**事实**，只读）。
//
// 为什么要读邻居表：NAS 天生知道「连上隧道的设备」，却不知道「家里还有哪些机器」——
// 而拓扑图上前者只是几个节点，后者才是用户真正想看的全貌。
// 邻居表是内核里现成的、只读的事实来源，不需要任何扫描或额外流量。
//
// 代价（必须让用户知道）：邻居表只记「最近通信过」的对端。NAS 是文件服务器，
// 平时打得交道不少，但它看不到从没跟它说过话的机器 —— 界面上的说明会写清这一点。
type LANDevice struct {
	IP        string `json:"ip"`
	MAC       string `json:"mac,omitempty"`
	Name      string `json:"name,omitempty"`
	Interface string `json:"interface,omitempty"`
	// State 是内核里的邻居状态（reachable / stale / delay / probe / failed / permanent）。
	State string `json:"state,omitempty"`
}

// LANReport 是「内网里有哪些设备」的读取结果。
type LANReport struct {
	// Demo 为真表示这是演示数据（内存后端），不是真实网络的观测结果。
	// 与「读不到」分开：演示模式照样有东西可画，但不能让人以为那是家里的机器。
	Demo bool `json:"demo,omitempty"`
	// Readable 为假表示这次没能读到（代理不可用、或运行在不支持的平台上）。
	// 界面据此区分「内网里没有别的设备」与「这次没读到」—— 两者绝不能混。
	Readable bool        `json:"readable"`
	Devices  []LANDevice `json:"devices,omitempty"`
	Reason   string      `json:"reason,omitempty"`
}

// BackupCopy 是外部备份目录里的一份副本。
//
// 放在 model 里而不是各自定义一份：它以同一形状穿过三个包 ——
// 特权代理（真正读写这个目录的进程）→ 协议 → 界面接口。
// 三处各写一个同形结构，迟早会有一处的字段名或 json tag 走偏，
// 而那种偏差的表现是「界面上少一列或时间显示不出来」，很难往回追。
type BackupCopy struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// BackupDirInfo 是外部备份目录的实况：能不能写、有什么要说清的、里面有哪些副本。
//
// OK/Note 由**真正执行写入的进程**给出（见 internal/service 里 InspectTargetDir 的说明），
// 界面只负责显示，不自己判断。
type BackupDirInfo struct {
	OK    bool         `json:"ok"`
	Note  string       `json:"note,omitempty"`
	Files []BackupCopy `json:"files,omitempty"`
}
