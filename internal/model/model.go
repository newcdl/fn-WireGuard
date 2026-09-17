// Package model 定义贯穿数据层、收敛引擎与 API 的领域模型。
package model

import "time"

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
	// RouteModeFull 设备全部流量走本连接（全局代理）。
	RouteModeFull = "full"
	// RouteModeLAN 仅访问本端网段，其余流量走设备本地网络。
	RouteModeLAN = "lan"
	// RouteModeCustom 由 ClientAllowedIPs 指定。
	RouteModeCustom = "custom"

	// RouteTableOff 本应用不管理本机路由（默认，安全底线）。
	RouteTableOff = "off"
	// RouteTableClient 仅当本机作为客户端时才为对端网段添加路由。
	RouteTableClient = "client"
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
	AllowedIPs   []string   `json:"allowed_ips"`
	EndpointHost string     `json:"endpoint_host"`
	EndpointPort int        `json:"endpoint_port"`
	Keepalive    int        `json:"persistent_keepalive"`
	GroupTag     string     `json:"group_tag"`
	Remark       string     `json:"remark"`
	QuotaRx      int64      `json:"quota_rx"`
	QuotaTx      int64      `json:"quota_tx"`
	ExpireAt     *time.Time `json:"expire_at,omitempty"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
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

	// 以下三个同样是派生字段（不是数据库列），由 service 层在返回给界面时填充。
	//
	// Source 是账号来源：SourceGateway（由飞牛账号映射而来）或 SourceLocal（应用内自建）。
	// 界面靠它决定「改密码」这类操作该不该显示 —— 飞牛账号的密码由飞牛管，
	// 给它一个改密码按钮比不给更糟：用户会以为改了能生效，实际上改完也登不进来。
	//
	// DisplayName 是给界面看的名字。飞牛账号的 Username 是 nas:<uid> 这种映射锚点，
	// 是用户从未设置过、也无法识别的名字，直接显示出来等于让他对着编号发呆；
	// 飞牛那边叫什么，这里就显示什么。本地账号的 DisplayName 就是 Username 本身，
	// 前端因此可以一律用 display_name ?? username 渲染，不必分情况。
	//
	// TrimUID 只在飞牛账号上有值，供界面标注「飞牛账号 1000」这类可核对的信息。
	Source      string `json:"source,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	TrimUID     string `json:"trim_uid,omitempty"`
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
}
