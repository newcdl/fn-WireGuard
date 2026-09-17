export interface WgInterface {
  id: number
  name: string
  uuid: string
  private_key?: string
  listen_port: number
  fwmark: number
  mtu: number
  addresses: string[]
  dns: string[]
  dns_mode: 'client' | 'host' | 'off'
  route_table: string
  pre_up: string
  post_up: string
  pre_down: string
  post_down: string
  enabled: boolean
  autostart: boolean
  /** 允许设备访问家里内网（NAT 转发） */
  allow_lan: boolean
  /** 设备间隔离：这条连接里的设备之间不能互相访问 */
  isolate_peers: boolean
  revision: number
  created_at: string
  updated_at: string
  public_key?: string
  up?: boolean
  peer_count?: number
  peer_online?: number
  rx_bytes?: number
  tx_bytes?: number
  rx_rate?: number
  tx_rate?: number
  backend?: string
}

export interface WgPeer {
  id: number
  interface_id: number
  interface_name?: string
  name: string
  public_key: string
  preshared_key?: string
  client_private_key?: string
  /** 设备上网方式：full 全局 / lan 仅访问本端 / custom 自定义 */
  route_mode: 'full' | 'lan' | 'custom'
  /** 仅 route_mode=custom 时生效 */
  client_allowed_ips: string[]
  endpoint_host: string
  endpoint_port: number
  allowed_ips: string[]
  persistent_keepalive: number
  group_tag: string
  remark: string
  quota_rx: number
  quota_tx: number
  expire_at?: string | null
  /**
   * 设备里那份配置已经与当前设置不一致，需要重新扫码导入。
   * 改通行范围、对外地址、DNS 都只影响「之后新生成」的配置。
   */
  config_stale?: boolean
  enabled: boolean
  created_at: string
  updated_at: string
  online?: boolean
  last_handshake?: string
  endpoint?: string
  rx_bytes?: number
  tx_bytes?: number
  rx_rate?: number
  tx_rate?: number
}

export interface PeerStatus {
  public_key: string
  endpoint: string
  allowed_ips: string[]
  keepalive: number
  last_handshake: string
  rx_bytes: number
  tx_bytes: number
  rx_rate: number
  tx_rate: number
}

export interface InterfaceStatus {
  name: string
  up: boolean
  public_key: string
  listen_port: number
  fwmark: number
  mtu: number
  addresses: string[]
  peers: PeerStatus[]
}

export interface Status {
  backend: string
  interfaces: InterfaceStatus[]
  updated_at: string
}

/** 登录方式：网关免密 / 端口账号密码 的组合。 */
export type LoginMode = 'both' | 'gateway_only' | 'password_only'

/** 当前页面所处入口的描述（登录前就要知道，用于决定登录页怎么展示）。 */
export interface GatewayEntry {
  /** 是否经由飞牛统一网关的 Unix Socket 到达。 */
  entry?: boolean
  /**
   * 本机是否真的在监听网关入口（app.sock）。
   *
   * 与 entry 合起来才能把「没有飞牛账号登录」拆成两种不同的原因：
   * entry=false + socket_ready=true 说明入口是好的、只是这次请求没走那条通道；
   * entry=false + socket_ready=false 说明入口压根没建起来，与用户怎么打开无关。
   */
  socket_ready?: boolean
  /** 是否拿到了可信的飞牛身份（可用于一键免密登录）。 */
  available?: boolean
  username?: string
  is_admin?: boolean
  /** 通道存在但身份未被信任时的原因，直接展示给用户/运维。 */
  blocked_reason?: string
}

export interface AuthState {
  initialized: boolean
  authenticated: boolean
  user: User | null
  login_mode: LoginMode
  gateway: GatewayEntry
}

/** 登录方式开关的当前状态。 */
export interface LoginModeState {
  mode: LoginMode
  /** 是否已成功用过飞牛账号免密登录（未验证前不允许关闭端口登录）。 */
  gateway_proven: boolean
  /** 当前请求是否来自网关入口。 */
  gateway_entry: boolean
  /**
   * 本机是否真的在监听网关入口（app.sock）。
   *
   * 为 false 时「去飞牛桌面打开一次」是做不到的动作，界面必须改说环境问题，
   * 否则用户会一直在两个入口之间来回试。
   */
  gateway_socket: boolean
  /** 网关入口不可用/未被信任的原因（正常时为空串）。 */
  gateway_diagnosis: string
}

export interface Health {
  agent_up: boolean
  agent_version: string
  backend: string
  kernel_module: boolean
  tun_device: boolean
  uptime_sec: number
  error?: string
}

export interface User {
  id: number
  username: string
  role: 'admin' | 'operator' | 'viewer'
  status: number
  last_login_at?: string | null
  created_at: string
  /** 是否已开启二次验证（密钥本身不会下发，只给这个派生标志） */
  totp_enabled?: boolean
}

/** 二次验证状态。 */
export interface TOTPStatus {
  enabled: boolean
  recovery_remaining: number
}

/** 绑定二次验证所需的密钥与扫码链接（此时尚未生效）。 */
export interface TOTPSetup {
  secret: string
  uri: string
}

/** 受信任设备：登录时勾选「信任本设备」后登记，30 天内可跳过动态口令。 */
export interface TrustedDevice {
  id: number
  user_id: number
  name: string
  src_ip: string
  created_at: string
  last_used_at: string
  expires_at: string
}

/** 登录第一步的返回：口令正确但还需二次验证时不带用户信息。 */
export interface LoginChallenge {
  totp_required?: boolean
  challenge?: string
  username?: string
}

export interface Overview {
  health: Health
  backend: string
  interface_count: number
  interface_up: number
  peer_count: number
  peer_online: number
  peer_enabled: number
  total_rx: number
  total_tx: number
  rx_rate: number
  tx_rate: number
  interfaces: WgInterface[]
  top_peers: WgPeer[]
  recent_handshakes: WgPeer[]
  server_endpoint: string
  generated_at: string
}

export interface AuditEntry {
  id: number
  ts: string
  user_id: number
  username: string
  src_ip: string
  action: string
  target_type: string
  target_id: string
  before?: string
  after?: string
  result: string
  message?: string
}

export interface LogEntry {
  id: number
  ts: string
  level: string
  scope: string
  message: string
  fields?: string
}

export interface BackupRecord {
  id: number
  filename: string
  size: number
  sha256: string
  kind: string
  note: string
  include_key: boolean
  created_at: string
}

/** 配置快照与当前配置之间的一处变化 */
export interface SnapshotDiffItem {
  key: string
  name: string
  /** 字段级差异说明；新增/删除时为空 */
  details?: string[]
}

/** 一类对象的三组变化：新增 / 删除 / 修改 */
export interface SnapshotDiffSection {
  added: SnapshotDiffItem[]
  removed: SnapshotDiffItem[]
  changed: SnapshotDiffItem[]
}

/** 一条设置项变化（只给键名、不给取值，避免把凭据摊给只读账号） */
export interface SnapshotSettingDiff {
  key: string
}

/** 「快照 → 当前配置」的差异，用于回滚前确认会撤销什么 */
export interface SnapshotDiff {
  snapshot_id: number
  filename: string
  note: string
  created_at: string
  /** 一句话结论，形如「回滚将撤销：连接 +1 -0 ~0」 */
  summary: string
  /** 与当前配置完全一致 */
  empty: boolean
  interfaces: SnapshotDiffSection
  peers: SnapshotDiffSection
  dns: SnapshotDiffSection
  settings: SnapshotSettingDiff[]
}

/** 手动留档结果：created=false 表示与最近一份快照一致，未重复留档 */
export interface SnapshotCreateResult {
  created: boolean
  message?: string
  item?: BackupRecord
}

/** 可配置的事件通知类型（由后端下发，避免前后端各维护一份清单） */
export interface NotifyKind {
  kind: string
  /** 所属分组：peer / iface / system */
  group: string
  label: string
  detail: string
  level: 'info' | 'warn'
}

/** 事件分组（设备 / 连接 / 系统），供界面分节展示 */
export interface NotifyGroup {
  key: string
  label: string
}

/** 一次通知投递的结果 */
export interface NotifyResult {
  ok: boolean
  status_code?: number
  message: string
  at: string
  /** 实际发出的内容（截断后），排障用：接收端不显示消息时唯一可靠的线索 */
  payload?: string
}

/** 通知配置与最近一次投递结果 */
export interface NotifyStatus {
  configured: boolean
  /** 脱敏后的地址：路径与查询串已被抹掉，避免令牌泄漏 */
  url: string
  /** 地址本身的问题（为空表示可用） */
  problem?: string
  format: 'json' | 'text' | 'markdown'
  /** 已开启的事件类型 */
  events: string[]
  all_kinds: NotifyKind[]
  groups: NotifyGroup[]
  last?: NotifyResult
  sent: number
  failed: number
  deduped: number
  dropped: number
}

export interface DefaultRoute {
  family: number
  gw?: string
  dev?: string
  metric: number
  table: number
  owned_by_us: boolean
}

/** 内核里存在、但不属于本应用的 WireGuard 网卡（疑似历史残留或其它工具创建） */
export interface ForeignInterface {
  name: string
  listen_port: number
  up: boolean
  peer_count: number
  addresses: string[]
}

/** 内网访问链路上某一层的检查结果 */
export interface NATCheck {
  key: string
  label: string
  ok: boolean
  detail: string
  fix?: string
}

/** 内网访问（设备访问家里其它机器）的规则状态 */
export interface NATStatus {
  active: boolean
  sources: string[]
  wans: string[]
  /** 内核是否允许转发（net.ipv4.ip_forward） */
  ip_forward: boolean
  /** 该开关是否由本应用开启 */
  ip_forward_enabled_by_us: boolean
  note?: string
  /** 设备间隔离规则是否已生效 */
  isolate_active: boolean
  /** 当前被隔离的隧道网段 */
  isolate_nets: string[]
  /** 内核里实际的阻断规则条数 */
  isolate_rules: number
  /** 逐项自检结果：直接指出卡在哪一层 */
  checks: NATCheck[]
}

/** 「设备通行范围 / 内网访问 / 设备隔离」之间互相矛盾的一条结论 */
export interface AccessIssue {
  key: string
  title: string
  detail: string
  fix?: string
  /** 涉及哪条连接，便于直接定位 */
  interface_id?: number
  /** 需要用户去处理的页面路由名 */
  to?: string
}

export interface NetworkCheckResult {
  healthy: boolean
  route_info_readable: boolean
  managed_interfaces: string[]
  system_defaults: DefaultRoute[]
  stray_defaults: DefaultRoute[]
  foreign_interfaces: ForeignInterface[]
  nat: NATStatus
  forward_policy_drop: boolean
  /** 探测到的 NAS 所在局域网网段（供「自定义可访问范围」点选，避免手写填错） */
  home_subnets: string[]
  /** 访问控制相关的配置矛盾（已按连接聚合，数量与连接数同阶） */
  access_issues: AccessIssue[]
  /** 内网域名解析的运行状态 */
  dns: DNSStatus
  messages: string[]
}

/** 内网域名解析的运行状态 */
export interface DNSStatus {
  enabled: boolean
  /** 实际在监听的地址（形如 10.10.0.1:53） */
  listen: string[]
  records: number
  queries: number
  failed: number
  /** 监听失败等异常原因（为空表示正常） */
  note?: string
}

/** 一条内网域名记录（主机名 → 家里设备地址） */
export interface DNSRecord {
  id: number
  name: string
  ip: string
  note: string
  created_at: string
  updated_at: string
}

export interface PeerConfigResult {
  conf: string
  filename: string
  endpoint: string
  server_public_key: string
  client_address: string[]
  allowed_ips: string[]
  qr_payload: string
  warning?: string
}

/** 批量导入设备：一行一台设备 */
export interface PeerImportRow {
  name: string
  public_key: string
  remark: string
  group_tag: string
}

/** 单台设备的导入结果 */
export interface PeerImportItem {
  index: number
  name: string
  ok: boolean
  error?: string
  peer_id?: number
}

/** 批量导入汇总 */
export interface PeerImportResult {
  created: number
  failed: number
  items: PeerImportItem[]
}
