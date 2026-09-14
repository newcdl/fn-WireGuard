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
  /** 逐项自检结果：直接指出卡在哪一层 */
  checks: NATCheck[]
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
  messages: string[]
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
