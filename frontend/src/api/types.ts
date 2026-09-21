// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

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

export interface AuthState {
  initialized: boolean
  authenticated: boolean
  user: User | null
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
  /** 记录在、文件却已经不在了（被手动删除或移走）：界面据此禁掉下载与还原 */
  missing?: boolean
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

/**
 * 飞牛统一网关入口（从飞牛桌面点图标那条通道）的状态。
 *
 * 单独成一项的理由：这类故障最容易被误判 —— 端口能打开、进程在跑、日志也正常，
 * 唯独点桌面图标是 502，差别只在这个 socket 文件上。
 */
export interface GatewayEntry {
  /** 本机确实配置了入口（能定位到应用目录并落点） */
  configured: boolean
  /** 入口 socket 的路径 */
  path: string
  /** socket 文件在、且确实有人在监听（后端真去连了一次） */
  ready: boolean
  /** 不可用时的事实说明 */
  detail?: string
  /** 不可用时的处置办法 */
  fix?: string
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
  /** 飞牛桌面入口（从桌面点图标那条通道）的状态 */
  gateway: GatewayEntry
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

/** 某一天（服务器本地时区的自然日）的流量合计 */
export interface TrafficDay {
  day: string
  rx_bytes: number
  tx_bytes: number
}

/** 流量报表里的一台设备 */
export interface TrafficPeerRow {
  peer_id: number
  name: string
  interface_id: number
  interface_name: string
  enabled: boolean
  /** 被自动停用的原因：quota（用量超限）/ expire（已到期），空表示不是自动停用 */
  disabled_reason?: string
  expire_at?: string | null
  /** 每月的发送额度（0 表示不限） */
  quota_tx: number
  month_rx_bytes: number
  month_tx_bytes: number
  rx_bytes: number
  tx_bytes: number
  daily: TrafficDay[]
}

/** 流量报表：区间汇总 + 逐日明细 + 保留策略 */
export interface TrafficReport {
  days: number
  from: string
  to: string
  peers: TrafficPeerRow[]
  daily: TrafficDay[]
  rx_bytes: number
  tx_bytes: number
  retention_days: number
  hour_rows: number
  oldest?: string | null
}

/** 计划备份的配置 */
export interface BackupPlan {
  enabled: boolean
  /** daily（每天）| weekly（每周） */
  freq: string
  /** 执行时刻 HH:MM（NAS 本地时间） */
  at: string
  /** 1=周一 … 7=周日，仅每周执行时有效 */
  weekday: number
  /** 目标目录（绝对路径，必须落在应用自己的数据目录之外） */
  dir: string
  /** 保留份数 */
  keep: number
}

/** 计划备份最近一次的执行结果 */
export interface BackupRunState {
  at: string
  ok: boolean
  /** 由「立即执行一次」触发 */
  manual?: boolean
  file?: string
  size?: number
  pruned?: number
  error?: string
}

/** 目标目录里的一份备份副本 */
export interface BackupPlanFile {
  name: string
  size: number
  mod_time: string
}

/** 计划备份的完整状态 */
export interface BackupPlanStatus {
  plan: BackupPlan
  last?: BackupRunState
  since?: string
  next_at?: string
  files: BackupPlanFile[]
  dir_ok: boolean
  dir_note?: string
  /** 用户在飞牛里授权给本应用的目录（目标目录只能从这里面选） */
  authorized_dirs: string[]
  /** 是否必须从上面那份清单里选（开发模式为 false） */
  auth_required: boolean
  /** 配置解析出来的实际落盘目录：目标选「应用自己的备份目录」时就是它 */
  resolved_dir: string
}

/**
 * 巡检里的一条结论。
 *
 * level 为 ok 的是「检查且通过」的记录：界面上的异常清单会过滤掉它们，
 * 但报告会留着 —— 一份只记异常的报告看不出「到底查了没有」。
 */
export interface InspectItem {
  /** 稳定标识（界面据此去重，也用来对比「上次这条还在不在」） */
  key: string
  level: 'ok' | 'warning' | 'error'
  title: string
  detail: string
  fix?: string
  /** 能否在「系统维护」里一键修好 */
  repairable?: boolean
  /** 需要用户去别的页面处理时的目标路由名 */
  to?: string
}

/** 一次巡检的完整结论 */
export interface InspectReport {
  at: string
  /** 由用户点「立即巡检一次」触发（与按日程区分） */
  manual?: boolean
  items: InspectItem[]
  errors: number
  warnings: number
  passed: number
}

/** 巡检计划：开关 + 日程 + 保留报告份数 */
export interface InspectPlan {
  enabled: boolean
  freq: 'daily' | 'weekly'
  at: string
  /** 1=周一 … 7=周日（仅每周执行时有效） */
  weekday: number
  keep: number
}

/** 巡检的对外状态 */
export interface InspectStatus {
  plan: InspectPlan
  /** 最近一次报告；从没跑过时为空 */
  last?: InspectReport
  /** 历史报告（含最近一次），新的在前 */
  reports: InspectReport[]
  since?: string
  next_at?: string
}

/** 此刻的判定结论（顶栏与各页的异常清单读它，含通过项） */
export interface InspectChecks {
  at: string
  items: InspectItem[]
}
