export function formatBytes(n?: number): string {
  if (!n || n <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let v = n
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`
}

export function formatRate(bps?: number): string {
  if (!bps || bps <= 0) return '0 B/s'
  return `${formatBytes(bps)}/s`
}

export function formatTime(ts?: string | null): string {
  if (!ts) return '-'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return '-'
  return d.toLocaleString()
}

export function timeAgo(ts?: string | null): string {
  if (!ts) return '从未'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return '从未'
  const diff = (Date.now() - d.getTime()) / 1000
  if (diff < 60) return `${Math.floor(diff)} 秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)} 分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)} 小时前`
  return `${Math.floor(diff / 86400)} 天前`
}

export type HandshakeLevel = 'ok' | 'warn' | 'off'

export function handshakeLevel(ts?: string | null): HandshakeLevel {
  if (!ts) return 'off'
  const d = new Date(ts)
  if (Number.isNaN(d.getTime()) || d.getFullYear() < 1971) return 'off'
  const diff = Date.now() - d.getTime()
  if (diff < 2 * 60 * 1000) return 'ok'
  if (diff < 5 * 60 * 1000) return 'warn'
  return 'off'
}

export function daysLeft(ts?: string | null): number | null {
  if (!ts) return null
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return null
  return Math.ceil((d.getTime() - Date.now()) / 86400000)
}

/**
 * 账号的展示名。
 *
 * 飞牛账号（source=gateway）的 username 是 nas:<uid> 这样的映射锚点，是用户从未
 * 设置过、也认不出来的名字；飞牛那边叫什么，这里就显示什么。本地账号没有
 * display_name，回落成用户名本身 —— 所以调用方一律用它取值，不必分情况。
 */
export function displayNameOf(u?: { username?: string; display_name?: string } | null): string {
  return u?.display_name || u?.username || ''
}

/**
 * 账号是否由飞牛账号映射而来。
 *
 * 用来决定「改密码」「二次验证」这类入口要不要显示：飞牛账号的密码与二次验证
 * 都由飞牛 NAS 统一管理（它从桌面免密进入，不经过本应用的动态口令校验），
 * 在这里给入口只会让人以为改了能生效，而实际上永远用不上。
 */
export function isGatewayAccount(u?: { source?: string } | null): boolean {
  return u?.source === 'gateway'
}
