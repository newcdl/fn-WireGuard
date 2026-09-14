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
