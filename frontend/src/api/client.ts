// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { API_BASE } from './base'

// 接口根地址随入口变化（独立端口 / 飞牛统一网关子路径），见 base.ts。
const BASE = API_BASE

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const res = await fetch(BASE + path, {
    credentials: 'include',
    headers: { 'Content-Type': 'application/json', ...(init.headers || {}) },
    ...init,
  })
  const text = await res.text()
  let payload: any = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }
  if (!res.ok) {
    const msg = payload?.message || `请求失败（HTTP ${res.status}）`
    throw new ApiError(res.status, msg)
  }
  return (payload?.data ?? payload) as T
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'POST', body: JSON.stringify(body ?? {}) }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PATCH', body: JSON.stringify(body ?? {}) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: 'PUT', body: JSON.stringify(body ?? {}) }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
}

export function download(path: string) {
  const a = document.createElement('a')
  a.href = BASE + path
  a.rel = 'noopener'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
}

/** 以原始字符串作为请求体 POST（用于导入备份等需要原样上传 JSON 文件的场景）。 */
export async function postRaw<T>(path: string, body: string): Promise<T> {
  const res = await fetch(BASE + path, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body,
  })
  const text = await res.text()
  let payload: any = null
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }
  if (!res.ok) {
    throw new ApiError(res.status, payload?.message || `请求失败（HTTP ${res.status}）`)
  }
  return (payload?.data ?? payload) as T
}

export async function downloadText(path: string, filename: string) {
  const res = await fetch(BASE + path, { credentials: 'include' })
  if (!res.ok) {
    // 把服务端那句话带出来：「文件已不存在」和「没有权限」要用户做的事完全不同，
    // 一律显示「下载失败」等于把原因吞掉，用户只能去猜。
    let msg = `下载失败（HTTP ${res.status}）`
    try {
      const payload = await res.json()
      if (payload?.message) msg = payload.message
    } catch {
      /* 响应不是 JSON：保留上面那句带状态码的兜底说明 */
    }
    throw new ApiError(res.status, msg)
  }
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
