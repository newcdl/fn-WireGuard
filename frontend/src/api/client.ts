// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { API_BASE } from './base'

// 接口根地址随入口变化（独立端口 / 飞牛统一网关子路径），见 base.ts。
const BASE = API_BASE

export class ApiError extends Error {
  status: number
  /** 服务端要求先做一次二次验证（见后端 service/stepup.go 的开关）：界面据此弹验证框，而不是当成「没权限」。 */
  stepUp: boolean
  constructor(status: number, message: string, stepUp = false) {
    super(message)
    this.status = status
    this.stepUp = stepUp
  }
}

/**
 * 敏感操作遇到「需要先验证一次身份」时，交给界面弹框收验证码。
 *
 * 为什么放在这里、而不是每个敏感操作自己处理：那些操作（查看密钥、用备份还原、账号管理）
 * 散落在各个页面，每处都写一遍「拦截 403 → 弹框 → 重试」不但啰嗦，而且**一定会漏**。
 * 放在请求层，调用点一行都不用改。
 */
let stepUpHandler: (() => Promise<boolean>) | null = null

export function registerStepUpHandler(fn: () => Promise<boolean>): void {
  stepUpHandler = fn
}

async function request<T>(path: string, init: RequestInit = {}, retried = false): Promise<T> {
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
    if (payload?.step_up_required && !retried && stepUpHandler) {
      // 验证通过就原样重放这一次请求；没通过就照常把错误抛出去（不循环弹框）。
      // 只重试一次（retried 标记）：否则验证失败会变成反复弹框。
      if (await stepUpHandler()) return request<T>(path, init, true)
    }
    throw new ApiError(res.status, msg, !!payload?.step_up_required)
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
