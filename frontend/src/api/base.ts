// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

/**
 * 飞牛统一网关分配给本应用的公开前缀。
 *
 * 必须与后端 `api.GatewayPrefix` 及 `apps/fn-wireguard/app/ui/config` 的
 * `gatewayPrefix` 保持一致 —— 三处任意一处不同，就会变成
 * 「页面能打开但所有请求都 404」这类极难定位的故障。
 */
export const GATEWAY_PREFIX = '/app/fn-wireguard'

/**
 * 当前页面所处的挂载前缀：独立端口下为空串，网关下为 /app/fn-wireguard。
 *
 * 为什么不能把 /api/v1 写死：网关把整个应用挂在 fnOS 域名的一个子路径下，
 * 站根的 /api/v1 属于 fnOS 系统本身，写死就会把请求打到错误的地方。
 * 所有请求地址都必须相对当前入口拼出来。
 */
export const BASE_PATH = window.location.pathname.startsWith(GATEWAY_PREFIX) ? GATEWAY_PREFIX : ''

/** 接口根地址。 */
export const API_BASE = `${BASE_PATH}/api/v1`

/** 实时推送地址（WebSocket 与接口走同一入口，网关下也不例外）。 */
export function wsURL(): string {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${location.host}${API_BASE}/ws`
}
