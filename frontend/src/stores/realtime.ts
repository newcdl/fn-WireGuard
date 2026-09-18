// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

import { defineStore } from 'pinia'
import { wsURL } from '@/api/base'
import type { Status } from '@/api/types'

let socket: WebSocket | null = null
let retry = 0
let timer: number | null = null

export const useRealtime = defineStore('realtime', {
  state: () => ({
    connected: false,
    status: null as Status | null,
    lastUpdate: '' as string,
  }),
  actions: {
    connect() {
      if (socket && (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CONNECTING)) {
        return
      }
      // 地址由 base.ts 统一拼：网关下 WebSocket 与接口共用同一入口前缀，
      // 写死 /api/v1/ws 会在网关里连到 fnOS 系统本身而不是本应用。
      try {
        socket = new WebSocket(wsURL())
      } catch {
        this.scheduleReconnect()
        return
      }
      socket.onopen = () => {
        this.connected = true
        retry = 0
      }
      socket.onmessage = (ev) => {
        try {
          const msg = JSON.parse(ev.data)
          if (msg.type === 'status' && msg.data) {
            this.status = msg.data as Status
            this.lastUpdate = new Date().toLocaleTimeString()
          }
        } catch {
          /* 忽略非法消息 */
        }
      }
      socket.onclose = () => {
        this.connected = false
        this.scheduleReconnect()
      }
      socket.onerror = () => {
        socket?.close()
      }
    },
    scheduleReconnect() {
      if (timer) return
      retry = Math.min(retry + 1, 10)
      timer = window.setTimeout(() => {
        timer = null
        this.connect()
      }, Math.min(1000 * retry, 8000))
    },
    disconnect() {
      if (timer) {
        clearTimeout(timer)
        timer = null
      }
      socket?.close()
      socket = null
      this.connected = false
    },
  },
})
