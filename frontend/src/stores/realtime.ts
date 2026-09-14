import { defineStore } from 'pinia'
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
      const proto = location.protocol === 'https:' ? 'wss' : 'ws'
      const url = `${proto}://${location.host}/api/v1/ws`
      try {
        socket = new WebSocket(url)
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
