// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { AuthState, LoginChallenge, User } from '@/api/types'

/** 登录第一步的结果：要么已经登录，要么拿到一个待二次验证的挑战。 */
export interface LoginOutcome {
  totpRequired: boolean
  challenge: string
}

interface State {
  initialized: boolean
  authenticated: boolean
  user: User | null
  permissions: Record<string, boolean>
  version: string
  loaded: boolean
}

export const useSession = defineStore('session', {
  state: (): State => ({
    initialized: false,
    authenticated: false,
    user: null,
    permissions: {},
    version: '',
    loaded: false,
  }),
  getters: {
    can: (s) => (perm: string) => s.user?.role === 'admin' || !!s.permissions[perm],
    isAdmin: (s) => s.user?.role === 'admin',
  },
  actions: {
    /**
     * 读取登录态。
     *
     * 只有一条登录路径：本应用自己的账号密码（或安全码应急登录）。
     * 从飞牛桌面点图标进来时，fnOS 会先校验飞牛账号会话，但那只决定
     * 「能不能打开这个页面」——进到应用里仍然要登录，本应用不认任何外部身份。
     */
    async loadState() {
      const data = await api.get<AuthState>('/auth/state')
      this.initialized = data.initialized
      this.authenticated = data.authenticated
      this.user = data.user
      if (data.authenticated) {
        await this.loadMe()
      }
      this.loaded = true
    },
    async loadMe() {
      const data = await api.get<{ user: User; permissions: Record<string, boolean>; version: string }>(
        '/auth/me',
      )
      this.user = data.user
      this.permissions = data.permissions || {}
      this.version = data.version
    },
    /**
     * 登录第一步：提交账号口令。
     *
     * 账号开启二次验证时服务端**不会**下发会话，只回一个一次性挑战；
     * 因此这里不能把响应当作用户信息，必须交给调用方决定是否进入第二步。
     */
    async login(username: string, password: string): Promise<LoginOutcome> {
      const res = await api.post<User & LoginChallenge>('/auth/login', { username, password })
      if (res.totp_required) {
        return { totpRequired: true, challenge: res.challenge || '' }
      }
      this.user = res as User
      this.authenticated = true
      await this.loadMe()
      return { totpRequired: false, challenge: '' }
    },
    /**
     * 登录第二步：提交动态口令或恢复码，换取真正的会话。
     *
     * trustDevice 为真时服务端会下发一枚设备令牌（HttpOnly Cookie），
     * 该设备 30 天内登录可跳过这一步。
     */
    async loginTOTP(challenge: string, code: string, trustDevice = false) {
      const u = await api.post<User>('/auth/login/totp', {
        challenge,
        code,
        trust_device: trustDevice,
      })
      this.user = u
      this.authenticated = true
      await this.loadMe()
    },
    /**
     * 初始化管理员。
     *
     * 返回一次性下发的应急安全码（明文只在这一刻存在）；生成失败时 securityCodeError 非空。
     */
    async setup(
      username: string,
      password: string,
    ): Promise<{ securityCode: string; securityCodeError: string }> {
      const res = await api.post<{
        user: User
        security_code?: string
        security_code_error?: string
      }>('/auth/setup', { username, password })
      this.user = res.user
      this.authenticated = true
      this.initialized = true
      await this.loadMe()
      return {
        securityCode: res.security_code || '',
        securityCodeError: res.security_code_error || '',
      }
    },

    /**
     * 应急登录：用安全码进入。
     *
     * 成功后服务端会下发新的一枚安全码（旧码已被消耗），必须展示给用户保存。
     */
    async emergencyLogin(code: string, newPassword: string): Promise<string> {
      const res = await api.post<{ user: User; new_code: string }>('/auth/emergency', {
        code,
        new_password: newPassword,
      })
      this.user = res.user
      this.authenticated = true
      await this.loadMe()
      return res.new_code || ''
    },
    async logout() {
      await api.post('/auth/logout')
      this.authenticated = false
      this.user = null
      this.permissions = {}
    },
  },
})