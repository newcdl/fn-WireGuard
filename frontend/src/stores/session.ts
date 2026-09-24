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
  /** 本次请求走的通道：socket = 飞牛桌面经统一网关进来，port = 端口直连。 */
  channel: string
  /** 本次请求是否带着可用的飞牛身份（即能不能免密进入）。 */
  gatewayAvailable: boolean
  /** 有飞牛身份却被挡住的原因（例如账号已被停用）：登录页要显示，不能让人对着表单猜。 */
  gatewayBlocked: string
  /** 本次请求带着的飞牛身份（登录页的按钮要显示用户名）。 */
  gatewayUser: { username: string; is_admin: boolean } | null
  /** 这次身份是怎么来的：session = 本应用会话（可以退出登录）；gateway = 飞牛身份（没有会话可退）。 */
  identity: string
}

export const useSession = defineStore('session', {
  state: (): State => ({
    initialized: false,
    authenticated: false,
    user: null,
    permissions: {},
    version: '',
    loaded: false,
    channel: 'port',
    gatewayAvailable: false,
    gatewayBlocked: '',
    gatewayUser: null,
    identity: '',
  }),
  getters: {
    can: (s) => (perm: string) => s.user?.role === 'admin' || !!s.permissions[perm],
    isAdmin: (s) => s.user?.role === 'admin',
  },
  actions: {
    /**
     * 读取登录态。
     *
     * 两条进入方式，判定由服务端给（这里不自己推）：
     *  - 端口通道：本应用自己的账号密码，或安全码应急登录；
     *  - 统一网关通道：飞牛在转发前已校验飞牛账号会话，并注入身份头，本应用据此免密进入
     *    （只在连接确实来自网关进程的 Unix Socket 时才认，见后端 gateway.go）。
     * 无论哪条通道，进去之后的权限判定完全一样。
     */
    async loadState() {
      const data = await api.get<AuthState>('/auth/state')
      this.initialized = data.initialized
      this.authenticated = data.authenticated
      this.user = data.user
      this.channel = data.channel || 'port'
      this.gatewayAvailable = !!data.gateway_available
      this.gatewayBlocked = data.gateway_blocked || ''
      this.identity = data.identity || ''
      this.gatewayUser = data.gateway_user || null
      if (data.authenticated) {
        await this.loadMe()
      }
      this.loaded = true
    },
    /**
     * 以飞牛账号登录：把「这次请求带着的飞牛身份」换成一份普通会话。
     *
     * 为什么必须显式点一下、而不是让服务端按请求头自动放行：身份头每个请求都会带上，
     * 自动放行会让「退出登录」变成下一刻又被带进来；明确点一次，用户也知道自己用哪个身份进来。
     */
    async gatewayLogin() {
      await api.post('/auth/gateway-login', {})
      await this.loadState()
      if (this.authenticated) await this.loadMe()
    },
    async loadMe() {
      const data = await api.get<{
        user: User
        permissions: Record<string, boolean>
        version: string
        identity?: string
      }>('/auth/me')
      this.user = data.user
      this.permissions = data.permissions || {}
      this.version = data.version
      if (data.identity) this.identity = data.identity
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
     * 不建本地账号的初始化：把第一位管理员交给飞牛身份（对应后端 setupGatewayOnly）。
     *
     * 与 setup 的区别只有一点：本地不落任何口令。之后进入方式完全由飞牛账号承担，
     * 所以账号管理里也不该出现「修改密码」这类本地口令操作。
     */
    async setupWithGateway(): Promise<{ securityCode: string; securityCodeError: string }> {
      const res = await api.post<{
        user: User
        security_code?: string
        security_code_error?: string
      }>('/auth/setup', { gateway_only: true })
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