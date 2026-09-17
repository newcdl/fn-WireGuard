import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type {
  AuthState,
  GatewayEntry,
  LoginChallenge,
  LoginMode,
  LoginModeState,
  User,
} from '@/api/types'

/** 登录第一步的结果：要么已经登录，要么拿到一个待二次验证的挑战。 */
export interface LoginOutcome {
  totpRequired: boolean
  challenge: string
}

/**
 * 页面加载期间是否已自动尝试过飞牛账号免密登录。
 *
 * 放在模块级而不是 store 里：它要表达的是「本次页面加载只自动尝试一次」，
 * 与登录态本身无关。没有它的话，用户点了「退出登录」会立刻被自动登录回来。
 */
let gatewayAutoTried = false

interface State {
  initialized: boolean
  authenticated: boolean
  user: User | null
  permissions: Record<string, boolean>
  version: string
  loaded: boolean
  /** 当前入口的飞牛身份信息（登录页据此展示一键登录）。 */
  gateway: GatewayEntry
  /** 当前登录方式（决定登录页展示哪些入口）。 */
  loginMode: LoginMode
}

export const useSession = defineStore('session', {
  state: (): State => ({
    initialized: false,
    authenticated: false,
    user: null,
    permissions: {},
    version: '',
    loaded: false,
    gateway: {},
    loginMode: 'both',
  }),
  getters: {
    can: (s) => (perm: string) => s.user?.role === 'admin' || !!s.permissions[perm],
    isAdmin: (s) => s.user?.role === 'admin',
  },
  actions: {
    /**
     * 读取登录态与入口信息。
     *
     * 若当前是飞牛桌面打开的应用且尚未登录，会顺带自动尝试一次免密登录 ——
     * 这正是「NAS 账号免密」的体验：用户点开图标就直接进去了，
     * 不需要再输入任何东西。全流程只自动尝试一次，避免退出登录后被立刻登回来。
     */
    async loadState() {
      const data = await api.get<AuthState>('/auth/state')
      this.initialized = data.initialized
      this.authenticated = data.authenticated
      this.user = data.user
      this.gateway = data.gateway || {}
      this.loginMode = data.login_mode || 'both'
      if (data.authenticated) {
        await this.loadMe()
      } else if (data.initialized && this.gateway.available && !gatewayAutoTried) {
        gatewayAutoTried = true
        try {
          await this.gatewayLogin()
        } catch {
          // 自动登录失败不该弹错误：用户仍可手动点「一键登录」或改用账号密码，
          // 具体失败原因会在手动操作时如实展示。
        }
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
     * 飞牛账号免密登录：身份由飞牛统一网关注入，本应用据此建立本地会话。
     *
     * 只能用经 Unix Socket 转发过来的请求调用；直接访问端口时服务端会拒绝。
     */
    async gatewayLogin() {
      const res = await api.post<{ user: User }>('/auth/gateway')
      this.user = res.user
      this.authenticated = true
      await this.loadMe()
    },

    /** 读取登录方式与网关可用性（含「是否已验证过网关能进来」）。 */
    async loadLoginMode(): Promise<LoginModeState> {
      const data = await api.get<LoginModeState>('/auth/login-mode')
      this.loginMode = data.mode || 'both'
      return data
    },

    /** 修改登录方式（管理员）。 */
    async setLoginMode(mode: LoginMode): Promise<LoginModeState> {
      const data = await api.put<LoginModeState>('/auth/login-mode', { mode })
      this.loginMode = data.mode
      return data
    },

    /**
     * 初始化管理员。
     *
     * 返回一次性下发的应急安全码（明文只在这一刻存在）；生成失败时 securityCodeError 非空。
     */
    async setup(username: string, password: string): Promise<{
      securityCode: string
      securityCodeError: string
    }> {
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
      // 用户已主动退出：本次页面加载内不再自动免密登录，
      // 否则「退出登录」看起来毫无作用（点一下就被飞牛账号登回来）。
      gatewayAutoTried = true
    },
  },
})
