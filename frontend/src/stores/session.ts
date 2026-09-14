import { defineStore } from 'pinia'
import { api } from '@/api/client'
import type { User } from '@/api/types'

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
    async loadState() {
      const data = await api.get<{ initialized: boolean; authenticated: boolean; user: User | null }>(
        '/auth/state',
      )
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
    async login(username: string, password: string) {
      const u = await api.post<User>('/auth/login', { username, password })
      this.user = u
      this.authenticated = true
      await this.loadMe()
    },
    async setup(username: string, password: string) {
      const u = await api.post<User>('/auth/setup', { username, password })
      this.user = u
      this.authenticated = true
      this.initialized = true
      await this.loadMe()
    },
    async logout() {
      await api.post('/auth/logout')
      this.authenticated = false
      this.user = null
      this.permissions = {}
    },
  },
})
