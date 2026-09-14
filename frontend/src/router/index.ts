import { createRouter, createWebHashHistory } from 'vue-router'
import { useSession } from '@/stores/session'

const router = createRouter({
  // 使用 hash 模式，避免 fnOS 反向代理子路径下的 404 问题
  history: createWebHashHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('@/views/Login.vue'), meta: { public: true } },
    { path: '/setup', name: 'setup', component: () => import('@/views/Setup.vue'), meta: { public: true } },
    {
      path: '/',
      component: () => import('@/layouts/MainLayout.vue'),
      children: [
        { path: '', redirect: '/dashboard' },
        { path: 'dashboard', name: 'dashboard', component: () => import('@/views/Dashboard.vue') },
        { path: 'interfaces', name: 'interfaces', component: () => import('@/views/Interfaces.vue') },
        { path: 'peers', name: 'peers', component: () => import('@/views/Peers.vue') },
        { path: 'logs', name: 'logs', component: () => import('@/views/Logs.vue') },
        { path: 'settings', name: 'settings', component: () => import('@/views/Settings.vue') },
      ],
    },
    // 兜底路由：任何未匹配的路径都回到总览，避免出现"点一下就白屏"
    { path: '/:pathMatch(.*)*', redirect: '/dashboard' },
  ],
})

router.beforeEach(async (to) => {
  const session = useSession()
  if (!session.loaded) {
    try {
      await session.loadState()
    } catch {
      /* 网络异常时按未登录处理 */
    }
  }
  if (to.meta.public) {
    if (session.authenticated && to.name !== 'setup') {
      return { name: 'dashboard' }
    }
    return true
  }
  if (!session.initialized) {
    return { name: 'setup' }
  }
  if (!session.authenticated) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  return true
})

export default router
