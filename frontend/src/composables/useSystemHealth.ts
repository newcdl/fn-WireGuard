// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { computed, ref } from 'vue'
import { api } from '@/api/client'
import type { Health, InspectChecks, InspectItem, NetworkCheckResult } from '@/api/types'

/**
 * 全局「系统健康」数据源：取回结论、按等级过滤。
 *
 * **判定本身不在这里**，在服务端（`internal/service/inspect.go` 的 `judgeInspect`）。
 * 为什么挪过去：
 *   1. 「配置漂移巡检报告」必须能在没有浏览器的时候生成（它跑在常驻的代理进程里）；
 *   2. 判定一旦有第二份实现，就会出现「界面说正常、报告说异常」这种自相矛盾 ——
 *      同一个应用里两套口径，用户不知道该信哪个（本项目在权限判据上吃过两次同样的亏）。
 * 所以这里只调 `/system/inspect/checks` 把服务端的结论取回来，按等级分两档。
 * 定期报告读的是同一个函数、同一批检查项，两边天然一致。
 *
 * 其它约束不变：
 *   1. 只读，绝不在这里做任何修改动作 —— 修复动作一律由用户显式触发；
 *   2. 任一接口失败都不影响其它项（Promise.allSettled），
 *      避免「一个探测失败导致整块状态空白」，那反而让用户失去线索；
 *   3. 轮询间隔取 60 秒：这些数据来自 netlink/nftables 实读，比实时流量重。
 */

export type IssueLevel = 'error' | 'warning'

/** 一条需要用户知道的异常。level=error 表示功能确实没在工作。 */
export type HealthIssue = InspectItem & { level: IssueLevel }

const loading = ref(false)
const loaded = ref(false)
const net = ref<NetworkCheckResult | null>(null)
const health = ref<Health | null>(null)
/** checks 是服务端的判定结论（含通过项，界面按等级过滤）。 */
const checks = ref<InspectItem[]>([])
const failedReason = ref('')
const checkedAt = ref('')

let timer: number | null = null

async function refresh(): Promise<void> {
  loading.value = true
  try {
    const [n, h, c] = await Promise.allSettled([
      api.get<NetworkCheckResult>('/system/network'),
      api.get<Health>('/health'),
      api.get<InspectChecks>('/system/inspect/checks'),
    ])
    if (n.status === 'fulfilled') {
      net.value = n.value
      failedReason.value = ''
    } else {
      failedReason.value = (n.reason as Error)?.message || '网络自检失败'
    }
    if (h.status === 'fulfilled') health.value = h.value
    // 判定取不到时**保留上一次的结论**：它仍然是「最近一次知道的事实」，
    // 而清空会让顶栏瞬间变绿 —— 一个假的「一切正常」比一份旧结论危险得多。
    if (c.status === 'fulfilled') {
      checks.value = c.value.items || []
      if (!failedReason.value) checkedAt.value = new Date().toLocaleTimeString()
    }
    loaded.value = true
  } finally {
    loading.value = false
  }
}

/**
 * 异常清单。
 *
 * 顺序就是服务端判定的顺序（重要性：后台服务 → 运行模式 → 系统网络 → 桌面入口 →
 * 连接 → 内网访问 → 隔离 → 访问控制冲突 → 残留网卡 → 对外地址 → 通知 → 解析 → 备份），
 * 这里不再排序：两种排序迟早会不一致，而「哪个更要紧」只该有一处说了算。
 */
const issues = computed<HealthIssue[]>(() =>
  checks.value.filter((it): it is HealthIssue => it.level !== 'ok'),
)

const errors = computed(() => issues.value.filter((i) => i.level === 'error'))
const warnings = computed(() => issues.value.filter((i) => i.level === 'warning'))

/** 顶栏状态栏的总体色调：有错误红、只有警告黄、全通过绿、没数据灰。 */
const tone = computed<'ok' | 'warn' | 'down' | 'off'>(() => {
  if (!loaded.value) return 'off'
  if (errors.value.length) return 'down'
  if (warnings.value.length) return 'warn'
  return 'ok'
})

const toneLabel = computed(() => {
  if (!loaded.value) return '正在检查…'
  if (errors.value.length) return `${errors.value.length} 项异常需要处理`
  if (warnings.value.length) return `${warnings.value.length} 项待确认`
  return '运行状态正常'
})

/** 启动周期体检。重复调用安全（已启动时只立即刷新一次）。 */
function start(intervalMs = 60000): void {
  void refresh()
  if (timer === null) {
    timer = window.setInterval(() => void refresh(), intervalMs)
  }
}

function stop(): void {
  if (timer !== null) {
    clearInterval(timer)
    timer = null
  }
}

/** 用户执行过修复动作（或手动巡检）后调用，让各处状态立刻同步（不必等下一次轮询）。 */
export function refreshSystemHealth(): Promise<void> {
  return refresh()
}

export function useSystemHealth() {
  return {
    loading,
    loaded,
    net,
    health,
    checkedAt,
    failedReason,
    issues,
    errors,
    warnings,
    tone,
    toneLabel,
    refresh,
    start,
    stop,
  }
}
