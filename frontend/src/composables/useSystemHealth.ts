import { computed, ref } from 'vue'
import { api } from '@/api/client'
import type { Health, NetworkCheckResult, Overview } from '@/api/types'

/**
 * 全局「系统健康」数据源与异常清单推导。
 *
 * 为什么集中在一处：
 *   用户启用某项功能后「运行状态不符合预期」的原因散落在很多层
 *   （后台服务没起来、内核模块没开、出口网卡探测不到、系统路由有残留、连接没真正起来…）。
 *   若每个页面各判断一次，就会出现「总览报红、连接页却显示正常」这种自相矛盾，
 *   用户不知道该信哪个。这里把它们统一推导成一份**异常清单**，
 *   顶栏状态栏、总览、我的连接、系统维护都读同一份数据，口径完全一致。
 *
 * 其它约束：
 *   1. 只读，绝不在这里做任何修改动作 —— 修复动作一律由用户显式触发；
 *   2. 任一接口失败都不影响其它项（Promise.allSettled），
 *      避免「一个探测失败导致整块状态空白」，那反而让用户失去线索；
 *   3. 轮询间隔取 60 秒：这些数据来自 netlink/nftables 实读，
 *      比实时流量重，没必要跟 WebSocket 一样高频。
 */

export type IssueLevel = 'error' | 'warning'

/** 一条需要用户知道的异常。level=error 表示功能确实没在工作。 */
export interface HealthIssue {
  key: string
  level: IssueLevel
  title: string
  /** 具体事实（哪张网卡、哪一层没过） */
  detail: string
  /** 处理建议 */
  fix?: string
  /** 能否在「系统维护」里一键修好 */
  repairable?: boolean
  /** 需要用户去别的页面处理时的目标路由名 */
  to?: string
}

const loading = ref(false)
const loaded = ref(false)
const net = ref<NetworkCheckResult | null>(null)
const health = ref<Health | null>(null)
const overview = ref<Overview | null>(null)
const failedReason = ref('')
const checkedAt = ref('')

let timer: number | null = null

async function refresh(): Promise<void> {
  loading.value = true
  try {
    const [n, h, o] = await Promise.allSettled([
      api.get<NetworkCheckResult>('/system/network'),
      api.get<Health>('/health'),
      api.get<Overview>('/overview'),
    ])
    if (n.status === 'fulfilled') {
      net.value = n.value
      failedReason.value = ''
    } else {
      failedReason.value = (n.reason as Error)?.message || '网络自检失败'
    }
    if (h.status === 'fulfilled') health.value = h.value
    if (o.status === 'fulfilled') overview.value = o.value
    checkedAt.value = new Date().toLocaleTimeString()
    loaded.value = true
  } finally {
    loading.value = false
  }
}

/**
 * 异常清单。
 *
 * 判定顺序即重要性顺序：后台服务 → 运行模式 → 系统网络 → 连接 → 内网访问 → 残留 → 配置。
 * 每一条都必须是「用户在界面上能看懂、且知道下一步做什么」的事实。
 */
const issues = computed<HealthIssue[]>(() => {
  const out: HealthIssue[] = []
  const h = health.value
  const n = net.value
  const o = overview.value

  // ① 后台服务没运行：此时任何配置都不会生效，必须最先说
  if (h && !h.agent_up) {
    out.push({
      key: 'agent',
      level: 'error',
      title: '后台服务未运行，当前修改不会生效',
      detail: '负责实际建立连接的组件（fnwg-agent）没有运行。',
      fix: '到应用中心重启本应用；若重启后仍不恢复，请查看「运行记录」中的错误。',
      to: 'logs',
    })
  }

  // ② 标准模式不可用：新建连接会失败，但已有连接可能仍在工作
  if (h && h.agent_up && !h.kernel_module) {
    out.push({
      key: 'kernel',
      level: 'error',
      title: '系统未开启标准加速模式',
      detail: '找不到内核加密网络模块，新建的连接无法工作。',
      fix: '确认 NAS 系统版本较新（一般 0.9.0 以上），或用「兼容模式」相关选项。',
      to: 'logs',
    })
  }

  // ③ NAS 系统上网路线被本应用占用：唯一可能影响系统网络的情况，最要紧
  if (n && (n.stray_defaults?.length || !n.healthy)) {
    const stray = (n.stray_defaults || []).map((d) => `dev=${d.dev || '-'}`).join('、')
    out.push({
      key: 'net',
      level: 'error',
      title: 'NAS 自身的上网路线异常',
      detail: stray
        ? `系统默认路由指向了本应用的连接（${stray}），FN Connect / 应用市场可能已受影响。`
        : n.messages?.join('；') || '系统网络自检未通过。',
      fix: '点「立即修复」，或到「系统维护」执行一键修复；本应用只会清理自己造成的残留。',
      repairable: true,
      to: 'maintenance',
    })
  }

  // ④ 已启用但没真正工作的连接 —— 「启用了功能，运行状态不符合预期」的典型
  const notUp = (o?.interfaces || []).filter((i) => i.enabled && !i.up)
  if (notUp.length) {
    out.push({
      key: 'iface-down',
      level: 'error',
      title: `${notUp.length} 条已启用的连接没有工作`,
      detail: `未工作：${notUp.map((i) => i.name).join('、')}。设备现在连不上。`,
      fix: '到「我的连接」查看该连接，点「重新应用」把配置重新下发一次。',
      to: 'interfaces',
    })
  }

  // ⑤ 内网访问：开关开着但链路没就绪。判定依据是后端逐层自检，避免前端自己猜
  const natFailed = (n?.nat?.checks || []).filter((c) => !c.ok)
  if (natFailed.length) {
    out.push({
      key: 'nat',
      level: 'warning',
      title: '「允许设备访问家里内网」已开启，但还没真正生效',
      detail: natFailed.map((c) => `${c.label}：${c.detail}`).join('；'),
      fix: natFailed.find((c) => c.fix)?.fix,
      to: 'maintenance',
    })
  }

  // ⑥ 疑似残留网卡：不是错误（可能真在被别的工具使用），但会一直占着端口
  if (n?.foreign_interfaces?.length) {
    const list = n.foreign_interfaces.map((f) => f.name).join('、')
    out.push({
      key: 'foreign',
      level: 'warning',
      title: `发现 ${n.foreign_interfaces.length} 个疑似残留网卡`,
      detail: `${list} 不是本应用创建的，会占用它们监听中的端口。`,
      fix: '确认不是别的工具在用之后，到「系统维护」清理。',
      to: 'maintenance',
    })
  }

  // ⑦ 还没填对外访问地址：二维码里的地址在外网用不了
  if (o && o.interface_count > 0 && !o.server_endpoint) {
    out.push({
      key: 'endpoint',
      level: 'warning',
      title: '还没有填写「对外访问地址」',
      detail: '手机在外网需要一个能连回家的地址，现在生成的二维码只在内网可用。',
      fix: '到「系统设置 → 接入设置」填写家里的公网域名或 IP。',
      to: 'settings',
    })
  }

  return out
})

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

/** 用户执行过修复动作后调用，让各处状态立刻同步（不必等下一次轮询）。 */
export function refreshSystemHealth(): Promise<void> {
  return refresh()
}

export function useSystemHealth() {
  return {
    loading,
    loaded,
    net,
    health,
    overview,
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
