<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 newcdl <newcdl@163.com> -->

<template>
  <div>
    <!--
      系统状态：与顶栏状态栏、系统维护同源（useSystemHealth）。
      以前这里堆了 4 条各自判断的告警，现在统一成一份清单，口径一致、点一下就能去处理。
    -->
    <div class="fnwg-card" style="margin-bottom: 12px">
      <div class="fnwg-card-head">
        <div>
          <strong>系统状态</strong>
          <span class="fnwg-card-desc">每 60 秒自动复查；有异常时会一直显示在页面顶部</span>
        </div>
        <el-tag
          size="small"
          :type="!issues.length ? 'success' : errors.length ? 'danger' : 'warning'"
          effect="plain"
        >
          {{ !issues.length ? '全部正常' : `${issues.length} 项待处理` }}
        </el-tag>
        <el-button size="small" @click="goMaintenance">打开系统维护</el-button>
      </div>

      <div v-if="!issues.length" class="fnwg-hint">系统上网路线、连接状态、内网访问与转发规则都已就绪。</div>

      <div v-for="it in issues" :key="it.key" class="fnwg-issue-line" :class="it.level">
        <span :class="['fnwg-dot', it.level === 'error' ? 'down' : 'warn']" />
        <div class="fnwg-issue-line-body">
          <strong>{{ it.title }}</strong>
          <div class="fnwg-hint">{{ it.detail }}</div>
          <div v-if="it.fix" class="fnwg-hint">处理建议：{{ it.fix }}</div>
        </div>
        <el-button v-if="it.to" link type="primary" @click="router.push({ name: it.to })">去处理</el-button>
      </div>
    </div>

    <!-- 新手引导：没有任何连接时出现 -->
    <div v-if="overview && overview.interface_count === 0" class="fnwg-card fnwg-onboarding">
      <div class="fnwg-onboarding-title">三步就能在外网连回家</div>
      <div class="fnwg-onboarding-steps">
        <div class="fnwg-onboarding-step">
          <span class="fnwg-step-no">1</span>
          <div>
            <div class="fnwg-step-title">建立一条安全通道</div>
            <div class="fnwg-step-desc">点击下方按钮即可完成，系统会自动选择合适的地址与端口。</div>
          </div>
        </div>
        <div class="fnwg-onboarding-step">
          <span class="fnwg-step-no">2</span>
          <div>
            <div class="fnwg-step-title">添加你的手机或电脑</div>
            <div class="fnwg-step-desc">在「我的设备」中新增一台设备，会生成一个二维码。</div>
          </div>
        </div>
        <div class="fnwg-onboarding-step">
          <span class="fnwg-step-no">3</span>
          <div>
            <div class="fnwg-step-title">用手机扫一扫</div>
            <div class="fnwg-step-desc">安装 WireGuard 官方 App，扫描二维码即可连回家中网络。</div>
          </div>
        </div>
      </div>
      <div class="fnwg-onboarding-actions">
        <el-button type="primary" size="large" :loading="quickStarting" @click="quickStart">
          一键创建推荐连接
        </el-button>
        <el-button size="large" @click="helpVisible = true">先看看各项设置是什么意思</el-button>
      </div>
      <div class="fnwg-onboarding-note">
        创建后如需在外网使用，请到「系统设置」填写对外访问地址，并在路由器上放行所需端口。
      </div>
    </div>

    <div class="fnwg-grid" style="margin-bottom: 12px">
      <div class="fnwg-card fnwg-stat">
        <div class="fnwg-stat-label">已建立的连接</div>
        <div class="fnwg-stat-value">
          {{ overview?.interface_up ?? 0 }}<span class="fnwg-stat-sub">/ {{ overview?.interface_count ?? 0 }}</span>
        </div>
        <div class="fnwg-stat-label">正在工作 / 总数</div>
      </div>
      <div class="fnwg-card fnwg-stat">
        <div class="fnwg-stat-label">在线设备</div>
        <div class="fnwg-stat-value">
          {{ onlineCount }}<span class="fnwg-stat-sub">/ {{ peerCount }}</span>
        </div>
        <div class="fnwg-stat-label">最近 3 分钟内有通信</div>
      </div>
      <div class="fnwg-card fnwg-stat">
        <div class="fnwg-stat-label">下行速度</div>
        <div class="fnwg-stat-value">{{ formatRate(liveRxRate) }}</div>
        <div class="fnwg-stat-label">累计接收 {{ formatBytes(liveRx) }}</div>
      </div>
      <div class="fnwg-card fnwg-stat">
        <div class="fnwg-stat-label">上行速度</div>
        <div class="fnwg-stat-value">{{ formatRate(liveTxRate) }}</div>
        <div class="fnwg-stat-label">累计发送 {{ formatBytes(liveTx) }}</div>
      </div>
    </div>

    <div class="fnwg-card" style="margin-bottom: 12px">
      <div class="fnwg-card-head">
        <div>
          <strong>实时速度</strong>
          <span class="fnwg-card-desc">最近 2 分钟的数据传输速度变化</span>
        </div>
        <span style="font-size: 12px; opacity: 0.6">{{ realtime.lastUpdate || '等待数据…' }}</span>
      </div>
      <div ref="chartEl" :style="{ height: chartHeight }"></div>
    </div>

    <!-- 连接状态 -->
    <div class="fnwg-card" style="margin-bottom: 12px">
      <div class="fnwg-card-head">
        <div>
          <strong>连接状态</strong>
          <span class="fnwg-card-desc">每条通道当前是否工作，以及上面接了多少设备</span>
        </div>
      </div>

      <el-table v-if="!isMobile" :data="overview?.interfaces || []" size="small">
        <el-table-column label="连接" width="120">
          <template #default="{ row }">
            <span :class="['fnwg-dot', row.up ? 'ok' : 'down']" />{{ row.name }}
          </template>
        </el-table-column>
        <el-table-column label="工作状态" width="100">
          <template #default="{ row }">
            <el-tag size="small" :type="row.up ? 'success' : 'danger'" effect="plain">
              {{ row.up ? '正常' : '未工作' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="内部地址">
          <template #default="{ row }">
            <span class="fnwg-mono">{{ (row.addresses || []).join(', ') || '-' }}</span>
          </template>
        </el-table-column>
        <el-table-column label="设备" width="80">
          <template #default="{ row }">{{ row.peer_online ?? 0 }}/{{ row.peer_count ?? 0 }}</template>
        </el-table-column>
        <el-table-column label="实时速度" width="160">
          <template #default="{ row }">
            ↓{{ formatRate(row.rx_rate) }} ↑{{ formatRate(row.tx_rate) }}
          </template>
        </el-table-column>
      </el-table>

      <template v-else>
        <ItemCard
          v-for="it in overview?.interfaces || []"
          :key="it.id"
          :status="it.up ? 'ok' : 'down'"
          :title="it.name"
        >
          <template #extra>
            <el-tag size="small" :type="it.up ? 'success' : 'danger'" effect="plain">
              {{ it.up ? '正常' : '未工作' }}
            </el-tag>
          </template>
          <div class="fnwg-kv">
            <span class="fnwg-kv-key">内部地址</span>
            <span class="fnwg-kv-val">{{ (it.addresses || []).join(', ') || '-' }}</span>
          </div>
          <div class="fnwg-kv">
            <span class="fnwg-kv-key">已接设备</span>
            <span class="fnwg-kv-val">{{ it.peer_online ?? 0 }} 在线 / 共 {{ it.peer_count ?? 0 }} 台</span>
          </div>
          <div class="fnwg-kv">
            <span class="fnwg-kv-key">实时速度</span>
            <span class="fnwg-kv-val">↓ {{ formatRate(it.rx_rate) }}　↑ {{ formatRate(it.tx_rate) }}</span>
          </div>
        </ItemCard>
        <div v-if="!(overview?.interfaces || []).length" class="fnwg-empty">还没有任何连接</div>
      </template>
    </div>

    <el-row :gutter="12">
      <el-col :xs="24" :lg="12">
        <div class="fnwg-card" style="margin-bottom: 12px">
          <div class="fnwg-card-head">
            <div>
              <strong>流量最多的设备</strong>
              <span class="fnwg-card-desc">按累计流量排序，可快速发现异常占用</span>
            </div>
          </div>
          <el-table v-if="!isMobile" :data="overview?.top_peers || []" size="small">
            <el-table-column prop="name" label="设备" min-width="120" show-overflow-tooltip />
            <el-table-column label="接收" width="100">
              <template #default="{ row }">{{ formatBytes(row.rx_bytes) }}</template>
            </el-table-column>
            <el-table-column label="发送" width="100">
              <template #default="{ row }">{{ formatBytes(row.tx_bytes) }}</template>
            </el-table-column>
            <el-table-column label="最近通信" width="110">
              <template #default="{ row }">{{ timeAgo(row.last_handshake) }}</template>
            </el-table-column>
          </el-table>
          <template v-else>
            <ItemCard
              v-for="p in overview?.top_peers || []"
              :key="p.id"
              :status="p.online ? 'ok' : 'off'"
              :title="p.name"
            >
              <div class="fnwg-kv">
                <span class="fnwg-kv-key">接收 / 发送</span>
                <span class="fnwg-kv-val">{{ formatBytes(p.rx_bytes) }} / {{ formatBytes(p.tx_bytes) }}</span>
              </div>
              <div class="fnwg-kv">
                <span class="fnwg-kv-key">最近通信</span>
                <span class="fnwg-kv-val">{{ timeAgo(p.last_handshake) }}</span>
              </div>
            </ItemCard>
            <div v-if="!(overview?.top_peers || []).length" class="fnwg-empty">暂无设备</div>
          </template>
        </div>
      </el-col>

      <el-col :xs="24" :lg="12">
        <div class="fnwg-card" style="margin-bottom: 12px">
          <div class="fnwg-card-head">
            <div>
              <strong>最近有通信的设备</strong>
              <span class="fnwg-card-desc">说明这些设备当前能正常连上</span>
            </div>
          </div>
          <el-table
            v-if="!isMobile"
            :data="overview?.recent_handshakes || []"
            size="small"
            empty-text="暂时没有设备在线"
          >
            <el-table-column prop="name" label="设备" min-width="130" />
            <el-table-column prop="interface_name" label="连接" width="90" />
            <el-table-column prop="endpoint" label="来自" min-width="150" />
            <el-table-column label="时间" width="110">
              <template #default="{ row }">{{ timeAgo(row.last_handshake) }}</template>
            </el-table-column>
          </el-table>
          <template v-else>
            <ItemCard
              v-for="p in overview?.recent_handshakes || []"
              :key="p.id"
              status="ok"
              :title="p.name"
            >
              <div class="fnwg-kv">
                <span class="fnwg-kv-key">来自</span>
                <span class="fnwg-kv-val">{{ p.endpoint || '未知地址' }}</span>
              </div>
              <div class="fnwg-kv">
                <span class="fnwg-kv-key">最近通信</span>
                <span class="fnwg-kv-val">{{ timeAgo(p.last_handshake) }}</span>
              </div>
            </ItemCard>
            <div v-if="!(overview?.recent_handshakes || []).length" class="fnwg-empty">暂时没有设备在线</div>
          </template>
        </div>
      </el-col>
    </el-row>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import * as echarts from 'echarts'
import { api } from '@/api/client'
import type { Overview, Status } from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import ItemCard from '@/components/ItemCard.vue'
import { allHelpGroups } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSystemHealth } from '@/composables/useSystemHealth'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import { formatBytes, formatRate, timeAgo } from '@/utils/format'

const router = useRouter()
const realtime = useRealtime()
const session = useSession()
const { isMobile } = useBreakpoint()

const overview = ref<Overview | null>(null)
const helpVisible = ref(false)
const quickStarting = ref(false)
const chartEl = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null
let timer: number | null = null

const series = ref<{ t: string[]; rx: number[]; tx: number[] }>({ t: [], rx: [], tx: [] })

const helpGroups = allHelpGroups

// 系统状态统一由全局健康源提供（顶栏、系统维护与本页同源）
const { issues, errors } = useSystemHealth()

function goMaintenance() {
  router.push({ name: 'maintenance' })
}

// 后端在无数据时可能返回 null（Go 的 nil 切片），这里统一按空数组处理，
// 否则对 null 调用 reduce 会抛错并导致整个页面空白。
const liveIfaces = computed(() => realtime.status?.interfaces ?? [])
const sumPeers = (pick: (p: NonNullable<Status['interfaces'][number]['peers']>[number]) => number) =>
  liveIfaces.value.reduce((sum, i) => sum + (i.peers ?? []).reduce((a, p) => a + pick(p), 0), 0)

const liveRxRate = computed(() => sumPeers((p) => p.rx_rate))
const liveTxRate = computed(() => sumPeers((p) => p.tx_rate))
const liveRx = computed(() => sumPeers((p) => p.rx_bytes))
const liveTx = computed(() => sumPeers((p) => p.tx_bytes))

const peerCount = computed(() => overview.value?.peer_count ?? 0)
const onlineCount = computed(() => {
  const live = liveIfaces.value.reduce(
    (s, i) =>
      s +
      (i.peers ?? []).filter(
        (p) => p.last_handshake && Date.now() - new Date(p.last_handshake).getTime() < 180000,
      ).length,
    0,
  )
  return live || overview.value?.peer_online || 0
})

const chartHeight = computed(() => (isMobile.value ? '180px' : '260px'))

async function load() {
  try {
    overview.value = await api.get<Overview>('/overview')
  } catch {
    /* 忽略瞬时错误 */
  }
}

function renderChart() {
  if (!chartEl.value) return
  if (!chart) chart = echarts.init(chartEl.value)
  chart.setOption({
    grid: { left: 46, right: 12, top: 28, bottom: 26 },
    tooltip: {
      trigger: 'axis',
      valueFormatter: (v: number) => formatRate(v),
    },
    legend: { data: ['下载', '上传'], right: 0, top: 0, itemWidth: 12, itemHeight: 8 },
    xAxis: { type: 'category', data: series.value.t, boundaryGap: false, axisLabel: { fontSize: 10 } },
    yAxis: {
      type: 'value',
      axisLabel: { formatter: (v: number) => formatBytes(v) + '/s', fontSize: 10 },
    },
    series: [
      {
        name: '下载',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        data: series.value.rx,
      },
      {
        name: '上传',
        type: 'line',
        smooth: true,
        showSymbol: false,
        areaStyle: { opacity: 0.12 },
        data: series.value.tx,
      },
    ],
  })
}

watch(liveRxRate, () => {
  series.value.t.push(new Date().toLocaleTimeString())
  series.value.rx.push(Math.round(liveRxRate.value))
  series.value.tx.push(Math.round(liveTxRate.value))
  if (series.value.t.length > 60) {
    series.value.t.shift()
    series.value.rx.shift()
    series.value.tx.shift()
  }
  renderChart()
})

/** 一键创建推荐连接：不要求用户理解任何参数 */
async function quickStart() {
  quickStarting.value = true
  try {
    // 连接名称、本机专用地址与服务端口交给后端自动分配，
    // 保证已有连接时不会因为写死的默认值产生端口/网段冲突。
    const created = await api.post<{ name: string }>('/interfaces', {
      mtu: 1420,
      dns: ['223.5.5.5'],
      dns_mode: 'client',
      route_table: 'off',
      enabled: true,
      autostart: true,
    })
    await load()
    await ElMessageBox.alert(
      `已创建连接「${created.name}」。\n\n下一步：到「我的设备」中添加你的手机，然后用手机上的 WireGuard App 扫描二维码即可连回来。`,
      '创建成功',
      { confirmButtonText: '去添加设备' },
    )
    router.push({ name: 'peers' })
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    quickStarting.value = false
  }
}

function handleResize() {
  chart?.resize()
}

onMounted(async () => {
  await load()
  await nextTick()
  renderChart()
  window.addEventListener('resize', handleResize)
  timer = window.setInterval(load, 15000)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
  window.removeEventListener('resize', handleResize)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.fnwg-stat-sub {
  font-size: 14px;
  opacity: 0.6;
}

.fnwg-onboarding {
  margin-bottom: 12px;
  border-color: var(--el-color-primary-light-5);
}

.fnwg-onboarding-title {
  font-size: 16px;
  font-weight: 600;
  margin-bottom: 12px;
}

.fnwg-onboarding-steps {
  display: grid;
  gap: 10px;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
  margin-bottom: 16px;
}

.fnwg-onboarding-step {
  display: flex;
  gap: 10px;
  align-items: flex-start;
}

.fnwg-step-no {
  flex: 0 0 auto;
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: var(--el-color-primary);
  color: #fff;
  font-size: 12px;
  font-weight: 600;
  display: flex;
  align-items: center;
  justify-content: center;
  margin-top: 1px;
}

.fnwg-step-title {
  font-size: 13.5px;
  font-weight: 600;
}

.fnwg-step-desc {
  font-size: 12.5px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
  margin-top: 2px;
}

.fnwg-onboarding-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.fnwg-onboarding-note {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 10px;
  line-height: 1.6;
}
</style>
