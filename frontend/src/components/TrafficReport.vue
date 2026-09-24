<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
      <template #title>
        NAS 每分钟把每台设备的累计流量记一次账，按小时落库。下面的报表据此汇总，
        超出保留期的明细会被自动清理——所以「更早的查不到」是正常的，不是数据丢了。
      </template>
    </el-alert>

    <div class="fnwg-toolbar">
      <el-radio-group v-model="days" :disabled="loading" @change="load">
        <el-radio-button :value="7">近 7 天</el-radio-button>
        <el-radio-button :value="30">近 30 天</el-radio-button>
        <el-radio-button :value="90">近 90 天</el-radio-button>
      </el-radio-group>
      <el-button :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      <el-button :icon="Download" @click="exportCSV">导出 CSV</el-button>
      <span class="fnwg-hint">
        合计 {{ formatBytes(report?.rx_bytes) }} 接收 / {{ formatBytes(report?.tx_bytes) }} 发送
      </span>
    </div>

    <!-- 逐日趋势 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">逐日流量（全部设备）</div>
      <div ref="chartEl" :style="{ height: isMobile ? '200px' : '260px' }" />
      <div v-if="report && !report.rx_bytes && !report.tx_bytes" class="fnwg-hint">
        这个区间还没有流量记录。设备连上并产生流量后，这里会出现曲线。
      </div>
    </div>

    <!-- 按设备 -->
    <!-- 表格 / 卡片视图：由用户决定并记住（切一次，之后一直用这种） -->
    <ViewSwitch v-model="viewMode" />

    <div v-if="isTable" class="fnwg-card">
      <el-table :data="report?.peers || []" v-loading="loading" size="small" empty-text="还没有设备">
        <el-table-column prop="name" label="设备" min-width="120" show-overflow-tooltip />
        <el-table-column prop="interface_name" label="连接" width="100" show-overflow-tooltip />
        <el-table-column label="本月用量" min-width="190">
          <template #default="{ row }">
            <div v-if="row.quota_tx > 0">
              <span :class="{ 'fnwg-over-quota': row.month_tx_bytes >= row.quota_tx }">
                {{ formatBytes(row.month_tx_bytes) }} / {{ formatBytes(row.quota_tx) }}
              </span>
              <el-progress
                :percentage="usagePercent(row)"
                :status="row.month_tx_bytes >= row.quota_tx ? 'exception' : undefined"
                :show-text="false"
                :stroke-width="6"
                style="margin-top: 2px"
              />
            </div>
            <span v-else>{{ formatBytes(row.month_tx_bytes) }} 发送<el-tag size="small" type="info" effect="plain" style="margin-left: 6px">不限</el-tag></span>
          </template>
        </el-table-column>
        <el-table-column label="区间接收" width="110">
          <template #default="{ row }">{{ formatBytes(row.rx_bytes) }}</template>
        </el-table-column>
        <el-table-column label="区间发送" width="110">
          <template #default="{ row }">{{ formatBytes(row.tx_bytes) }}</template>
        </el-table-column>
        <el-table-column label="状态" width="150">
          <template #default="{ row }">
            <el-tag v-if="!row.enabled && row.disabled_reason === 'quota'" size="small" type="danger" effect="plain">
              超量已停用
            </el-tag>
            <el-tag v-else-if="!row.enabled && row.disabled_reason === 'expire'" size="small" type="warning" effect="plain">
              到期已停用
            </el-tag>
            <el-tag v-else-if="!row.enabled" size="small" type="info" effect="plain">已停用</el-tag>
            <span v-else>在用</span>
            <div v-if="row.expire_at" class="fnwg-hint">
              {{ (daysLeft(row.expire_at) ?? 0) > 0 ? `剩 ${daysLeft(row.expire_at)} 天到期` : '已到期' }}
            </div>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 移动端卡片 -->
    <div v-else v-loading="loading">
      <div class="fnwg-card-grid">
      <ItemCard
        v-for="row in report?.peers || []"
        :key="row.peer_id"
        :status="row.enabled ? 'ok' : 'off'"
        :title="row.name"
      >
        <template #extra>
          <el-tag v-if="!row.enabled" size="small" type="info" effect="plain">已停用</el-tag>
        </template>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">连接</span>
          <span class="fnwg-kv-val">{{ row.interface_name }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">本月发送</span>
          <span class="fnwg-kv-val">
            {{ formatBytes(row.month_tx_bytes) }}<template v-if="row.quota_tx > 0"> / {{ formatBytes(row.quota_tx) }}</template>
          </span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">区间接收 / 发送</span>
          <span class="fnwg-kv-val">{{ formatBytes(row.rx_bytes) }} / {{ formatBytes(row.tx_bytes) }}</span>
        </div>
      </ItemCard>
      </div>
      <div v-if="!(report?.peers || []).length" class="fnwg-empty">还没有设备</div>
    </div>

    <!-- 保留策略：与「留多久、占多大地方」放在一起，调完能立刻看到代价 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">明细保留</div>
      <div class="fnwg-hint">
        当前保留 {{ report?.retention_days ?? '-' }} 天 · 已存 {{ report?.hour_rows ?? 0 }} 条小时记录<template
          v-if="report?.oldest"
        >（最早一条：{{ formatTime(report.oldest) }}）</template>
      </div>
      <div v-if="session.isAdmin" class="fnwg-toolbar" style="margin-top: 8px">
        <el-input-number v-model="retention" :min="7" :max="3650" :step="1" controls-position="right" style="width: 140px" />
        <span class="fnwg-hint">天</span>
        <el-button :loading="savingRetention" :disabled="retention === report?.retention_days" @click="saveRetention">
          保存
        </el-button>
        <span class="fnwg-hint">调短会立即清掉更早的明细，调长只影响以后。</span>
      </div>
      <div v-else class="fnwg-hint">仅管理员可以调整保留天数。</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { nextTick, onMounted, onUnmounted, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Download, Refresh } from '@element-plus/icons-vue'
import * as echarts from 'echarts'
import { api, download } from '@/api/client'
import type { TrafficPeerRow, TrafficReport } from '@/api/types'
import ItemCard from '@/components/ItemCard.vue'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useTheme } from '@/composables/useTheme'
import { useSession } from '@/stores/session'
import { daysLeft, formatBytes, formatTime } from '@/utils/format'
import ViewSwitch from '@/components/ViewSwitch.vue'
import { useViewMode } from '@/composables/useViewMode'

// 表格 / 卡片视图：由用户决定并记住
const { mode: viewMode, isTable } = useViewMode('traffic-daily')

const { isMobile } = useBreakpoint()
const { isDark } = useTheme()
const session = useSession()

const days = ref(30)
const report = ref<TrafficReport | null>(null)
const loading = ref(false)
const retention = ref(90)
const savingRetention = ref(false)

const chartEl = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null

async function load() {
  loading.value = true
  try {
    report.value = await api.get<TrafficReport>(`/traffic/report?days=${days.value}`)
    retention.value = report.value.retention_days
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '读取流量报表失败')
  } finally {
    loading.value = false
    await nextTick()
    renderChart()
  }
}

/**
 * 取当前主题下的图表用色。
 *
 * ECharts 的默认配色是按浅色底定的（网格线 #E0E6F1、图例 #333），深色下网格线亮得刺眼。
 * 与总览页的实时流量图同一套做法：从 Element Plus 的 CSS 变量现取，深浅两套自动跟随。
 */
function chartInk() {
  const cs = getComputedStyle(document.documentElement)
  const read = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    text: read('--el-text-color-regular', '#606266'),
    dim: read('--el-text-color-secondary', '#909399'),
    line: read('--el-border-color-lighter', '#ebeef5'),
  }
}

function renderChart() {
  if (!chartEl.value || !report.value) return
  // 容器宽度为 0 时（例如页签尚未显示）ECharts 会画出一块空白画布并记下这个尺寸，
  // 之后再怎么切回来都是空的。宁可这次不画，等可见时的那次调用。
  if (!chartEl.value.clientWidth) return
  if (!chart) chart = echarts.init(chartEl.value)
  const ink = chartInk()
  const daily = report.value.daily
  chart.setOption(
    {
      grid: { left: 58, right: 12, top: 30, bottom: 26 },
      tooltip: { trigger: 'axis', valueFormatter: (v: number) => formatBytes(v) },
      legend: {
        data: ['接收', '发送'],
        right: 0,
        top: 0,
        itemWidth: 12,
        itemHeight: 8,
        textStyle: { color: ink.text },
      },
      xAxis: {
        type: 'category',
        data: daily.map((d) => d.day.slice(5)),
        boundaryGap: false,
        axisLine: { lineStyle: { color: ink.line } },
        axisLabel: { fontSize: 10, color: ink.dim },
      },
      yAxis: {
        type: 'value',
        splitLine: { lineStyle: { color: ink.line } },
        axisLabel: { fontSize: 10, color: ink.dim, formatter: (v: number) => formatBytes(v) },
      },
      series: [
        {
          name: '接收',
          type: 'line',
          smooth: true,
          showSymbol: false,
          areaStyle: { opacity: 0.12 },
          data: daily.map((d) => d.rx_bytes),
        },
        {
          name: '发送',
          type: 'line',
          smooth: true,
          showSymbol: false,
          areaStyle: { opacity: 0.12 },
          data: daily.map((d) => d.tx_bytes),
        },
      ],
    },
    // notMerge：换区间时天数会变，不整体替换的话类目轴会留着上一次的日期，
    // 曲线与横轴就对不上了。
    true,
  )
}

/** 本月发送占额度的百分比（没有额度时返回 0，进度条不显示）。 */
function usagePercent(row: TrafficPeerRow) {
  if (!row.quota_tx) return 0
  return Math.min(100, Math.round((row.month_tx_bytes / row.quota_tx) * 100))
}

/**
 * 导出 CSV。
 *
 * 用浏览器直接下载而不是先取回内容再在前端拼文件：区间大时明细有几十万行，
 * 走 fetch 会先整个读进内存再复制一遍，白占一份内存。
 */
function exportCSV() {
  download(`/traffic/export?days=${days.value}`)
}

async function saveRetention() {
  savingRetention.value = true
  try {
    const res = await api.put<{ retention_days: number }>('/traffic/retention', { days: retention.value })
    ElMessage.success(`已把明细保留期改为 ${res.retention_days} 天`)
    await load()
  } catch (e) {
    ElMessage.error(e instanceof Error ? e.message : '保存失败')
  } finally {
    savingRetention.value = false
  }
}

function handleResize() {
  chart?.resize()
}

// 切换外观后重画：图表用色是渲染时从 CSS 变量取的，不重画就还留着旧主题的颜色。
watch(isDark, () => nextTick(renderChart))

onMounted(async () => {
  await load()
  window.addEventListener('resize', handleResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', handleResize)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.fnwg-over-quota {
  color: var(--el-color-danger);
}
</style>
