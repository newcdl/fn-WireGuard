<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
  内网资产台账：把拓扑图「当下看到什么」变成「家里长期有哪些设备」。
  采集跟随巡检计划（不额外加定时器）；新设备会写审计与日志，界面上打「新设备」标记。
-->
<template>
  <div class="fnwg-card">
    <div class="fnwg-card-head">
      <div>
        <strong>内网资产</strong>
        <span class="fnwg-card-desc">跟着每次巡检记录内网设备：首次出现、最近出现与出现天数。新设备会标记出来，确认后可不再提醒。</span>
      </div>
      <div class="fnwg-toolbar">
        <el-radio-group v-model="filter" size="small">
          <el-radio-button value="all">全部</el-radio-button>
          <el-radio-button value="new">新设备</el-radio-button>
          <el-radio-button value="stale">久未出现</el-radio-button>
        </el-radio-group>
        <ViewSwitch v-model="viewMode" />
        <el-button size="small" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <div v-if="!rows.length" class="fnwg-hint">
      台账还是空的：它会跟着巡检记录（可在「配置漂移巡检」里设成每天或每周执行一次）。
    </div>

    <!-- 表格视图（原来只有这一种） -->
    <el-table v-else-if="isTable" :data="rows" size="small" empty-text="没有符合条件的设备">
      <el-table-column label="名称 / 地址" min-width="180">
        <template #default="{ row }">
          <div>{{ row.name || row.ip }}</div>
          <div class="fnwg-mono fnwg-asset-sub">{{ row.name ? row.ip : '未登记名称' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="MAC" width="150">
        <template #default="{ row }">{{ row.mac || '未知' }}</template>
      </el-table-column>
      <el-table-column label="出现情况" min-width="200">
        <template #default="{ row }">
          <div>首次 {{ day(row.first_seen) }} · 最近 {{ day(row.last_seen) }}</div>
          <div class="fnwg-asset-sub">共 {{ row.seen_days }} 天出现过</div>
        </template>
      </el-table-column>
      <el-table-column label="状态" width="120">
        <template #default="{ row }">
          <el-tag v-if="isNew(row)" size="small" type="warning" effect="plain">新设备</el-tag>
          <span v-else-if="row.known" class="fnwg-asset-sub">已知</span>
          <span v-else class="fnwg-asset-sub">—</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" width="120">
        <template #default="{ row }">
          <el-button v-if="isNew(row)" size="small" @click="mark(row, true)">标为已知</el-button>
          <el-button v-else-if="row.known" size="small" text @click="mark(row, false)">取消已知</el-button>
        </template>
      </el-table-column>
    </el-table>

    <!-- 卡片视图：与表格显示同样的字段；一条一块，确认新设备时不用左右看 -->
    <div v-else v-loading="loading">
      <div class="fnwg-card-grid">
      <ItemCard
        v-for="row in rows"
        :key="row.ip"
        :title="row.name || row.ip"
        :status="isNew(row) ? 'warn' : row.known ? 'ok' : 'off'"
      >
        <template #extra>
          <el-tag v-if="isNew(row)" size="small" type="warning" effect="plain">新设备</el-tag>
          <span v-else-if="row.known" class="fnwg-asset-sub">已知</span>
          <span v-else class="fnwg-asset-sub">—</span>
        </template>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">地址</span>
          <span class="fnwg-kv-val fnwg-mono">{{ row.name ? row.ip : '未登记名称' }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">MAC</span>
          <span class="fnwg-kv-val fnwg-mono">{{ row.mac || '未知' }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">出现情况</span>
          <span class="fnwg-kv-val">
            首次 {{ day(row.first_seen) }} · 最近 {{ day(row.last_seen) }}，共 {{ row.seen_days }} 天出现过
          </span>
        </div>
        <template #actions>
          <el-button v-if="isNew(row)" size="small" @click="mark(row, true)">标为已知</el-button>
          <el-button v-else-if="row.known" size="small" text @click="mark(row, false)">取消已知</el-button>
        </template>
      </ItemCard>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { Refresh } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import ItemCard from '@/components/ItemCard.vue'
import ViewSwitch from '@/components/ViewSwitch.vue'
import { useViewMode } from '@/composables/useViewMode'

interface Asset {
  ip: string
  mac?: string
  name?: string
  kind?: string
  first_seen: string
  last_seen: string
  seen_days: number
  known?: boolean
}

const assets = ref<Asset[]>([])
const loading = ref(false)
// 表格 / 卡片视图：由用户决定并记住
const { mode: viewMode, isTable } = useViewMode('assets')

const filter = ref<'all' | 'new' | 'stale'>('all')

const STALE_DAYS = 7

function daysSince(ts: string): number {
  const t = new Date(ts).getTime()
  return Number.isNaN(t) ? 0 : (Date.now() - t) / 86400000
}

/** 「新设备」= 首次出现距今 3 天内且用户还没确认过。 */
function isNew(a: Asset): boolean {
  return !a.known && daysSince(a.first_seen) <= 3
}

const rows = computed(() => {
  if (filter.value === 'new') return assets.value.filter(isNew)
  if (filter.value === 'stale') return assets.value.filter((a) => daysSince(a.last_seen) >= STALE_DAYS)
  return assets.value
})

function day(ts: string): string {
  const d = new Date(ts)
  if (Number.isNaN(d.getTime())) return '—'
  return `${d.getMonth() + 1}/${d.getDate()}`
}

async function load(): Promise<void> {
  loading.value = true
  try {
    assets.value = (await api.get<Asset[]>('/assets')) || []
  } catch (e) {
    ElMessage.error((e as Error)?.message || '读取台账失败')
  } finally {
    loading.value = false
  }
}

async function mark(row: Asset, known: boolean): Promise<void> {
  try {
    await api.post('/assets/known', { ip: row.ip, known })
    ElMessage.success(known ? '已标为已知' : '已取消已知')
    await load()
  } catch (e) {
    ElMessage.error((e as Error)?.message || '保存失败')
  }
}

onMounted(load)
</script>

<style scoped>
.fnwg-asset-sub {
  font-size: 11.5px;
  color: var(--el-text-color-secondary);
}
</style>
