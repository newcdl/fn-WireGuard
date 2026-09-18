<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <el-autocomplete
    ref="inputRef"
    v-model="query"
    :fetch-suggestions="fetchHits"
    :placeholder="placeholderText"
    clearable
    class="fnwg-global-search"
    :class="{ 'is-mobile': mobile }"
    @select="onSelect"
    @focus="ensureData"
  >
    <template #prefix><el-icon><Search /></el-icon></template>
    <template #default="{ item }">
      <div class="fnwg-gs-item">
        <el-tag size="small" :type="item.kind === 'iface' ? 'primary' : 'success'" effect="plain">
          {{ item.kindLabel }}
        </el-tag>
        <span class="fnwg-gs-name">{{ item.name }}</span>
        <span class="fnwg-gs-sub">{{ item.sub }}</span>
      </div>
    </template>
  </el-autocomplete>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { Search } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import type { WgInterface, WgPeer } from '@/api/types'

defineProps<{ mobile?: boolean }>()

const router = useRouter()

/** 一条搜索结果：连接或设备 */
type Hit = {
  /** el-autocomplete 要求的唯一值 */
  value: string
  kind: 'iface' | 'peer'
  kindLabel: string
  name: string
  sub: string
  ifaceId: number
  peerId?: number
}

const inputRef = ref()
const query = ref('')
const placeholderText = '搜索连接或设备'

// 数据在首次聚焦时拉取并缓存 30 秒：搜索是偶发操作，
// 没必要在每次挂载时都请求一遍列表，也不能把结果缓存太久而显示已删除的对象。
let ifaces: WgInterface[] = []
let peers: WgPeer[] = []
let loadedAt = 0
let loading = false

async function ensureData(force = false) {
  if (loading) return
  if (!force && Date.now() - loadedAt < 30000 && (ifaces.length || peers.length)) return
  loading = true
  try {
    const [i, p] = await Promise.allSettled([
      api.get<{ items: WgInterface[] }>('/interfaces'),
      api.get<{ items: WgPeer[] }>('/peers'),
    ])
    if (i.status === 'fulfilled') ifaces = i.value.items || []
    if (p.status === 'fulfilled') peers = p.value.items || []
    loadedAt = Date.now()
  } finally {
    loading = false
  }
}

/** 按名称/备注/分组/识别码/所属连接匹配，连接或设备都可能命中 */
function build(kw: string): Hit[] {
  const q = kw.trim().toLowerCase()
  if (!q) return []
  const out: Hit[] = []
  for (const it of ifaces) {
    const hay = `${it.name} ${it.uuid} ${(it.addresses || []).join(' ')}`.toLowerCase()
    if (hay.includes(q)) {
      out.push({
        value: `iface-${it.id}`,
        kind: 'iface',
        kindLabel: '连接',
        name: it.name,
        sub: (it.addresses || []).join(', ') || '未分配地址',
        ifaceId: it.id,
      })
    }
  }
  for (const p of peers) {
    const hay = `${p.name} ${p.remark || ''} ${p.group_tag || ''} ${p.public_key || ''} ${
      p.interface_name || ''
    }`.toLowerCase()
    if (hay.includes(q)) {
      out.push({
        value: `peer-${p.id}`,
        kind: 'peer',
        kindLabel: '设备',
        name: p.name,
        sub: p.interface_name ? `来自「${p.interface_name}」` : '',
        ifaceId: p.interface_id,
        peerId: p.id,
      })
    }
  }
  return out.slice(0, 20)
}

function fetchHits(kw: string, cb: (v: Hit[]) => void) {
  void ensureData().then(() => cb(build(kw)))
}

/** 跳到对应页面并打开详情：连接走 interfaces?edit=，设备走 peers?iface=&edit= */
function onSelect(item: Hit) {
  query.value = ''
  if (item.kind === 'iface') {
    router.push({ name: 'interfaces', query: { edit: String(item.ifaceId) } })
  } else {
    router.push({ name: 'peers', query: { iface: String(item.ifaceId), edit: String(item.peerId) } })
  }
}

function focus() {
  const el = (inputRef.value?.$el as HTMLElement | undefined)?.querySelector('input')
  ;(el as HTMLInputElement | null)?.focus()
}

defineExpose({ focus })
</script>

<style scoped>
.fnwg-global-search {
  width: 200px;
  /* 顶栏空间不足时由搜索框让出宽度（可缩到 120px），
     而不是把右侧的状态文字挤成竖排 */
  flex: 0 1 200px;
  min-width: 120px;
}

.fnwg-global-search.is-mobile {
  width: 100%;
  flex: 1 1 auto;
  min-width: 0;
}

.fnwg-gs-item {
  display: flex;
  align-items: center;
  gap: 8px;
  line-height: 1.6;
}

.fnwg-gs-name {
  font-weight: 500;
}

.fnwg-gs-sub {
  font-size: 12px;
  opacity: 0.6;
  margin-left: auto;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  max-width: 45%;
}
</style>
