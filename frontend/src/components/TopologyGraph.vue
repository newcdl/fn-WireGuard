<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div class="fnwg-card fnwg-topo">
    <div class="fnwg-card-head">
      <div>
        <strong>网络拓扑</strong>
        <span class="fnwg-card-desc">
          以本机 NAS 为中心：左侧是它所在的内网与内网里的设备，右侧是连上隧道的设备与另一台 NAS。
          拖动空白处平移、滚轮缩放、直接拖节点可换位置（会记住）；单击看整条链路，双击跳到对应页面，右键有更多操作。
        </span>
      </div>
      <div class="fnwg-topo-actions">
        <el-radio-group v-model="mode" size="small" @change="onModeChange">
          <el-radio-button value="radial">放射</el-radio-button>
          <el-radio-button value="circular">环状</el-radio-button>
          <el-radio-button value="force">自由</el-radio-button>
        </el-radio-group>
        <el-button-group>
          <el-button size="small" :icon="ZoomIn" title="放大" @click="zoomBy(1 / 1.3)" />
          <el-button size="small" :icon="ZoomOut" title="缩小" @click="zoomBy(1.3)" />
          <el-button size="small" :icon="Aim" title="适应窗口" @click="fitView" />
        </el-button-group>
        <el-button size="small" :icon="Picture" title="导出图片" @click="exportPNG">导出</el-button>
        <el-button size="small" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <div v-if="!graph" class="fnwg-hint">正在读取拓扑…</div>

    <template v-else>
      <div class="fnwg-topo-wrap">
        <div ref="chartEl" class="fnwg-topo-canvas" :style="{ height: canvasHeight }"></div>

        <!-- 缩略图：设备多起来、又缩放平移过之后，用来看「现在看的是哪一块」，也可以直接点它跳过去 -->
        <div class="fnwg-topo-mini" :title="'全览：点击或拖动可快速定位'">
          <svg :viewBox="`0 0 ${mini.w} ${mini.h}`" @mousedown="onMiniJump" @mousemove="onMiniDrag" @mouseup="miniDragging = false">
            <line v-for="(l, i) in mini.lines" :key="i" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="fnwg-topo-mini-line" />
            <circle v-for="n in mini.nodes" :key="n.id" :cx="n.cx" :cy="n.cy" r="2.6" :class="`k-${n.kind}`" />
            <rect :x="mini.view.x" :y="mini.view.y" :width="mini.view.w" :height="mini.view.h" class="fnwg-topo-mini-view" />
          </svg>
          <span>全览</span>
        </div>

        <!-- 右键菜单：用页面自己的样式，和 Element Plus 观感一致 -->
        <div v-if="menu" class="fnwg-topo-menu" :style="{ left: menu.x + 'px', top: menu.y + 'px' }">
          <div class="fnwg-topo-menu-head">{{ menu.label }}</div>
          <div v-for="(it, i) in menu.items" :key="i" class="fnwg-topo-menu-item" @click="runMenu(it)">
            <el-icon><component :is="it.icon" /></el-icon>{{ it.text }}
          </div>
        </div>
      </div>

      <div class="fnwg-topo-legend">
        <span v-for="l in legend" :key="l.text"><i :style="{ background: l.color }" />{{ l.text }}</span>
        <span><i class="fnwg-topo-legend-line flow" />箭头流动 = 正在传数据（越快越急）</span>
        <span><i class="fnwg-topo-legend-line off" />虚线 = 已停用 / 未连接</span>
      </div>
      <div class="fnwg-topo-notes">
        <div v-if="selected" class="fnwg-hint">
          · 正在看「{{ selectedLabel }}」这条链路：相关的连线与设备高亮，点空白处取消。
          <a class="fnwg-topo-link" @click="clearSelection">取消高亮</a>
        </div>
        <div class="fnwg-hint">· 节点图标按名字判断设备类型（路由 / 电脑 / 手机 / 打印机…）：给设备在「内网域名」里起个名字，图标会更准。</div>
        <div v-for="(n, i) in graph.notes" :key="i" class="fnwg-hint">· {{ n }}</div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import * as echarts from 'echarts'
import { ElMessage } from 'element-plus'
import { Aim, CopyDocument, Link, Picture, Refresh, Setting, View, ZoomIn, ZoomOut } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import type { TopologyGraph, TopologyNode } from '@/api/types'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { formatRate, formatTime } from '@/utils/format'

const { isMobile } = useBreakpoint()
const router = useRouter()

const graph = ref<TopologyGraph | null>(null)
const loading = ref(false)
const chartEl = ref<HTMLElement | null>(null)
let chart: echarts.ECharts | null = null

/** 布局方式：放射（默认）/ 环状 / 自由（力导向松弛）。 */
type Mode = 'radial' | 'circular' | 'force'
const mode = ref<Mode>('radial')
/** 节点位置：用户拖过之后就以这里为准（按节点 id 记住，刷新页面还在原处）。 */
const positions = ref<Record<string, { x: number; y: number }>>({})
/** 当前高亮的节点（点一下看整条链路）。 */
const selected = ref<string | null>(null)
/** 右键菜单（屏幕坐标 + 该节点可做的事）。 */
const menu = ref<{ x: number; y: number; label: string; items: MenuItem[] } | null>(null)
/** 缩放窗口（百分比）。自己记着，重画后不会跳回全览。 */
const zoom = ref({ x: { start: 0, end: 100 }, y: { start: 0, end: 100 } })

interface MenuItem {
  text: string
  icon: object
  act: () => void
}

const STORE_KEY = 'fnwg.topology.view'

const atLabel = computed(() => (graph.value ? `更新于 ${formatTime(graph.value.at)}` : ''))
const canvasHeight = computed(() => (isMobile.value ? '440px' : '560px'))
const selectedLabel = computed(() => graph.value?.nodes.find((n) => n.id === selected.value)?.label || '')

const KIND_COLOR: Record<string, string> = {
  nas: '#409eff',
  lan: '#14b8a6',
  'site-lan': '#14b8a6',
  host: '#22c55e',
  device: '#409eff',
  site: '#8b5cf6',
  foreign: '#f59e0b',
}
const STATUS_COLOR: Record<string, string> = { ok: '#22c55e', warn: '#f59e0b', off: '#94a3b8' }
const STATUS_DRIVEN = new Set(['host', 'device'])

/**
 * 节点图标：简单的几何图形（单一颜色，由节点的状态色填充）。
 *
 * 为什么用内联 SVG 而不是图标字体/图片文件：图标要跟着状态变色、要能进导出的 PNG，
 * 内联 SVG 转 data URI 后既能按节点着色，也不额外增加任何依赖或字体加载。
 */
const ICON_PATHS: Record<string, string> = {
  server:
    '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/>' +
    '<rect x="6.5" y="6.6" width="3" height="1.8" rx="0.9" fill-opacity="0.5"/><rect x="6.5" y="15.6" width="3" height="1.8" rx="0.9" fill-opacity="0.5"/>',
  network:
    '<circle cx="12" cy="5" r="2.6"/><circle cx="5" cy="18.5" r="2.6"/><circle cx="19" cy="18.5" r="2.6"/>' +
    '<path d="M12 7.6v3.9M5 15.9v-2.4h14v2.4" fill="none" stroke-width="1.7"/>',
  router:
    '<rect x="3" y="13" width="18" height="7" rx="2"/><path d="M8 13V8M16 13V8" stroke-width="1.7"/>' +
    '<path d="M9.4 8.2a3.8 3.8 0 0 1 5.2 0" fill="none" stroke-width="1.7"/>',
  switch:
    '<rect x="2.5" y="7" width="19" height="10" rx="2"/><rect x="5" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>' +
    '<rect x="8.6" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/><rect x="12.2" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>' +
    '<rect x="15.8" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>',
  laptop:
    '<rect x="4" y="5" width="16" height="10" rx="1.5"/><rect x="6" y="7" width="12" height="6" rx="1" fill-opacity="0.35"/>' +
    '<path d="M2.5 17.5h19l-1.2 2.3a1 1 0 0 1-.9.5H4.6a1 1 0 0 1-.9-.5z"/>',
  monitor:
    '<rect x="3" y="3.5" width="12" height="10" rx="1.5"/><rect x="4.6" y="5.1" width="8.8" height="6.8" rx="1" fill-opacity="0.35"/>' +
    '<rect x="16.8" y="3.5" width="4.4" height="17" rx="1.5" fill-opacity="0.6"/><rect x="3" y="15.4" width="12" height="1.8" rx="0.9"/>',
  phone:
    '<rect x="7" y="2.5" width="10" height="19" rx="2.5"/><rect x="9" y="5" width="6" height="12" rx="1" fill-opacity="0.35"/>' +
    '<circle cx="12" cy="19.2" r="1" fill-opacity="0.5"/>',
  printer:
    '<rect x="6.5" y="3" width="11" height="5" rx="1" fill-opacity="0.55"/><rect x="3" y="9" width="18" height="8" rx="2"/>' +
    '<rect x="6" y="14" width="12" height="7" rx="1.5" fill-opacity="0.4"/>',
  tv:
    '<rect x="2.5" y="5" width="19" height="12.5" rx="2"/><rect x="4.5" y="7" width="15" height="8.5" rx="1" fill-opacity="0.35"/>' +
    '<path d="M9.2 20h5.6l-.8-2.5H10z"/>',
  camera:
    '<rect x="2.5" y="6.5" width="14" height="11" rx="2.5"/><circle cx="9.5" cy="12" r="3" fill-opacity="0.35"/>' +
    '<path d="M17.2 12l4.3-2.8v5.6z"/>',
  speaker:
    '<rect x="5" y="2.5" width="14" height="19" rx="3"/><circle cx="12" cy="8" r="3" fill-opacity="0.35"/>' +
    '<circle cx="12" cy="16.6" r="2.2" fill-opacity="0.35"/>',
  warning:
    '<path d="M12 3.2l9.2 16.2a1.6 1.6 0 0 1-1.4 2.4H4.2A1.6 1.6 0 0 1 2.8 19.4z"/>' +
    '<rect x="11" y="9.4" width="2" height="6" rx="1" fill-opacity="0.45"/><circle cx="12" cy="18" r="1.1" fill-opacity="0.45"/>',
}

const iconCache = new Map<string, string>()

/** 把图标转成按颜色着色的 data URI（同色同图只生成一次）。 */
function iconURI(name: string, color: string): string {
  const key = name + color
  const hit = iconCache.get(key)
  if (hit) return hit
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="${color}" stroke="${color}">` +
    `${ICON_PATHS[name] || ICON_PATHS.monitor}</svg>`
  const uri = 'data:image/svg+xml,' + encodeURIComponent(svg)
  iconCache.set(key, uri)
  return uri
}

/** 名称关键词 → 图标：用户给设备起过名字，图标就能比默认的更准。 */
const NAME_RULES: [RegExp, string][] = [
  [/nas|存储|群晖|威联通|synology|qnap|极空间|绿联|服务器|server/i, 'server'],
  [/路由|router|网关|gateway|无线|wifi|mesh/i, 'router'],
  [/交换机|switch|hub/i, 'switch'],
  [/打印|printer|扫描/i, 'printer'],
  [/手机|phone|iphone|android|安卓|redmi|oppo|vivo|荣耀|一加/i, 'phone'],
  [/平板|pad|tablet|ipad/i, 'phone'],
  [/电脑|pc|mac|book|笔记本|台式|desktop|thinkpad/i, 'laptop'],
  [/电视|tv|盒子|机顶盒|投影/i, 'tv'],
  [/摄像|camera|监控|nvr|ipc/i, 'camera'],
  [/音响|音箱|speaker|homepod|echo|小爱|天猫/i, 'speaker'],
]

/** 决定一个节点用哪个图标：先看种类，再看名称关键词，最后给默认图标。 */
function iconOf(n: TopologyNode): string {
  if (n.kind === 'nas' || n.kind === 'site') return 'server'
  if (n.kind === 'lan' || n.kind === 'site-lan') return 'network'
  if (n.kind === 'foreign') return 'warning'
  const text = `${n.label} ${n.sublabel || ''}`
  for (const [re, icon] of NAME_RULES) if (re.test(text)) return icon
  return 'monitor'
}

const TYPE_LABEL: Record<string, string> = {
  server: 'NAS / 服务器',
  network: '网段',
  router: '路由器 / 无线',
  switch: '交换机',
  laptop: '电脑（笔记本）',
  monitor: '电脑（默认图标）',
  phone: '手机 / 平板',
  printer: '打印机',
  tv: '电视 / 盒子',
  camera: '摄像头',
  speaker: '音箱',
  warning: '疑似残留网卡',
}

const legend = computed(() => [
  { text: '本机 NAS', color: KIND_COLOR.nas },
  { text: '内网网段', color: KIND_COLOR.lan },
  { text: '内网设备（绿=可达、橙=待确认、灰=未知）', color: STATUS_COLOR.ok },
  { text: '隧道设备', color: KIND_COLOR.device },
  { text: '另一台 NAS 及其内网', color: KIND_COLOR.site },
  { text: '疑似残留网卡', color: KIND_COLOR.foreign },
])

// ------------------------------------------------------------------ 位置计算

interface Placed {
  node: TopologyNode
  x: number
  y: number
  w: number
  h: number
  color: string
}

const rad = (deg: number) => (deg * Math.PI) / 180

/** 卡片宽度按文字长度估：中文按 13px、西文按 7.2px 算，够准且不会为它引入测量逻辑。 */
function textWidth(s: string): number {
  let w = 0
  for (const ch of s) w += /[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]/.test(ch) ? 13 : 7.2
  return w
}

/** 节点卡片的尺寸：两行字（名称 + 地址）撑起来的固定卡片，比纯圆圈好读。 */
function sizeOf(n: TopologyNode): [number, number] {
  // 估宽留足余量（不同字体的实际宽度会有出入，估窄了文字会溢出到卡片外面）
  const widest = Math.max(...(n.sublabel ? [n.label, n.sublabel] : [n.label]).map(textWidth))
  // 高度也留余量：两行字（名称 + 地址）在内侧垂直居中，卡矮了第二行会被切掉一截
  if (n.kind === 'nas') return [Math.min(260, Math.max(170, widest * 1.08 + 56)), 60]
  return [Math.min(isMobile.value ? 200 : 240, Math.max(isMobile.value ? 118 : 128, widest * 1.08 + 44)), n.sublabel ? 52 : 34]
}

function colorOf(n: TopologyNode): string {
  return STATUS_DRIVEN.has(n.kind) ? STATUS_COLOR[n.status] || STATUS_COLOR.off : KIND_COLOR[n.kind] || STATUS_COLOR.off
}

/**
 * 算出每个节点的坐标。
 *
 * 三种布局都由我们自己算（不用力导向库）：位置**可复现**是硬要求 ——
 * 同一个网络每次打开方位一致，用户才能靠位置认东西；「自由」布局也从放射布局出发松弛，
 * 因此同样输入必然得到同样结果。
 *
 * 左右分家的约定不变：内网在左半圆、隧道与对端在右半圆（两类东西语义不同，
 * 混成一圈会让人以为「内网设备」和「连上来的设备」是一回事）。
 */
function computePositions(g: TopologyGraph, m: Mode): Record<string, { x: number; y: number }> {
  const narrow = isMobile.value
  const R1 = narrow ? 190 : 250
  const R2 = narrow ? 320 : 470
  const out: Record<string, { x: number; y: number }> = {}
  const nas = g.nodes.find((n) => n.kind === 'nas')
  if (nas) out[nas.id] = { x: 0, y: 0 }

  const childrenOf = (id: string) =>
    g.links.filter((l) => l.from === id).map((l) => g.nodes.find((n) => n.id === l.to)).filter(Boolean) as TopologyNode[]
  const lans = g.nodes.filter((n) => n.kind === 'lan')
  const sites = g.nodes.filter((n) => n.kind === 'site')
  const devices = g.nodes.filter((n) => n.kind === 'device')
  const foreign = g.nodes.filter((n) => n.kind === 'foreign')

  const placeArc = (list: TopologyNode[], center: number, spread: number, radius: number) => {
    list.forEach((n, i) => {
      const t = list.length === 1 ? 0.5 : i / (list.length - 1)
      const a = rad(center - spread / 2 + spread * t)
      out[n.id] = { x: radius * Math.cos(a), y: radius * Math.sin(a) }
    })
  }
  const rightSide = [...sites, ...devices]

  if (m === 'circular') {
    // 环状：中心节点一圈均匀铺开，设备再往外一圈
    const ring1 = [...lans, ...rightSide, ...foreign]
    ring1.forEach((n, i) => {
      const a = rad((360 / Math.max(1, ring1.length)) * i - 90)
      out[n.id] = { x: R1 * Math.cos(a), y: R1 * Math.sin(a) }
    })
    for (const parent of [...lans, ...sites]) {
      const kids = childrenOf(parent.id)
      const at = out[parent.id]
      if (!kids.length || !at) continue
      const base = Math.atan2(at.y, at.x)
      const spread = rad(Math.min(150, Math.max(40, kids.length * 18)))
      kids.forEach((n, i) => {
        const t = kids.length === 1 ? 0.5 : i / (kids.length - 1)
        const a = base - spread / 2 + spread * t
        out[n.id] = { x: R2 * Math.cos(a), y: R2 * Math.sin(a) }
      })
    }
  } else {
    // 放射（默认）与自由的初始状态：左半圆内网、右半圆隧道
    placeArc(lans, 180, 100, R1)
    placeArc(rightSide, 0, Math.min(150, Math.max(60, rightSide.length * 20)), R1)
    placeArc(foreign, 270, 60, R1)
    for (const parent of [...lans, ...sites]) {
      const kids = childrenOf(parent.id)
      const at = out[parent.id]
      if (!kids.length || !at) continue
      const base = Math.atan2(at.y, at.x)
      const spread = Math.min(140, Math.max(30, kids.length * 16))
      const radius = R2 + Math.max(0, kids.length - 5) * (narrow ? 10 : 16)
      kids.forEach((n, i) => {
        const t = kids.length === 1 ? 0.5 : i / (kids.length - 1)
        const a = rad(base * (180 / Math.PI) - spread / 2 + spread * t)
        out[n.id] = { x: radius * Math.cos(a), y: radius * Math.sin(a) }
      })
    }
  }

  if (m === 'force') return relax(g, out)
  return out
}

/**
 * 「自由」布局：从放射布局出发做力导向松弛。
 *
 * 自己写而不是引 d3-force：只有几十个节点，几十行就够；更重要的是**确定性** ——
 * 从固定初值出发、固定迭代次数，同样的网络必然收敛到同样的形状，不会每次开图都换一个样子。
 * 中心节点固定不动（它必须是图的心脏）。
 */
function relax(g: TopologyGraph, init: Record<string, { x: number; y: number }>): Record<string, { x: number; y: number }> {
  const ids = Object.keys(init)
  const pos = ids.map((id) => ({ id, ...init[id] }))
  const idx = new Map(ids.map((id, i) => [id, i]))
  const nas = g.nodes.find((n) => n.kind === 'nas')
  const links = g.links
    .map((l) => ({ a: idx.get(l.from), b: idx.get(l.to) }))
    .filter((l) => l.a !== undefined && l.b !== undefined) as { a: number; b: number }[]
  const level = (i: number) => {
    const n = g.nodes.find((x) => x.id === ids[i])
    return n?.kind === 'nas' ? 0 : n?.kind === 'lan' || n?.kind === 'site' ? 1 : 2
  }
  const depths = ids.map((_, i) => level(i))

  for (let step = 0; step < 320; step++) {
    const cool = 1 - step / 320
    // 斥力：所有节点互相推开（同类中的远端节点推得弱一些，避免整图炸开）
    for (let i = 0; i < pos.length; i++) {
      for (let j = i + 1; j < pos.length; j++) {
        let dx = pos[j].x - pos[i].x
        let dy = pos[j].y - pos[i].y
        let d2 = dx * dx + dy * dy
        if (d2 < 1) {
          dx = (i - j) * 0.01 + 0.1
          dy = 0.1
          d2 = 1
        }
        const d = Math.sqrt(d2)
        const rep = (90000 / d2) * cool
        const ux = dx / d
        const uy = dy / d
        pos[i].x -= ux * rep
        pos[i].y -= uy * rep
        pos[j].x += ux * rep
        pos[j].y += uy * rep
      }
    }
    // 引力：连线把两端拉近；另外把「同一层的节点」往各自该在的半径上拉，保持左右分家的可读性
    for (const l of links) {
      const dx = pos[l.b].x - pos[l.a].x
      const dy = pos[l.b].y - pos[l.a].y
      const d = Math.sqrt(dx * dx + dy * dy) || 1
      const pull = (d - 200) * 0.045 * cool
      const ux = dx / d
      const uy = dy / d
      pos[l.a].x += ux * pull
      pos[l.a].y += uy * pull
      pos[l.b].x -= ux * pull
      pos[l.b].y -= uy * pull
    }
    for (let i = 0; i < pos.length; i++) {
      if (depths[i] === 0) continue
      const want = depths[i] === 1 ? 260 : 470
      const d = Math.sqrt(pos[i].x * pos[i].x + pos[i].y * pos[i].y) || 1
      const k = ((want - d) / d) * 0.12 * cool
      pos[i].x += pos[i].x * k
      pos[i].y += pos[i].y * k
    }
    if (nas) {
      const i = idx.get(nas.id)!
      pos[i].x = 0
      pos[i].y = 0
    }
  }
  const out: Record<string, { x: number; y: number }> = {}
  for (const p of pos) out[p.id] = { x: Math.round(p.x), y: Math.round(p.y) }
  return out
}

/** 每次要画的节点与连线（把「布局」「用户拖动」「高亮」三件事合到一起）。 */
const scene = computed(() => {
  const g = graph.value
  if (!g) return null
  const base = computePositions(g, mode.value)
  const placed: Placed[] = []
  for (const n of g.nodes) {
    const p = positions.value[n.id] || base[n.id]
    if (!p) continue
    const [w, h] = sizeOf(n)
    placed.push({ node: n, x: p.x, y: p.y, w, h, color: colorOf(n) })
  }
  const byId = new Map(placed.map((p) => [p.node.id, p]))
  const neighbors = new Set<string>()
  const edges: { from: string; to: string; status: string; rate: number; label?: string }[] = []
  for (const l of g.links) {
    if (!byId.has(l.from) || !byId.has(l.to)) continue
    edges.push({ from: l.from, to: l.to, status: l.status, rate: l.rate || 0, label: l.label })
  }
  if (selected.value) {
    neighbors.add(selected.value)
    for (const e of edges) {
      if (e.from === selected.value) neighbors.add(e.to)
      if (e.to === selected.value) neighbors.add(e.from)
    }
  }
  const xs = placed.map((p) => p.x)
  const ys = placed.map((p) => p.y)
  const pad = isMobile.value ? 200 : 240
  const bounds: [number, number, number, number] = [
    Math.min(...xs) - pad,
    Math.max(...xs) + pad,
    Math.min(...ys) - (isMobile.value ? 110 : 130),
    Math.max(...ys) + (isMobile.value ? 110 : 130),
  ]
  return { placed, byId, edges, neighbors, bounds }
})

// ------------------------------------------------------------------ 画图

function chartInk() {
  const cs = getComputedStyle(document.documentElement)
  const read = (name: string, fallback: string) => cs.getPropertyValue(name).trim() || fallback
  return {
    text: read('--el-text-color-primary', '#303133'),
    dim: read('--el-text-color-secondary', '#909399'),
    line: read('--el-border-color', '#dcdfe6'),
    card: read('--fnwg-card', '#ffffff'),
  }
}

function escapeHTML(s: string): string {
  return s.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c] as string)
}

/** 悬停卡：节点给完整信息；连线给「谁连谁 + 当前速率」。 */
function tipHTML(data: any): string {
  const ink = chartInk()
  const row = (k: string, v: string) =>
    `<div style="display:flex;gap:8px;margin-top:4px"><span style="flex:0 0 66px;color:${ink.dim}">${k}</span>` +
    `<span style="flex:1;word-break:break-word">${escapeHTML(v)}</span></div>`
  if (data.__edge) {
    const e = data.__edge
    return (
      `<div style="font-size:13px"><strong>${escapeHTML(e.fromLabel)} → ${escapeHTML(e.toLabel)}</strong></div>` +
      row('连接', e.label || '内网') +
      row('状态', e.status === 'ok' ? '正常' : e.status === 'warn' ? '待确认 / 离线' : '已停用') +
      row('速率', e.rate > 0 ? formatRate(e.rate) : '当前没有流量')
    )
  }
  const n = data.__node as TopologyNode
  return (
    `<div style="font-size:13px"><strong>${escapeHTML(n.label)}</strong>` +
    (n.sublabel ? `<span style="color:${ink.dim}">　${escapeHTML(n.sublabel)}</span>` : '') +
    '</div>' +
    row('类型', TYPE_LABEL[iconOf(n)] + (['host', 'device'].includes(n.kind) ? '（按名称判断）' : '')) +
    n.details.map((d) => row(d.key, d.value)).join('') +
    `<div style="margin-top:6px;color:${ink.dim};font-size:11.5px">单击看链路 · 双击跳转 · 右键更多 · 可拖动</div>`
  )
}

function buildOption(): echarts.EChartsOption {
  const ink = chartInk()
  const s = scene.value!
  const dim = (id: string) => selected.value !== null && !s.neighbors.has(id)

  const nodes = s.placed.map((p) => {
    const n = p.node
    const isNas = n.kind === 'nas'
    const faded = dim(n.id)
    return {
      name: n.id,
      x: p.x,
      y: p.y,
      value: [p.x, p.y],
      symbol: 'roundRect',
      symbolSize: [p.w, p.h],
      itemStyle: {
        color: isNas ? p.color : ink.card,
        borderColor: p.color,
        borderWidth: isNas ? 2.5 : 1.5,
        borderType: n.kind === 'foreign' ? 'dashed' : 'solid',
        shadowBlur: faded ? 0 : 8,
        shadowColor: 'rgba(15, 23, 42, 0.10)',
        opacity: faded ? 0.25 : 1,
      },
      label: {
        show: true,
        position: 'inside',
        align: 'left',
        padding: [0, 0, 0, isNas ? 16 : 13],
        formatter: n.sublabel ? `{ico|}{a|${n.label}}\n{pad|}{b|${n.sublabel}}` : `{ico|}{a|${n.label}}`,
        rich: {
          ico: {
            width: 18,
            height: 18,
            align: 'center',
            verticalAlign: 'middle',
            backgroundColor: { image: iconURI(iconOf(n), isNas ? '#ffffff' : p.color) } as any,
          },
          pad: { width: 18, height: 14 },
          a: { color: isNas ? '#ffffff' : ink.text, fontSize: 12.5, fontWeight: isNas ? 'bold' : 'normal', lineHeight: 16 },
          b: { color: isNas ? 'rgba(255,255,255,0.85)' : ink.dim, fontSize: 11, lineHeight: 14 },
        },
        opacity: faded ? 0.3 : 1,
      },
      __node: n,
    }
  })

  // 连线按速率分档到不同系列：effect.period 只能按系列设，分档后「越快越急」才看得出来
  const buckets: { key: number; color: string; period: number; width: number; symbol: string }[] = [
    { key: 0, color: '#409eff', period: 1.1, width: 2.4, symbol: 'arrow' },
    { key: 1, color: '#409eff', period: 2, width: 2, symbol: 'arrow' },
    { key: 2, color: '#409eff', period: 3.2, width: 1.8, symbol: 'arrow' },
    { key: 3, color: '#f59e0b', period: 5, width: 1.8, symbol: 'arrow' },
    { key: 4, color: ink.line, period: 9, width: 1.4, symbol: 'circle' },
  ]
  const bucketOf = (e: { status: string; rate: number }) => {
    if (e.status !== 'ok' && e.status !== 'warn') return 5
    if (e.rate >= 1024 * 1024) return 0
    if (e.rate >= 64 * 1024) return 1
    if (e.rate > 0) return 2
    if (e.status === 'warn') return 3
    return 4
  }
  // draggable 关掉：拖动由我们自己接管（见 bindChartEvents），位置要能被记住与保存
  const nodSeries: any = { type: 'graph', coordinateSystem: 'cartesian2d', layout: 'none', draggable: false, roam: false, z: 5, data: nodes, edges: [] }
  const series: any[] = [nodSeries]
  for (const b of buckets) {
    const data = s.edges
      .filter((e) => bucketOf(e) === b.key)
      .map((e) => {
        const a = s.byId.get(e.from)!
        const c = s.byId.get(e.to)!
        const faded = selected.value !== null && !(s.neighbors.has(e.from) && s.neighbors.has(e.to))
        return {
          coords: [
            [a.x, a.y],
            [c.x, c.y],
          ],
          lineStyle: { opacity: faded ? 0.15 : 0.8 },
          __edge: { ...e, fromLabel: a.node.label, toLabel: c.node.label },
        }
      })
    if (!data.length) continue
    series.push({
      type: 'lines',
      coordinateSystem: 'cartesian2d',
      polyline: false,
      z: 2,
      silent: false,
      data,
      lineStyle: { color: b.color, width: b.width, opacity: 0.8, curveness: 0, type: b.key >= 4 ? 'dashed' : 'solid' },
      // 只有「在传数据」的线才跑动画：空闲线也动会让人误以为在传输，而且是卡顿主因之一
      effect: b.key <= 2 ? { show: true, period: b.period, trailLength: 0.3, symbol: b.symbol, symbolSize: 6, color: b.color } : undefined,
    })
  }
  const offEdges = s.edges
    .filter((e) => bucketOf(e) === 5)
    .map((e) => {
      const a = s.byId.get(e.from)!
      const c = s.byId.get(e.to)!
      return {
        coords: [
          [a.x, a.y],
          [c.x, c.y],
        ],
        __edge: { ...e, fromLabel: a.node.label, toLabel: c.node.label },
      }
    })
  if (offEdges.length) {
    series.push({
      type: 'lines',
      coordinateSystem: 'cartesian2d',
      lineStyle: { color: '#94a3b8', width: 1.2, type: 'dashed', opacity: 0.7 },
      data: offEdges,
    })
  }

  return {
    animation: true,
    animationDuration: 320,
    grid: { left: 6, right: 6, top: 6, bottom: 6 },
    xAxis: { type: 'value', min: s.bounds[0], max: s.bounds[1], show: false },
    yAxis: { type: 'value', min: s.bounds[2], max: s.bounds[3], show: false },
    dataZoom: [
      {
        type: 'inside',
        xAxisIndex: 0,
        filterMode: 'none',
        zoomOnMouseWheel: true,
        moveOnMouseWheel: false,
        // 平移交给我们自己处理：让 dataZoom 也跟着鼠标拖，就会和「拖动节点」打架
        moveOnMouseMove: false,
        start: zoom.value.x.start,
        end: zoom.value.x.end,
      },
      {
        type: 'inside',
        yAxisIndex: 0,
        filterMode: 'none',
        zoomOnMouseWheel: true,
        moveOnMouseWheel: false,
        moveOnMouseMove: false,
        start: zoom.value.y.start,
        end: zoom.value.y.end,
      },
    ],
    tooltip: { trigger: 'item', confine: true, className: 'fnwg-topo-tip', padding: [8, 10], formatter: (p: any) => tipHTML(p.data || {}) },
    series,
  }
}

let paintPending = false
/** paint 合并同一帧里的多次重画（拖动节点时每帧最多画一次）。 */
function paint(): void {
  if (paintPending) return
  paintPending = true
  requestAnimationFrame(() => {
    paintPending = false
    if (!chart || !graph.value) return
    const option = buildOption()
    // 拖动时关掉过渡动画：每帧都做一次 300ms 补间，手一拖就明显发涩
    if (dragging) option.animation = false
    // 用增量合并而不是整图 replace：后者重建全部系列与容器，是「卡」的主要来源
    chart.setOption(option)
  })
}

// ------------------------------------------------------------------ 交互

/** 拖动节点：ECharts 的 graph 系列在 cartesian2d 下自带拖动支持有限，这里自己接管，保证位置可控可存。 */
let dragging: { id: string; moved: boolean } | null = null
/** 空白处拖动平移的状态（与节点拖动分开，避免两个动作抢鼠标）。 */
let panning: { x: number; y: number } | null = null

function bindChartEvents(): void {
  if (!chart) return
  chart.off('mousedown')
  chart.off('dblclick')
  chart.off('contextmenu')
  chart.on('mousedown', (p: any) => {
    if (!p.data?.__node) return
    dragging = { id: p.data.__node.id, moved: false }
    // 按下时把当前布局固化成底稿：拖动只覆盖被拖的那一个，其余节点保持原样，
    // 也避免每帧重算布局。之后位置就一直以用户摆的为准。
    if (mode.value !== 'force' && Object.keys(positions.value).length === 0) {
      positions.value = computePositions(graph.value!, mode.value)
    }
  })
  // 空白处按住拖动 = 平移画布（节点上的拖动则是移动节点，两者互不干扰）
  chart.getZr().off('mousedown')
  chart.getZr().on('mousedown', (e: any) => {
    if (!e.target && chart) panning = { x: e.offsetX, y: e.offsetY }
  })
  chart.getZr().off('mousemove')
  chart.getZr().on('mousemove', (e: any) => {
    if (panning && chart) {
      const w = chart.getWidth() || 1
      const h = chart.getHeight() || 1
      const spanX = zoom.value.x.end - zoom.value.x.start
      const spanY = zoom.value.y.end - zoom.value.y.start
      const dx = ((panning.x - e.offsetX) / w) * spanX
      const dy = ((e.offsetY - panning.y) / h) * spanY
      zoom.value = {
        x: window100(zoom.value.x.start + spanX / 2 + dx, spanX),
        y: window100(zoom.value.y.start + spanY / 2 + dy, spanY),
      }
      panning = { x: e.offsetX, y: e.offsetY }
      applyZoom()
      return
    }
    if (!dragging || !chart) return
    const pt = chart.convertFromPixel({ seriesIndex: 0 }, [e.offsetX, e.offsetY]) as number[]
    if (!pt || pt.length < 2 || Number.isNaN(pt[0])) return
    dragging.moved = true
    positions.value = { ...positions.value, [dragging.id]: { x: Math.round(pt[0]), y: Math.round(pt[1]) } }
  })
  chart.getZr().off('mouseup')
  chart.getZr().on('mouseup', () => {
    if (dragging?.moved) saveView()
    dragging = null
    panning = null
  })
  // 滚轮/拖动改视野时 ECharts 只改内部状态：把窗口读回来，缩略图的「正在看哪一块」才能跟上
  chart.on('dataZoom', () => {
    const dz = ((chart?.getOption() as any)?.dataZoom || []) as any[]
    const at = (i: number, k: 'start' | 'end') => {
      const v = dz[i]?.[k]
      return typeof v === 'number' ? v : k === 'start' ? 0 : 100
    }
    zoom.value = { x: { start: at(0, 'start'), end: at(0, 'end') }, y: { start: at(1, 'start'), end: at(1, 'end') } }
  })
  chart.on('dblclick', (p: any) => {
    const n = p.data?.__node as TopologyNode | undefined
    if (n) jumpTo(n)
  })
  chart.on('contextmenu', (p: any) => {
    const n = p.data?.__node as TopologyNode | undefined
    const ev = p.event?.event as MouseEvent | undefined
    if (!n || !ev) return
    ev.preventDefault()
    const box = chartEl.value?.getBoundingClientRect()
    menu.value = {
      x: (ev.clientX || 0) - (box?.left || 0),
      y: (ev.clientY || 0) - (box?.top || 0),
      label: n.label,
      items: menuFor(n),
    }
  })
  // 点空白处：关菜单 + 取消高亮（点在节点上由下面的 click 处理）
  chart.getZr().on('click', (e: any) => {
    menu.value = null
    if (!e.target) clearSelection()
  })
  chart.on('click', (p: any) => {
    const n = p.data?.__node as TopologyNode | undefined
    if (n) selected.value = selected.value === n.id ? null : n.id
    saveView()
  })
}

function clearSelection(): void {
  if (selected.value) {
    selected.value = null
    paint()
  }
}

/** 布局切换：换布局就丢掉手工位置（否则新布局看不出来）。 */
function onModeChange(): void {
  positions.value = {}
  saveView()
  paint()
}

/** window100 把「以 center 为中心、跨 span 的窗口」夹在 0~100 之内。 */
function window100(center: number, span: number): { start: number; end: number } {
  let s = center - span / 2
  if (s < 0) s = 0
  if (s + span > 100) s = 100 - span
  return { start: s, end: s + span }
}

/** applyZoom 把当前窗口下发给两个 dataZoom（横、纵各一个，分开才能用缩略图双向定位）。 */
function applyZoom(): void {
  chart?.dispatchAction({ type: 'dataZoom', dataZoomIndex: 0, start: zoom.value.x.start, end: zoom.value.x.end })
  chart?.dispatchAction({ type: 'dataZoom', dataZoomIndex: 1, start: zoom.value.y.start, end: zoom.value.y.end })
}

function zoomBy(factor: number): void {
  const span = Math.min(100, Math.max(8, (zoom.value.x.end - zoom.value.x.start) * factor))
  zoom.value = {
    x: window100((zoom.value.x.start + zoom.value.x.end) / 2, span),
    y: window100((zoom.value.y.start + zoom.value.y.end) / 2, span),
  }
  applyZoom()
}

function fitView(): void {
  zoom.value = { x: { start: 0, end: 100 }, y: { start: 0, end: 100 } }
  applyZoom()
}

/** 双击跳转：把图上的东西和页面里的东西对应起来，省得自己去翻。 */
function jumpTo(n: TopologyNode): void {
  if (n.kind === 'device' || n.kind === 'site') return void router.push({ name: 'peers' })
  if (n.kind === 'lan' || n.kind === 'site-lan') return void router.push({ name: 'interfaces' })
  if (n.kind === 'foreign') return void router.push({ name: 'maintenance' })
  void router.push({ name: 'settings' }) // 内网设备：去「系统设置 → 内网域名」给它起名字
}

function copy(text: string, what: string): void {
  navigator.clipboard
    ?.writeText(text)
    .then(() => ElMessage.success(`${what}已复制`))
    .catch(() => ElMessage.warning('复制失败，请手动选择'))
  menu.value = null
}

/** 右键菜单：只做「看一眼、复制一下、跳过去」这类安全动作，不改网络。 */
function menuFor(n: TopologyNode): MenuItem[] {
  const detail = (k: string) => n.details.find((d) => d.key === k)?.value || ''
  const items: MenuItem[] = []
  if (n.kind === 'host') {
    const ip = detail('IP 地址') || n.label
    items.push({ text: '复制 IP 地址', icon: CopyDocument, act: () => copy(ip, 'IP 地址') })
    items.push({ text: '在浏览器打开', icon: Link, act: () => window.open(`http://${ip}`, '_blank') })
    items.push({ text: '去「内网域名」给它起名字', icon: Setting, act: () => { menu.value = null; void router.push({ name: 'settings' }) } })
  } else if (n.kind === 'device' || n.kind === 'site') {
    items.push({ text: '查看设备配置', icon: View, act: () => { menu.value = null; void router.push({ name: 'peers' }) } })
    items.push({ text: '复制隧道地址', icon: CopyDocument, act: () => copy(detail('隧道地址'), '隧道地址') })
    if (n.kind === 'site') items.push({ text: '复制对端内网网段', icon: CopyDocument, act: () => copy(detail('对端内网'), '网段') })
  } else if (n.kind === 'lan' || n.kind === 'site-lan') {
    items.push({ text: '复制网段', icon: CopyDocument, act: () => copy(n.label, '网段') })
    items.push({ text: '查看连接', icon: View, act: () => { menu.value = null; void router.push({ name: 'interfaces' }) } })
  } else if (n.kind === 'foreign') {
    items.push({ text: '去「系统维护」处理', icon: Setting, act: () => { menu.value = null; void router.push({ name: 'maintenance' }) } })
    items.push({ text: '复制网卡名', icon: CopyDocument, act: () => copy(n.label, '网卡名') })
  } else {
    items.push({ text: '复制内网网段', icon: CopyDocument, act: () => copy(detail('内网网段'), '网段') })
    items.push({ text: '查看连接', icon: View, act: () => { menu.value = null; void router.push({ name: 'interfaces' }) } })
  }
  return items
}

function runMenu(it: MenuItem): void {
  it.act()
}

/** 导出图片：把当前视图（含高亮状态）存成 PNG，方便发给别人看。 */
function exportPNG(): void {
  if (!chart) return
  const url = chart.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: chartInk().card })
  const a = document.createElement('a')
  a.href = url
  a.download = `网络拓扑-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')}.png`
  a.click()
  ElMessage.success('已导出图片')
}

// ------------------------------------------------------------------ 缩略图

const miniDragging = ref(false)

/** 缩略图：把当前布局缩到一个小方框里，并画出「正在看的是哪一块」。 */
const mini = computed(() => {
  const s = scene.value
  const w = 170
  const h = 116
  if (!s) return { w, h, nodes: [] as any[], lines: [] as any[], view: { x: 0, y: 0, w: 0, h: 0 } }
  const [x0, x1, y0, y1] = s.bounds
  const sx = w / (x1 - x0)
  const sy = h / (y1 - y0)
  const px = (x: number) => (x - x0) * sx
  const py = (y: number) => h - (y - y0) * sy
  const nodes = s.placed.map((p) => ({ id: p.node.id, cx: px(p.x), cy: py(p.y), kind: p.node.kind }))
  const lines = s.edges.map((e) => {
    const a = s.byId.get(e.from)!
    const b = s.byId.get(e.to)!
    return { x1: px(a.x), y1: py(a.y), x2: px(b.x), y2: py(b.y) }
  })
  // 当前可见窗口：把 dataZoom 的百分比换算回数据坐标（x、y 两轴各自线性映射）
  const vx0 = x0 + ((x1 - x0) * zoom.value.x.start) / 100
  const vx1 = x0 + ((x1 - x0) * zoom.value.x.end) / 100
  const vy0 = y0 + ((y1 - y0) * zoom.value.y.start) / 100
  const vy1 = y0 + ((y1 - y0) * zoom.value.y.end) / 100
  const view = {
    x: px(vx0),
    y: py(vy1),
    w: Math.max(6, (vx1 - vx0) * sx),
    h: Math.max(6, (vy1 - vy0) * sy),
  }
  return { w, h, nodes, lines, view }
})

/** 在缩略图上点击/拖动：把视野移到那一点（等于「拖动对照」的另一半）。 */
function onMiniJump(e: MouseEvent): void {
  miniDragging.value = true
  jumpMini(e)
}

function onMiniDrag(e: MouseEvent): void {
  if (miniDragging.value) jumpMini(e)
}

function jumpMini(e: MouseEvent): void {
  const s = scene.value
  const el = e.currentTarget as SVGElement
  if (!s || !el) return
  const box = el.getBoundingClientRect()
  const fx = (e.clientX - box.left) / box.width
  const fy = 1 - (e.clientY - box.top) / box.height
  const spanX = zoom.value.x.end - zoom.value.x.start
  const spanY = zoom.value.y.end - zoom.value.y.start
  zoom.value = { x: window100(fx * 100, spanX), y: window100(fy * 100, spanY) }
  applyZoom()
}

// ------------------------------------------------------------------ 存取与生命周期

function saveView(): void {
  try {
    localStorage.setItem(STORE_KEY, JSON.stringify({ mode: mode.value, positions: positions.value }))
  } catch {
    /* 存不下就算了：位置只是便利，不该影响使用 */
  }
}

function loadView(): void {
  try {
    const raw = localStorage.getItem(STORE_KEY)
    if (!raw) return
    const v = JSON.parse(raw)
    if (v?.mode === 'radial' || v?.mode === 'circular' || v?.mode === 'force') mode.value = v.mode
    if (v?.positions && typeof v.positions === 'object') positions.value = v.positions
  } catch {
    /* 坏了就用默认布局 */
  }
}

async function load(): Promise<void> {
  loading.value = true
  try {
    graph.value = await api.get<TopologyGraph>('/topology')
    await nextTick()
    if (!chart && chartEl.value) {
      chart = echarts.init(chartEl.value, null, { useDirtyRect: true })
      bindChartEvents()
    }
    paint()
    chart?.resize()
  } catch (e) {
    ElMessage.error((e as Error)?.message || '读取拓扑失败')
  } finally {
    loading.value = false
  }
}

function onResize(): void {
  chart?.resize()
}

watch(scene, () => paint())
watch(isMobile, async () => {
  await nextTick()
  paint()
  chart?.resize()
})

onMounted(() => {
  loadView()
  load()
  window.addEventListener('resize', onResize)
  window.addEventListener('click', closeMenu)
})

function closeMenu(): void {
  if (menu.value) menu.value = null
}

onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('click', closeMenu)
  chart?.dispose()
  chart = null
})
</script>

<style scoped>
.fnwg-topo-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.fnwg-topo-wrap {
  position: relative;
  width: 100%;
}

.fnwg-topo-canvas {
  width: 100%;
}

/* 缩略图：右下角压一层，不挡主图的操作（pointer-events 只在自身） */
.fnwg-topo-mini {
  position: absolute;
  right: 6px;
  top: 6px;
  width: 170px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow-light);
  opacity: 0.92;
  cursor: crosshair;
}

.fnwg-topo-mini svg {
  display: block;
  width: 100%;
  height: 116px;
}

.fnwg-topo-mini > span {
  position: absolute;
  left: 6px;
  top: 4px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
}

.fnwg-topo-mini-line {
  stroke: var(--el-border-color-lighter);
  stroke-width: 0.8;
}

.fnwg-topo-mini circle {
  fill: var(--el-text-color-disabled);
}

.fnwg-topo-mini circle.k-nas {
  fill: #409eff;
}

.fnwg-topo-mini circle.k-lan,
.fnwg-topo-mini circle.k-site-lan {
  fill: #14b8a6;
}

.fnwg-topo-mini circle.k-host {
  fill: #22c55e;
}

.fnwg-topo-mini circle.k-site {
  fill: #8b5cf6;
}

.fnwg-topo-mini circle.k-foreign {
  fill: #f59e0b;
}

.fnwg-topo-mini-view {
  fill: rgba(64, 158, 255, 0.12);
  stroke: var(--el-color-primary);
  stroke-width: 1;
}

.fnwg-topo-menu {
  position: absolute;
  z-index: 12;
  min-width: 176px;
  padding: 4px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow);
}

.fnwg-topo-menu-head {
  padding: 4px 8px 6px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  border-bottom: 1px solid var(--el-border-color-lighter);
  margin-bottom: 4px;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.fnwg-topo-menu-item {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 6px 8px;
  font-size: 13px;
  border-radius: 4px;
  cursor: pointer;
}

.fnwg-topo-menu-item:hover {
  background: var(--el-fill-color-light);
  color: var(--el-color-primary);
}

.fnwg-topo-legend {
  display: flex;
  flex-wrap: wrap;
  gap: 6px 16px;
  margin-top: 4px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.fnwg-topo-legend span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

/* 图例里的「点」是 HTML 元素，要用背景色画（早前误用了 SVG 的 fill，于是颜色没渲染出来） */
.fnwg-topo-legend i {
  display: inline-block;
  width: 9px;
  height: 9px;
  border-radius: 50%;
}

.fnwg-topo-legend-line {
  display: inline-block;
  width: 26px;
  height: 0;
  border-top: 2px solid #409eff;
}

.fnwg-topo-legend-line.off {
  border-top-style: dashed;
  border-top-color: #94a3b8;
}

.fnwg-topo-notes {
  margin-top: 8px;
}

.fnwg-topo-link {
  color: var(--el-color-primary);
  cursor: pointer;
}

/* ECharts 的悬停卡挂在图表容器里，用 :deep 才能套上本组件的样式 */
.fnwg-topo :deep(.fnwg-topo-tip) {
  border: 1px solid var(--el-border-color);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow-light);
  font-size: 12.5px;
  line-height: 1.7;
  max-width: 340px;
}
</style>
