<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
  网络拓扑（v-network-graph 版）。
  与 ECharts 版共用同一份 /topology 数据、同样的卡片与图标观感，用来看「换个库手感是否更好」。

  这一版刻意保持精简，几处已知差异会显示在卡片下方的说明里（不藏起来）：
    · 连线不做逐边的状态/速率配色（v-network-graph 的样式是全局配置；逐边配色要另想办法）；
    · 缩略图只作全览用（这个库没有暴露视野状态，因此画不出「当前看的是哪一块」的方框）；
    · 拖动位置记不住（拖动由库自己管，落盘需要拿到它的位置回调，待确认）。
  （曾经用 ECharts 做过一版并对比过手感，最终选定这个库；落选的那一版已删除。）
-->
<template>
  <div class="fnwg-card fnwg-topo">
    <div class="fnwg-card-head">
      <div>
        <strong>网络拓扑</strong>
        <span class="fnwg-card-desc">
          左侧内网、右侧隧道与对端 NAS；拖空白平移、滚轮缩放，单击看链路、双击跳转、右键更多。
        </span>
      </div>
      <div class="fnwg-topo-actions">
        <el-tag v-if="graph" size="small" type="info" effect="plain">{{ atLabel }}</el-tag>
        <el-radio-group v-model="mode" size="small" @change="onModeChange">
          <el-radio-button value="radial">放射</el-radio-button>
          <el-radio-button value="circular">环状</el-radio-button>
          <el-radio-button value="force">自由</el-radio-button>
        </el-radio-group>
        <el-button-group>
          <el-button size="small" :icon="ZoomIn" title="放大" @click="gref?.zoomIn()" />
          <el-button size="small" :icon="ZoomOut" title="缩小" @click="gref?.zoomOut()" />
          <el-button size="small" :icon="Aim" title="适应窗口" @click="gref?.fitToContents()" />
        </el-button-group>
        <el-button size="small" :icon="Picture" title="导出图片" @click="exportPNG">导出</el-button>
        <el-button size="small" :icon="Refresh" :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <div v-if="!graph" class="fnwg-hint">正在读取拓扑…</div>

    <template v-else>
      <!--
        交互全部放在 DOM 这一层（捕获阶段）：这个库的节点事件载荷字段与我们猜的不一致，
        而它渲染出来的 SVG 就在我们手里 —— 直接用 data-node 找节点最稳，不受它的事件定义影响。
      -->
      <div
        ref="wrapEl"
        class="fnwg-topo-wrap"
        @click.capture="onWrapClick"
        @dblclick.capture="onWrapDbl"
        @contextmenu.capture="onWrapMenu"
        @mousemove="onWrapMove"
        @mouseleave="hover = null"
      >
        <VNetworkGraph
          ref="gref"
          class="fnwg-vng"
          :nodes="vngNodes"
          :edges="vngEdges"
          :layouts="{ nodes: pos }"
          :configs="configs"
          :selected-nodes="selected ? [selected] : []"
          :style="{ height: canvasHeight }"
        >
          <!-- 节点：用 SVG 自绘卡片（图标 + 名称 + 地址），与 ECharts 版观感一致 -->
          <template #override-node="{ nodeId }">
            <g :data-node="nodeId" :transform="`translate(${-sizeOf(nodeOf(nodeId)).w / 2}, ${-sizeOf(nodeOf(nodeId)).h / 2})`">
              <rect
                :width="sizeOf(nodeOf(nodeId)).w"
                :height="sizeOf(nodeOf(nodeId)).h"
                rx="9"
                :fill="nodeOf(nodeId).kind === 'nas' ? colorOf(nodeOf(nodeId)) : ink.card"
                :stroke="colorOf(nodeOf(nodeId))"
                :stroke-width="nodeOf(nodeId).kind === 'nas' ? 2.5 : 1.5"
                :stroke-dasharray="nodeOf(nodeId).kind === 'foreign' ? '4 3' : undefined"
                :opacity="dimmed(nodeId) ? 0.25 : 1"
              />
              <image
                :href="iconURI(iconOf(nodeOf(nodeId)), nodeOf(nodeId).kind === 'nas' ? '#ffffff' : colorOf(nodeOf(nodeId)))"
                x="10"
                :y="sizeOf(nodeOf(nodeId)).h / 2 - 9"
                width="18"
                height="18"
                :opacity="dimmed(nodeId) ? 0.25 : 1"
              />
              <text
                x="34"
                :y="sizeOf(nodeOf(nodeId)).h / 2 - 3"
                font-size="12.5"
                :font-weight="nodeOf(nodeId).kind === 'nas' ? 'bold' : 'normal'"
                :fill="nodeOf(nodeId).kind === 'nas' ? '#ffffff' : ink.text"
                :opacity="dimmed(nodeId) ? 0.3 : 1"
              >
                {{ nodeOf(nodeId).label }}
              </text>
              <text
                v-if="nodeOf(nodeId).note"
                x="34"
                :y="sizeOf(nodeOf(nodeId)).h / 2 + 27"
                font-size="10.5"
                :fill="nodeOf(nodeId).kind === 'nas' ? 'rgba(255,255,255,0.7)' : ink.dim"
                :opacity="dimmed(nodeId) ? 0.3 : 1"
              >
                {{ nodeOf(nodeId).note }}
              </text>
              <text
                v-if="nodeOf(nodeId).sublabel"
                x="34"
                :y="sizeOf(nodeOf(nodeId)).h / 2 + 13"
                font-size="11"
                :fill="nodeOf(nodeId).kind === 'nas' ? 'rgba(255,255,255,0.85)' : ink.dim"
                :opacity="dimmed(nodeId) ? 0.3 : 1"
              >
                {{ nodeOf(nodeId).sublabel }}
              </text>
            </g>
          </template>
        </VNetworkGraph>

        <!-- 悬停：跟着鼠标给出这台设备的完整信息（与原来那版同一套字段） -->
        <div v-if="hover" class="fnwg-topo-tip" :style="{ left: hover.x + 'px', top: hover.y + 'px' }">
          <strong>{{ hover.node.label }}</strong>
          <span v-if="hover.node.sublabel" class="fnwg-topo-tip-sub">{{ hover.node.sublabel }}</span>
          <div v-for="kv in detailRows(hover.node)" :key="kv.key" class="fnwg-topo-tip-row">
            <span class="fnwg-topo-tip-key">{{ kv.key }}</span>
            <span class="fnwg-topo-tip-val">{{ kv.value }}</span>
          </div>
          <div class="fnwg-topo-tip-foot">单击固定这条信息 · 双击跳转 · 右键更多 · 可拖动</div>
        </div>

        <!-- 点击：把信息固定在左下角（手机上也能用，悬停不好使） -->
        <div v-if="pinned" class="fnwg-topo-panel">
          <div class="fnwg-topo-panel-head">
            <strong>{{ pinned.label }}</strong>
            <a class="fnwg-topo-link" @click="pinned = null">关闭</a>
          </div>
          <div v-for="kv in detailRows(pinned)" :key="kv.key" class="fnwg-topo-tip-row">
            <span class="fnwg-topo-tip-key">{{ kv.key }}</span>
            <span class="fnwg-topo-tip-val">{{ kv.value }}</span>
          </div>
          <div v-if="pinned.kind === 'host'" class="fnwg-topo-kind">
            <span>设备类型</span>
            <el-select
              :model-value="pinned.device_kind || ''"
              size="small"
              placeholder="按名称自动判断"
              clearable
              style="width: 150px"
              @change="setKind"
            >
              <el-option v-for="o in kindOptions" :key="o.value" :label="o.label" :value="o.value" />
            </el-select>
          </div>

          <div class="fnwg-topo-panel-foot">
            <el-button size="small" @click="jumpTo(pinned)">去对应页面</el-button>
            <el-button size="small" @click="copy((pinned.details.find((d) => d.key === 'IP 地址') || {}).value || pinned.label, '地址')">
              复制地址
            </el-button>
          </div>
        </div>

        <!-- 右键菜单（与原来那版同一套动作） -->
        <div v-if="menu" class="fnwg-topo-menu" :style="{ left: menu.x + 'px', top: menu.y + 'px' }">
          <div class="fnwg-topo-menu-head">{{ menu.label }}</div>
          <div v-for="(it, i) in menu.items" :key="i" class="fnwg-topo-menu-item" @click="it.act()">
            <el-icon><component :is="it.icon" /></el-icon>{{ it.text }}
          </div>
        </div>

      </div>

      <!--
        全览小地图与图例放在画布下方同一行。
        小地图原来浮在画布右上角，会盖住那里的节点（它只是「全览」、不参与交互，
        浮着没有任何好处）—— 挪出画布最省事也最不容易出错：画布里的东西再也不会被它挡住。
      -->
      <div class="fnwg-topo-below">
        <!-- 图例：颜色对应节点种类，线型对应连线状态 -->
        <div class="fnwg-topo-legend">
          <span v-for="l in legend" :key="l.text"><i :style="{ background: l.color }" />{{ l.text }}</span>
          <span><i class="fnwg-topo-legend-line flow" />绿色流动 + 箭头 = 正在传数据（越快越急）</span>
          <span><i class="fnwg-topo-legend-line off" />灰色虚线 = 空闲 / 已停用</span>
        </div>
        <div class="fnwg-topo-mini">
          <svg :viewBox="`0 0 ${mini.w} ${mini.h}`">
            <line v-for="(l, i) in mini.lines" :key="i" :x1="l.x1" :y1="l.y1" :x2="l.x2" :y2="l.y2" class="fnwg-topo-mini-line" />
            <circle v-for="n in mini.nodes" :key="n.id" :cx="n.cx" :cy="n.cy" r="2.6" :class="`k-${n.kind}`" />
            <rect
              v-if="mini.view"
              :x="mini.view.x"
              :y="mini.view.y"
              :width="mini.view.w"
              :height="mini.view.h"
              class="fnwg-topo-mini-view"
            />
          </svg>
          <span>全览</span>
        </div>
      </div>

      <div class="fnwg-topo-notes">
        <div v-if="selected" class="fnwg-hint">
          · 正在看「{{ selectedLabel }}」这条链路。 <a class="fnwg-topo-link" @click="selected = null">取消高亮</a>
        </div>
        <div class="fnwg-hint">· 节点图标按名字判断设备类型（路由 / 电脑 / 手机 / 打印机…）：给设备在「内网域名」里起个名字，图标会更准。</div>
        <div v-for="(n, i) in graph.notes" :key="i" class="fnwg-hint">· {{ n }}</div>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Aim, CopyDocument, Link, Picture, Refresh, Setting, View, ZoomIn, ZoomOut } from '@element-plus/icons-vue'
import { VNetworkGraph } from 'v-network-graph'
import { api } from '@/api/client'
import type { TopologyGraph, TopologyNode } from '@/api/types'
import { useBreakpoint } from '@/composables/useBreakpoint'

const { isMobile } = useBreakpoint()
const router = useRouter()

const graph = ref<TopologyGraph | null>(null)
const loading = ref(false)
const wrapEl = ref<HTMLElement | null>(null)
const gref = ref<any>(null)
const mode = ref<'radial' | 'circular' | 'force'>('radial')
const positions = ref<Record<string, { x: number; y: number }>>({})
const selected = ref<string | null>(null)
const menu = ref<{ x: number; y: number; label: string; items: { text: string; icon: object; act: () => void }[] } | null>(null)

// 与 ECharts 版分开存：两个引擎的布局方式与手工位置互不影响。
// 手机与桌面也分开存：两边的布局半径不同，共用一份坐标会出现「同一张图在另一块屏幕上挤成一团」。
function storeKey(): string {
  return isMobile.value ? 'fnwg.topology.view.mobile' : 'fnwg.topology.view'
}

/**
 * 画布高度：设备多的时候固定高度会把卡片挤成一团（用户反馈「高度不够」），
 * 因此按节点数给高度，并设上下限（太高会让图例与说明被推到屏幕外）。
 */
const canvasHeight = computed(() => {
  const n = graph.value?.nodes.length || 0
  const base = isMobile.value ? 440 : 500
  const per = isMobile.value ? 28 : 30
  return `${Math.min(isMobile.value ? 680 : 780, Math.max(base, n * per))}px`
})

const atLabel = computed(() => (graph.value ? `更新于 ${graph.value.at}` : ''))
const selectedLabel = computed(() => graph.value?.nodes.find((n) => n.id === selected.value)?.label || '')
/** 悬停提示（跟随鼠标）与「点击固定」的详情面板。 */
const hover = ref<{ x: number; y: number; node: TopologyNode } | null>(null)
const pinned = ref<TopologyNode | null>(null)

const legend = computed(() => [
  { text: '本机 NAS（蓝，实心）', color: KIND_COLOR.nas },
  { text: '内网网段 / 对端内网（青）', color: KIND_COLOR.lan },
  { text: '另一台 NAS（紫）', color: KIND_COLOR.site },
  { text: '设备：绿=在线或可达', color: STATUS_COLOR.ok },
  { text: '设备：橙=离线或待确认', color: STATUS_COLOR.warn },
  { text: '设备：灰=已停用或未知', color: STATUS_COLOR.off },
  { text: '疑似残留网卡（橙虚线框）', color: KIND_COLOR.foreign },
])

const TYPE_LABEL: Record<string, string> = {
  server: 'NAS / 服务器',
  network: '网段',
  router: '路由器 / 无线',
  laptop: '电脑（笔记本）',
  monitor: '电脑（默认图标）',
  phone: '手机 / 平板',
  printer: '打印机',
  tv: '电视 / 盒子',
  warning: '疑似残留网卡',
}

/** 详情行：第一行是「类型」（按名称判断，写明依据），其余用服务端给的字段。 */
function detailRows(n: TopologyNode): { key: string; value: string }[] {
  const isHost = n.kind === 'host' || n.kind === 'device'
  const configured = n.device_kind ? kindLabel(n.device_kind) : ''
  const typeText = configured
    ? configured + '（已配置）'
    : (TYPE_LABEL[iconOf(n)] || '设备') + (isHost ? '（按名称判断）' : '')
  const rows = [{ key: '类型', value: typeText }, ...n.details]
  // 「内网域名」里登记的备注：名字之外还常需要一句人能看懂的说明
  if (n.note) rows.splice(2, 0, { key: '备注', value: n.note })
  return rows
}

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

/** 图标（与 ECharts 版同一套；抽成共用模块留待选定引擎后处理）。 */
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
  switch:
    '<rect x="2.5" y="7" width="19" height="10" rx="2"/><rect x="5" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>' +
    '<rect x="8.6" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/><rect x="12.2" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>' +
    '<rect x="15.8" y="10" width="2.4" height="4" rx="0.6" fill-opacity="0.4"/>',
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
function iconURI(name: string, color: string): string {
  const k = name + color
  const hit = iconCache.get(k)
  if (hit) return hit
  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24" fill="${color}" stroke="${color}">` +
    `${ICON_PATHS[name] || ICON_PATHS.monitor}</svg>`
  const uri = 'data:image/svg+xml,' + encodeURIComponent(svg)
  iconCache.set(k, uri)
  return uri
}
const NAME_RULES: [RegExp, string][] = [
  [/nas|存储|群晖|威联通|synology|qnap|极空间|绿联|服务器|server/i, 'server'],
  [/路由|router|网关|gateway|无线|wifi|mesh/i, 'router'],
  [/打印|printer|扫描/i, 'printer'],
  [/手机|phone|iphone|android|安卓|pad|tablet|ipad/i, 'phone'],
  [/电视|tv|盒子|机顶盒|投影/i, 'tv'],
  [/电脑|pc|mac|book|笔记本|台式|desktop/i, 'laptop'],
]
function iconOf(n: TopologyNode): string {
  if (n.kind === 'nas' || n.kind === 'site') return 'server'
  if (n.kind === 'lan' || n.kind === 'site-lan') return 'network'
  if (n.kind === 'foreign') return 'warning'
  // 用户配过类型就按它画：猜是兜底，用户说了算才是准的
  if (n.device_kind) {
    const map: Record<string, string> = {
      router: 'router', switch: 'switch', server: 'server', computer: 'monitor',
      phone: 'phone', printer: 'printer', tv: 'tv', camera: 'camera', speaker: 'speaker', other: 'monitor',
    }
    return map[n.device_kind] || 'monitor'
  }
  const text = `${n.label} ${n.sublabel || ''}`
  for (const [re, icon] of NAME_RULES) if (re.test(text)) return icon
  return 'monitor'
}

const ink = { text: '#303133', dim: '#909399', line: '#dcdfe6', card: '#ffffff' }
/** 「在传数据」的连线用这个颜色（见 edgeStyle 与 applyFlow，两处必须是同一个值）。 */
const FLOW_COLOR = '#22c55e'

function nodeOf(id: string): TopologyNode {
  return graph.value?.nodes.find((n) => n.id === id) || { id, kind: 'host', label: id, status: 'off', details: [] }
}
function colorOf(n: TopologyNode): string {
  return STATUS_DRIVEN.has(n.kind) ? STATUS_COLOR[n.status] || STATUS_COLOR.off : KIND_COLOR[n.kind] || STATUS_COLOR.off
}
/** 卡片尺寸：与 ECharts 版同一套估算口径。 */
function sizeOf(n: TopologyNode): { w: number; h: number } {
  const width = (s: string) => {
    let w = 0
    for (const ch of s) w += /[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]/.test(ch) ? 13 : 7.2
    return w
  }
  const lines = n.sublabel ? [n.label, n.sublabel] : [n.label]
  const widest = Math.max(...lines.map(width))
  const cap = n.kind === 'nas' ? 260 : isMobile.value ? 200 : 240
  const min = n.kind === 'nas' ? 170 : isMobile.value ? 118 : 128
  const h = n.note ? 66 : n.sublabel ? 52 : 34
  return { w: Math.min(cap, Math.max(min, widest * 1.08 + (n.kind === 'nas' ? 56 : 44))), h }
}

/** 位置：与 ECharts 版同样的三套布局（方位可复现）。 */
function computePositions(g: TopologyGraph, m: 'radial' | 'circular' | 'force'): Record<string, { x: number; y: number }> {
  const narrow = isMobile.value
  // 窄屏半径要压得够狠：手机画布只有 390px 宽，半径大一点，自动适应就把整张图缩到字读不出。
  // 以「能读」为准反推 —— 内容宽度约 460（节点卡片本身就有 120 宽），k 才落在 0.7 以上。
  const R1 = narrow ? 96 : 250
  const R2 = narrow ? 168 : 470
  const out: Record<string, { x: number; y: number }> = {}
  const nas = g.nodes.find((n) => n.kind === 'nas')
  if (nas) out[nas.id] = { x: 0, y: 0 }
  const rad = (d: number) => (d * Math.PI) / 180
  const childrenOf = (id: string) =>
    g.links.filter((l) => l.from === id).map((l) => g.nodes.find((n) => n.id === l.to)).filter(Boolean) as TopologyNode[]
  const lans = g.nodes.filter((n) => n.kind === 'lan')
  const sites = g.nodes.filter((n) => n.kind === 'site')
  const devices = g.nodes.filter((n) => n.kind === 'device')
  const foreign = g.nodes.filter((n) => n.kind === 'foreign')
  const arc = (list: TopologyNode[], center: number, spread: number, radius: number) => {
    list.forEach((n, i) => {
      const t = list.length === 1 ? 0.5 : i / (list.length - 1)
      const a = rad(center - spread / 2 + spread * t)
      out[n.id] = { x: radius * Math.cos(a), y: radius * Math.sin(a) }
    })
  }
  if (m === 'circular') {
    const ring1 = [...lans, ...sites, ...devices, ...foreign]
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
    arc(lans, 180, 100, R1)
    const right = [...sites, ...devices]
    arc(right, 0, Math.min(150, Math.max(60, right.length * 20)), R1)
    arc(foreign, 270, 60, R1)
    for (const parent of [...lans, ...sites]) {
      const kids = childrenOf(parent.id)
      const at = out[parent.id]
      if (!kids.length || !at) continue
      const baseAngle = (Math.atan2(at.y, at.x) * 180) / Math.PI
      const spread = Math.min(140, Math.max(30, kids.length * 16))
      const radius = R2 + Math.max(0, kids.length - 5) * (narrow ? 10 : 16)
      kids.forEach((n, i) => {
        const t = kids.length === 1 ? 0.5 : i / (kids.length - 1)
        const a = rad(baseAngle - spread / 2 + spread * t)
        out[n.id] = { x: radius * Math.cos(a), y: radius * Math.sin(a) }
      })
    }
  }
  if (m === 'force') return relax(g, out)
  return out
}

/** 「自由」布局：从放射出发做力导向松弛（固定初值 + 固定迭代 = 结果可复现）。 */
function relax(g: TopologyGraph, init: Record<string, { x: number; y: number }>): Record<string, { x: number; y: number }> {
  const narrow = isMobile.value
  const ids = Object.keys(init)
  const pos = ids.map((id) => ({ id, ...init[id] }))
  const idx = new Map(ids.map((id, i) => [id, i]))
  const nas = g.nodes.find((n) => n.kind === 'nas')
  const links = g.links
    .map((l) => ({ a: idx.get(l.from), b: idx.get(l.to) }))
    .filter((l) => l.a !== undefined && l.b !== undefined) as { a: number; b: number }[]
  const depth = ids.map((id) => {
    const k = g.nodes.find((x) => x.id === id)?.kind
    return k === 'nas' ? 0 : k === 'lan' || k === 'site' ? 1 : 2
  })
  for (let step = 0; step < 320; step++) {
    const cool = 1 - step / 320
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
        pos[i].x -= (dx / d) * rep
        pos[i].y -= (dy / d) * rep
        pos[j].x += (dx / d) * rep
        pos[j].y += (dy / d) * rep
      }
    }
    for (const l of links) {
      const dx = pos[l.b].x - pos[l.a].x
      const dy = pos[l.b].y - pos[l.a].y
      const d = Math.sqrt(dx * dx + dy * dy) || 1
      const pull = (d - 200) * 0.045 * cool
      pos[l.a].x += (dx / d) * pull
      pos[l.a].y += (dy / d) * pull
      pos[l.b].x -= (dx / d) * pull
      pos[l.b].y -= (dy / d) * pull
    }
    for (let i = 0; i < pos.length; i++) {
      if (depth[i] === 0) continue
      const want = depth[i] === 1 ? (narrow ? 110 : 260) : narrow ? 190 : 470
      const d = Math.sqrt(pos[i].x ** 2 + pos[i].y ** 2) || 1
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

const pos = computed(() => {
  const g = graph.value
  if (!g) return {}
  const base = computePositions(g, mode.value)
  const merged: Record<string, { x: number; y: number }> = {}
  for (const n of g.nodes) merged[n.id] = positions.value[n.id] || base[n.id] || { x: 0, y: 0 }
  return merged
})

const vngNodes = computed(() => {
  const out: Record<string, { name: string }> = {}
  for (const n of graph.value?.nodes || []) out[n.id] = { name: n.label }
  return out
})

const vngEdges = computed(() => {
  const out: Record<string, { source: string; target: string }> = {}
  linkOf.clear()
  for (const l of graph.value?.links || []) {
    out[`${l.from}>${l.to}`] = { source: l.from, target: l.to }
    linkOf.set(`${l.from}>${l.to}`, { status: l.status, rate: l.rate || 0 })
  }
  return out
})

/** 高亮：选中节点及其邻居保持清晰，其余淡出。 */
const related = computed(() => {
  const set = new Set<string>()
  const g = graph.value
  if (!g || !selected.value) return set
  set.add(selected.value)
  for (const l of g.links) {
    if (l.from === selected.value) set.add(l.to)
    if (l.to === selected.value) set.add(l.from)
  }
  return set
})
function dimmed(id: string): boolean {
  return selected.value !== null && !related.value.has(id)
}


/** 边 → 状态/速率（按 source>target 查回我们自己的连线数据）。 */
const linkOf = new Map<string, { status: string; rate: number }>()

/**
 * 一条线的画法：只有「在传数据」的线才流动（按速率分档决定粗细），空闲与已停用的线静止。
 * 这是补上的第一项 —— 该库没有逐边样式的现成开关，但配置项支持传函数（CallableValue）。
 */
function edgeStyle(e: any): { color: string; width: number; lineDash: number[] } {
  const l = linkOf.get(`${e?.source}>${e?.target}`)
  if (!l || (l.status !== 'ok' && l.status !== 'warn')) return { color: '#94a3b8', width: 1.2, lineDash: [3, 4] }
  if (l.rate >= 1024 * 1024) return { color: FLOW_COLOR, width: 2.6, lineDash: [8, 6] }
  if (l.rate >= 64 * 1024) return { color: FLOW_COLOR, width: 2.2, lineDash: [8, 6] }
  if (l.rate > 0) return { color: FLOW_COLOR, width: 1.8, lineDash: [8, 6] }
  if (l.status === 'warn') return { color: '#f59e0b', width: 1.8, lineDash: [6, 6] }
  return { color: '#cbd5e1', width: 1.4, lineDash: [6, 6] }
}

const configs: any = computed(() => ({
  view: {
    panEnabled: true,
    zoomEnabled: true,
    minZoomLevel: 0.2,
    maxZoomLevel: 4,
    // 打开时自动把内容装进画布（原来写的 autoFit 不是这个库的字段，等于没开）
    autoPanAndZoomOnLoad: 'fit-content',
    // 库只按节点「点」算包围盒，不知道我们用 SVG 自绘的卡片有多大 —— 边距必须按卡片尺寸给足，
    // 否则贴着边缘的卡片会被画布裁掉（库默认只有 8%，这次线上表现就是最下面那张被切）。
    // 手机上只留一点：把一千多像素宽的内容硬塞进 390px 会让字缩到读不出，
    // 不如让用户拖动看 —— 字号能读比「一屏看全」重要。
    fitContentMargin: isMobile.value
      ? { top: 34, right: 22, bottom: 34, left: 22 }
      : { top: '9%', right: '19%', bottom: '9%', left: '19%' },
  },
  node: { selectable: true, draggable: true, normal: { type: 'circle', radius: 0 }, label: { visible: false } },
  edge: {
    normal: {
      width: (e: any) => edgeStyle(e).width,
      color: (e: any) => edgeStyle(e).color,
      lineDash: (e: any) => edgeStyle(e).lineDash,
      opacity: 0.9,
    },
    hover: { width: 3, color: '#409eff' },
    selectable: true,
  },
}))


/** 全览小地图：只画节点与连线（不画视野方框，见文件顶部说明）。 */
const mini = computed(() => {
  const g = graph.value
  const w = 170
  const h = 116
  if (!g)
    return {
      w,
      h,
      nodes: [] as Array<{ id: string; cx: number; cy: number; kind: string }>,
      lines: [] as Array<{ x1: number; y1: number; x2: number; y2: number }>,
      view: null as null | { x: number; y: number; w: number; h: number },
    }
  const p = pos.value
  const xs = Object.values(p).map((v) => v.x)
  const ys = Object.values(p).map((v) => v.y)
  const pad = 60
  const [x0, x1, y0, y1] = [Math.min(...xs) - pad, Math.max(...xs) + pad, Math.min(...ys) - pad, Math.max(...ys) + pad]
  const sx = w / (x1 - x0)
  const sy = h / (y1 - y0)
  const px = (x: number) => (x - x0) * sx
  const py = (y: number) => h - (y - y0) * sy
  // 视野方框：把屏幕可见范围换算回世界坐标，再映射到缩略图上
  let box: null | { x: number; y: number; w: number; h: number } = null
  const v = view.value
  const svgEl = wrapEl.value?.querySelector('svg')
  if (v && svgEl && svgEl.clientWidth > 0) {
    const x0w = -v.tx / v.k
    const x1w = (svgEl.clientWidth - v.tx) / v.k
    const y1w = -v.ty / v.k
    const y0w = (svgEl.clientHeight - v.ty) / v.k
    box = { x: px(x0w), y: py(y1w), w: Math.max(6, (x1w - x0w) * sx), h: Math.max(6, (y1w - y0w) * sy) }
  }
  return {
    w,
    h,
    view: box,
    nodes: g.nodes.map((n) => ({ id: n.id, cx: px(p[n.id]?.x || 0), cy: py(p[n.id]?.y || 0), kind: n.kind })),
    lines: g.links.map((l) => ({ x1: px(p[l.from]?.x || 0), y1: py(p[l.from]?.y || 0), x2: px(p[l.to]?.x || 0), y2: py(p[l.to]?.y || 0) })),
  }
})

/**
 * 换布局：必须把「回读/手工」的位置清掉。
 * 回读是每 1.5 秒把当前所有节点位置记下来（为了记住拖动），它会覆盖新布局算出来的坐标 ——
 * 清掉之后，新布局立即生效，随后的回读又以新布局为基准（这就是此前「切布局没反应」的原因）。
 */
function onModeChange(): void {
  positions.value = {}
  saveView()
}

/** 从事件目标往上找带 data-node 的卡片 —— 这就是「鼠标在哪台设备上」。 */
function nodeIdFrom(target: EventTarget | null): string {
  let el = target as Element | null
  while (el && el !== wrapEl.value) {
    const id = el.getAttribute?.('data-node')
    if (id) return id
    el = el.parentElement
  }
  return ''
}

/** 提示卡的位置：跟着鼠标，但不越出画布。 */
function tipPos(ev: MouseEvent): { x: number; y: number } {
  const box = wrapEl.value?.getBoundingClientRect()
  return {
    x: Math.min(Math.max(8, (ev.clientX || 0) - (box?.left || 0) + 14), Math.max(8, (box?.width || 800) - 336)),
    y: Math.min(Math.max(8, (ev.clientY || 0) - (box?.top || 0) + 12), Math.max(8, (box?.height || 600) - 240)),
  }
}

/** 单击：高亮这条链路，并把详细信息固定在左下角（手机上悬停不好使，详情得有地方看）。 */
// 事件是否落在浮层（详情卡 / 右键菜单 / 缩略图）里。必须排除：详情卡就在画布容器内，
// 若把卡里的点击也当成「点到空白」，一碰卡里的下拉就会把卡片关掉。
function inOverlay(target: EventTarget | null): boolean {
  const el = target as Element | null
  return !!el?.closest?.('.fnwg-topo-panel, .fnwg-topo-menu, .fnwg-topo-mini')
}

function onWrapClick(ev: MouseEvent): void {
  if (inOverlay(ev.target)) return
  const id = nodeIdFrom(ev.target)
  if (!id) {
    selected.value = null
    pinned.value = null
    menu.value = null
    return
  }
  const on = selected.value !== id
  selected.value = on ? id : null
  pinned.value = on ? nodeOf(id) : null
  menu.value = null
}

/** 双击：跳到这台设备/这条连接对应的页面。 */
function onWrapDbl(ev: MouseEvent): void {
  if (inOverlay(ev.target)) return
  const id = nodeIdFrom(ev.target)
  if (id) jumpTo(nodeOf(id))
}

/** 右键：给出可做的事（只看、只复制，不改网络）。 */
function onWrapMenu(ev: MouseEvent): void {
  if (inOverlay(ev.target)) return
  const id = nodeIdFrom(ev.target)
  if (!id) return
  ev.preventDefault()
  menu.value = { ...tipPos(ev), label: nodeOf(id).label, items: menuFor(nodeOf(id)) }
}

/** 悬停：跟着鼠标给出完整信息。 */
function onWrapMove(ev: MouseEvent): void {
  if (inOverlay(ev.target)) {
    hover.value = null
    return
  }
  const id = nodeIdFrom(ev.target)
  hover.value = id ? { ...tipPos(ev), node: nodeOf(id) } : null
}

function jumpTo(n: TopologyNode): void {
  if (n.kind === 'device' || n.kind === 'site') return void router.push({ name: 'peers' })
  if (n.kind === 'lan' || n.kind === 'site-lan') return void router.push({ name: 'interfaces' })
  if (n.kind === 'foreign') return void router.push({ name: 'maintenance' })
  void router.push({ name: 'settings' })
}

function copy(text: string, what: string): void {
  menu.value = null
  navigator.clipboard
    ?.writeText(text)
    .then(() => ElMessage.success(`${what}已复制`))
    .catch(() => ElMessage.warning('复制失败，请手动选择'))
}

function menuFor(n: TopologyNode): { text: string; icon: object; act: () => void }[] {
  const detail = (k: string) => n.details.find((d) => d.key === k)?.value || ''
  if (n.kind === 'host') {
    const ip = detail('IP 地址') || n.label
    return [
      { text: '复制 IP 地址', icon: CopyDocument, act: () => copy(ip, 'IP 地址') },
      { text: '在浏览器打开', icon: Link, act: () => { menu.value = null; window.open(`http://${ip}`, '_blank') } },
      { text: '去「内网域名」给它起名字', icon: Setting, act: () => { menu.value = null; void router.push({ name: 'settings' }) } },
    ]
  }
  if (n.kind === 'device' || n.kind === 'site') {
    return [
      { text: '查看设备配置', icon: View, act: () => { menu.value = null; void router.push({ name: 'peers' }) } },
      { text: '复制隧道地址', icon: CopyDocument, act: () => copy(detail('隧道地址'), '隧道地址') },
    ]
  }
  if (n.kind === 'foreign') {
    return [{ text: '去「系统维护」处理', icon: Setting, act: () => { menu.value = null; void router.push({ name: 'maintenance' }) } }]
  }
  return [{ text: '复制网段', icon: CopyDocument, act: () => copy(n.label, '网段') }]
}

/** 导出 PNG：把这个 SVG 序列化后画进 canvas（节点都是 SVG，导出不会有白块）。 */
async function exportPNG(): Promise<void> {
  const svg = wrapEl.value?.querySelector('svg')
  if (!svg) return
  const w = svg.clientWidth || 1200
  const h = svg.clientHeight || 600
  const clone = svg.cloneNode(true) as SVGElement
  clone.setAttribute('xmlns', 'http://www.w3.org/2000/svg')
  clone.setAttribute('width', String(w))
  clone.setAttribute('height', String(h))
  const xml = new XMLSerializer().serializeToString(clone)
  const img = new Image()
  try {
    await new Promise<void>((res, rej) => {
      img.onload = () => res()
      img.onerror = () => rej(new Error('转图片失败'))
      img.src = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(xml)
    })
  } catch {
    ElMessage.warning('导出失败：请重试或截图保存')
    return
  }
  const canvas = document.createElement('canvas')
  canvas.width = w * 2
  canvas.height = h * 2
  const ctx = canvas.getContext('2d')
  if (!ctx) return
  ctx.fillStyle = ink.card
  ctx.fillRect(0, 0, canvas.width, canvas.height)
  ctx.drawImage(img, 0, 0, canvas.width, canvas.height)
  const a = document.createElement('a')
  a.href = canvas.toDataURL('image/png')
  a.download = `网络拓扑-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, '')}.png`
  a.click()
  ElMessage.success('已导出图片')
}

/**
 * 视野与节点位置回读。
 *
 * 为什么要从 DOM 读：该库把「拖动节点后的位置」与「平移缩放状态」都放在它自己内部，没有对外事件，
 * 它的可调用配置只用于样式。好在它渲染的就是 SVG —— 每个节点外面那层 g 的 transform 就是它的世界坐标，
 * 视野那层的 transform 就是平移与缩放。读回来即可落盘位置、并在缩略图上画出「正在看哪一块」。
 */
const view = ref<{ k: number; tx: number; ty: number } | null>(null)
let tickTimer: number | undefined

function syncFromDOM(): void {
  const root = wrapEl.value?.querySelector('svg')
  if (!root) return
  const next: Record<string, { x: number; y: number }> = { ...positions.value }
  let moved = false
  // 节点位置：从我们自绘的卡片往上找一层（那一层是库给节点用的 g，它的 transform 就是世界坐标）
  root.querySelectorAll('g[data-node]').forEach((card) => {
    const id = card.getAttribute('data-node') || ''
    const m = /translate\(\s*(-?[\d.]+)[ ,]+(-?[\d.]+)\s*\)/.exec(card.parentElement?.getAttribute('transform') || '')
    if (!id || !m) return
    const x = Math.round(+m[1])
    const y = Math.round(+m[2])
    const prev = next[id]
    if (!prev || Math.abs(prev.x - x) > 1 || Math.abs(prev.y - y) > 1) {
      next[id] = { x, y }
      moved = true
    }
  })
  if (moved) positions.value = next
  // 视野：这个库把平移缩放放在 g.v-ng-viewport 上，格式是 matrix(k,0,0,k,tx,ty)
  // （世界坐标 → 屏幕坐标 = 世界 * k + t，与缩略图的换算同一套）
  const vp = root.querySelector('g.v-ng-viewport') || root.querySelector('g[transform]')
  const t = vp?.getAttribute('transform') || ''
  const mx = /matrix\(\s*(-?[\d.eE+-]+)[ ,]+(-?[\d.eE+-]+)[ ,]+(-?[\d.eE+-]+)[ ,]+(-?[\d.eE+-]+)[ ,]+(-?[\d.eE+-]+)[ ,]+(-?[\d.eE+-]+)\s*\)/.exec(t)
  if (mx) {
    view.value = { k: +mx[1] || 1, tx: +mx[5], ty: +mx[6] }
  } else {
    const tr = /translate\(\s*(-?[\d.]+)[ ,]+(-?[\d.]+)\s*\)\s*scale\(\s*([\d.]+)\s*\)/.exec(t)
    if (tr) view.value = { tx: +tr[1], ty: +tr[2], k: +tr[3] || 1 }
  }
}

function saveView(): void {
  try {
    localStorage.setItem(storeKey(), JSON.stringify({ mode: mode.value, positions: positions.value }))
  } catch {
    /* 存不下不影响使用 */
  }
}
function loadView(): void {
  try {
    const raw = localStorage.getItem(storeKey())
    if (!raw) return
    const v = JSON.parse(raw)
    if (v?.mode === 'radial' || v?.mode === 'circular' || v?.mode === 'force') mode.value = v.mode
    if (v?.positions && typeof v.positions === 'object') positions.value = v.positions
  } catch {
    /* 坏了用默认布局 */
  }
}

const kindOptions = ref<{ value: string; label: string }[]>([])

function kindLabel(v: string): string {
  return kindOptions.value.find((o) => o.value === v)?.label || v
}

/** 保存设备类型：选完立即生效（刷新拓扑），图标随即按配置绘制。 */
async function setKind(kind: string): Promise<void> {
  const ip = pinned.value?.details.find((d) => d.key === 'IP 地址')?.value || ''
  if (!ip) return
  try {
    await api.post('/device-kind', { ip, kind })
    ElMessage.success(kind ? `已记为「${kindLabel(kind)}」` : '已改回按名称自动判断')
    await load()
  } catch (e) {
    ElMessage.error((e as Error)?.message || '保存失败')
  }
}

async function load(): Promise<void> {
  loading.value = true
  try {
    graph.value = await api.get<TopologyGraph>('/topology')
    if (!kindOptions.value.length) {
      const res = await api.get<{ options: { value: string; label: string }[] }>('/device-kinds')
      kindOptions.value = res?.options || []
    }
    // 重新加载后详情卡指向的是旧对象，按 id 重新绑定，下拉里的值才跟得上
    if (pinned.value) pinned.value = nodeOf(pinned.value.id)
  } catch (e) {
    ElMessage.error((e as Error)?.message || '读取拓扑失败')
  } finally {
    loading.value = false
  }
}

/**
 * 流动动画：自己用 requestAnimationFrame 直接改边上的 strokeDashoffset。
 *
 * 为什么不用 CSS 动画/属性选择器：这个库每次重绘都会重建或覆盖边的样式，
 * 注入的 animation 会被清掉（线上表现就是「看着不动」）。直接写属性最稳。
 *
 * 口径：**有流量的线走得快**（一眼看出在传数据）、**空闲/待确认的线慢慢走**（表示线是通的），
 * 已停用的线完全静止。这样「在动」与「动得快」分得清，也不会因为一时没流量就完全看不出效果。
 */
let raf = 0
/** 每条有流量的边上放几个箭头。 */
const ARROWS_PER_EDGE = 3
/** 边 → 它上面那几个箭头（按元素记，重绘后失效的不影响）。 */
const arrowMap = new WeakMap<SVGPathElement, SVGUseElement[]>()
const SVG_NS = 'http://www.w3.org/2000/svg'

/** 箭头字形（只建一次）。 */
function ensureArrowGlyph(root: Element): void {
  if (root.querySelector('#fnwg-flow-arrow')) return
  const defs = root.querySelector('defs') || root.insertBefore(document.createElementNS(SVG_NS, 'defs'), root.firstChild)
  const g = document.createElementNS(SVG_NS, 'g')
  g.setAttribute('id', 'fnwg-flow-arrow')
  const head = document.createElementNS(SVG_NS, 'path')
  head.setAttribute('d', 'M 0 -4.5 L 9 0 L 0 4.5 z')
  head.setAttribute('fill', FLOW_COLOR)
  g.appendChild(head)
  defs.appendChild(g)
}

/** 箭头承载层：放在最上面，且不吃鼠标事件（不挡拖动与点击）。 */
function flowLayer(root: Element): SVGGElement {
  let layer = root.querySelector('#fnwg-flow-layer') as SVGGElement | null
  if (!layer) {
    layer = document.createElementNS(SVG_NS, 'g') as SVGGElement
    layer.setAttribute('id', 'fnwg-flow-layer')
    layer.setAttribute('pointer-events', 'none')
    // 必须放进这个库自己的视野层：箭头坐标取自路径的世界坐标，
    // 挂在根节点上不会跟着平移缩放走 —— 表现就是「箭头错位」。
    const vp = root.querySelector('g.v-ng-viewport')
    const host = vp || root
    host.insertBefore(layer, host.firstChild)
  }
  return layer
}

/**
 * 保证 SVG 里有一个绿色箭头标记（只建一次）。
 * 用 marker 而不是自己画三角形：挂在边的 marker-end 上，方向自然就是「从 A 到 B」，
 * 也随线的粗细自动缩放。
 */
function ensureArrow(root: Element): void {
  if (root.querySelector('#fnwg-topo-arrow')) return
  const ns = 'http://www.w3.org/2000/svg'
  const defs = root.querySelector('defs') || root.insertBefore(document.createElementNS(ns, 'defs'), root.firstChild)
  const marker = document.createElementNS(ns, 'marker')
  marker.setAttribute('id', 'fnwg-topo-arrow')
  marker.setAttribute('viewBox', '0 0 10 10')
  marker.setAttribute('refX', '9')
  marker.setAttribute('refY', '5')
  marker.setAttribute('markerWidth', '6')
  marker.setAttribute('markerHeight', '6')
  marker.setAttribute('orient', 'auto')
  const head = document.createElementNS(ns, 'path')
  head.setAttribute('d', 'M 0 0 L 10 5 L 0 10 z')
  head.setAttribute('fill', FLOW_COLOR)
  marker.appendChild(head)
  defs.appendChild(marker)
}

/**
 * 把每个设备卡片提到同级最后（SVG 的叠放顺序由 DOM 顺序决定，没有 z-index）。
 *
 * 要求是「线永远在设备下面」：库把连线与节点分层渲染，重绘后顺序还可能变，
 * 所以这里定期把节点组重新挪到末尾 —— 卡片始终压在线上面，选中高亮、变暗时也一样。
 */
function raiseNodes(): void {
  const root = wrapEl.value?.querySelector('svg')
  if (!root) return
  const parents = new Set<Element>()
  root.querySelectorAll('g[data-node]').forEach((card) => {
    const holder = card.parentElement
    if (holder?.parentElement) parents.add(holder.parentElement)
  })
  parents.forEach((parent) => {
    parent.querySelectorAll(':scope > g').forEach((g) => {
      if (g.querySelector('g[data-node]')) parent.appendChild(g)
    })
  })
}

function flowTick(): void {
  const root = wrapEl.value?.querySelector('svg')
  if (root) {
    const t = performance.now()
    ensureArrowGlyph(root)
    hideStaleArrows(root)
    root.querySelectorAll('path').forEach((node) => {
      const el = node as SVGPathElement
      const stroke = el.getAttribute('stroke') || ''
      const fast = stroke === FLOW_COLOR
      const slow = stroke === '#cbd5e1' || stroke === '#f59e0b'
      if (!fast && !slow) return
      if (!el.getAttribute('stroke-dasharray')) el.setAttribute('stroke-dasharray', fast ? '10 6' : '6 9')
      if (fast) {
        // 有流量的线：线本身静止（虚线只是样式），靠**沿线跑动的绿色箭头**表达流动与方向
        el.setAttribute('stroke-dashoffset', '0')
        driveArrows(el, t)
      } else {
        // 空闲/待确认：慢慢走的虚线（表示线是通的），不带箭头
        const period = 4200
        el.setAttribute('stroke-dashoffset', String(Math.round(((t % period) / period) * 15)))
      }
    })
  }
  raf = requestAnimationFrame(flowTick)
}

/**
 * 让一条边上的箭头沿线跑起来。
 *
 * 用 SVG 自己的 getPointAtLength/getTotalLength 取点，再按切线角度旋转 ——
 * 这样箭头严格贴着线走（包括直连与曲线），方向就是「从源到目的」。
 */
function driveArrows(el: SVGPathElement, t: number): void {
  const root = wrapEl.value?.querySelector('svg')
  if (!root) return
  const layer = flowLayer(root)
  let uses = arrowMap.get(el)
  if (!uses || uses.some((u) => !u.isConnected)) {
    uses = Array.from({ length: ARROWS_PER_EDGE }, () => {
      const u = document.createElementNS(SVG_NS, 'use') as SVGUseElement
      u.setAttribute('href', '#fnwg-flow-arrow')
      layer.appendChild(u)
      return u
    })
    arrowMap.set(el, uses)
  }
  const len = el.getTotalLength()
  if (!len) return
  const cycle = 2200 // 一个箭头跑完全程的毫秒数
  const base = ((t % cycle) / cycle) * len
  uses.forEach((u, i) => {
    const pos = (base + (i * len) / ARROWS_PER_EDGE) % len
    const p1 = el.getPointAtLength(pos)
    const p2 = el.getPointAtLength(Math.min(len, pos + 1.5))
    const ang = (Math.atan2(p2.y - p1.y, p2.x - p1.x) * 180) / Math.PI
    u.setAttribute('transform', `translate(${p1.x.toFixed(1)},${p1.y.toFixed(1)}) rotate(${ang.toFixed(1)})`)
    u.removeAttribute('display')
  })
}

/** 不再有流量的边：把它的箭头收起来（元素留着复用，省得每帧重建）。 */
function hideStaleArrows(root: Element): void {
  root.querySelectorAll('path').forEach((node) => {
    const el = node as SVGPathElement
    if (el.getAttribute('stroke') === FLOW_COLOR) return
    const uses = arrowMap.get(el)
    if (uses) uses.forEach((u) => u.setAttribute('display', 'none'))
  })
}

function closeMenu(): void {
  menu.value = null
}

onMounted(() => {
  loadView()
  load()
  window.addEventListener('click', closeMenu)

  // 每 1.5 秒轻量回读一次：拖动与平移不会发事件，只能这样拿（开销很小）
  tickTimer = window.setInterval(() => {
    syncFromDOM()
    raiseNodes()
    saveView()
  }, 1500)
  raf = requestAnimationFrame(flowTick)
})

onBeforeUnmount(() => {
  window.removeEventListener('click', closeMenu)
  if (tickTimer) window.clearInterval(tickTimer)
  if (raf) cancelAnimationFrame(raf)
  syncFromDOM()
  saveView()
})
</script>

<style scoped>
.fnwg-topo-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-left: auto;
  justify-content: flex-end;
}
.fnwg-topo :deep(.fnwg-card-head) {
  display: flex;
  align-items: flex-start;
  gap: 12px;
}

.fnwg-topo :deep(.fnwg-card-head > div:first-child) {
  flex: 1;
  min-width: 0;
}

@media (max-width: 767px) {
  .fnwg-topo-below {
    flex-direction: column-reverse;
  }

  .fnwg-topo-mini {
    flex: 0 0 auto;
    width: 100%;
  }

  .fnwg-topo :deep(.fnwg-card-head) {
    flex-direction: column;
  }

  .fnwg-topo-actions {
    margin-left: 0;
    justify-content: flex-start;
  }
}


.fnwg-topo-wrap {
  position: relative;
  width: 100%;
}

   这段样式在运行时注入（见 onMounted 里的 FLOW_CSS）：属性选择器里带 # 会让 SFC 的 CSS 解析器报错，

.fnwg-vng {
  width: 100%;
}

.fnwg-topo-below {
  display: flex;
  align-items: flex-start;
  gap: 12px;
  margin-top: 8px;
}

.fnwg-topo-legend {
  display: flex;
  flex: 1;
  flex-wrap: wrap;
  gap: 6px 16px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.fnwg-topo-legend span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

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
  border-top: 2px solid #22c55e;
}

.fnwg-topo-legend-line.off {
  border-top-style: dashed;
  border-top-color: #94a3b8;
}

.fnwg-topo-tip {
  position: absolute;
  z-index: 11;
  max-width: 320px;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow-light);
  font-size: 12.5px;
  line-height: 1.7;
  pointer-events: none;
}

.fnwg-topo-tip-sub {
  display: block;
  color: var(--el-text-color-secondary);
  font-size: 11.5px;
}

.fnwg-topo-tip-row {
  display: flex;
  gap: 8px;
  margin-top: 3px;
}

.fnwg-topo-tip-key {
  flex: 0 0 66px;
  color: var(--el-text-color-secondary);
}

.fnwg-topo-tip-val {
  flex: 1;
  word-break: break-word;
}

.fnwg-topo-tip-foot {
  margin-top: 6px;
  color: var(--el-text-color-secondary);
  font-size: 11.5px;
}

.fnwg-topo-panel {
  position: absolute;
  left: 6px;
  top: 6px;
  z-index: 11;
  width: 300px;
  max-height: 60%;
  overflow: auto;
  padding: 8px 10px;
  border: 1px solid var(--el-border-color);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow-light);
  font-size: 12.5px;
  line-height: 1.7;
}

.fnwg-topo-panel-head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 10px;
  margin-bottom: 4px;
}

.fnwg-topo-kind {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 10px;
  font-size: 12.5px;
  color: var(--el-text-color-secondary);
}

.fnwg-topo-panel-foot {
  display: flex;
  gap: 8px;
  margin-top: 8px;
}

.fnwg-topo-mini {
  position: relative;
  flex: 0 0 170px;
  width: 170px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: var(--fnwg-radius);
  background: var(--fnwg-card);
  box-shadow: var(--el-box-shadow-light);
  opacity: 0.92;
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

.fnwg-topo-mini-view {
  fill: rgba(64, 158, 255, 0.12);
  stroke: var(--el-color-primary);
  stroke-width: 1;
}

.fnwg-topo-mini-line {
  stroke: var(--el-border-color-lighter);
  stroke-width: 0.8;
}

.fnwg-topo-mini circle {
  fill: var(--el-text-color-disabled);
}

.fnwg-topo-mini circle.k-nas,
.fnwg-topo-mini circle.k-device {
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

.fnwg-topo-notes {
  margin-top: 8px;
}

.fnwg-topo-link {
  color: var(--el-color-primary);
  cursor: pointer;
}
</style>
