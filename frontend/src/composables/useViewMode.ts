// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { computed, ref } from 'vue'
import { useBreakpoint } from '@/composables/useBreakpoint'

/** 列表的两种呈现方式：表格（一行一条、适合横着比）/ 卡片（一条一块、适合看单条详情）。 */
export type ListViewMode = 'table' | 'cards'

/**
 * 列表的「表格 / 卡片」视图偏好。
 *
 * 为什么要有它：同一个列表，有人习惯表格（一屏几十行、字段能对齐着比），有人习惯卡片
 * （字段分组清楚、手机上不用左右滚）。与其替用户决定，不如让他自己切；切完记住，下次进来还是他选的那种。
 *
 * 默认值按屏幕给：手机默认卡片（表格在 390px 宽里根本看不全）、桌面默认表格 —— 与加开关之前各页的
 * 行为**完全一致**，所以这个功能不会改变任何既有习惯，只是多给了一个选择。
 *
 * @param key 每个列表一个键。同一页有多个列表时必须各用各的，否则切一个会连带另一个。
 */
export function useViewMode(key: string) {
  const { isMobile } = useBreakpoint()
  const STORE = `fnwg.view.${key}`

  /** 读偏好：读不到（首次访问、隐私模式禁了本地存储）就按屏幕给默认值，绝不报错打扰用户。 */
  function read(): ListViewMode | null {
    try {
      const v = localStorage.getItem(STORE)
      return v === 'table' || v === 'cards' ? v : null
    } catch {
      return null
    }
  }

  const current = ref<ListViewMode>(read() ?? (isMobile.value ? 'cards' : 'table'))

  function setMode(next: ListViewMode): void {
    current.value = next
    try {
      localStorage.setItem(STORE, next)
    } catch {
      /* 存不下不影响本次使用 */
    }
  }

  /*
   * 对外给的是**可写 computed**：页面里写的是 `v-model="mode"`，而 v-model 会直接给 ref 赋值 ——
   * 那样就绕过了 setMode，偏好永远写不进本地存储（线上表现是「切了、刷新又变回去」）。
   * 包一层 get/set 之后，任何写法都会经过 setMode。这是这一处唯一的坑，特此记下原因。
   */
  const mode = computed<ListViewMode>({
    get: () => current.value,
    set: (next) => setMode(next),
  })

  return {
    mode,
    setMode,
    /**
     * 表格视图：页面里用在原来 `v-if="!isMobile"` 的位置，卡片那支保持 `v-else` 不动 ——
     * 这样两种视图一定互斥，也不会出现「两个都不显示」的空档。
     */
    isTable: computed(() => mode.value === 'table'),
    isCards: computed(() => mode.value === 'cards'),
  }
}
