// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

import { computed, ref } from 'vue'

/** 外观偏好：浅色 / 深色 / 跟随系统。 */
export type ThemeMode = 'light' | 'dark' | 'system'

/**
 * 存放外观偏好的位置。
 *
 * 只存在浏览器本地，不上报服务端：它描述的是「这个人这台设备看起来舒服」，
 * 而不是任何一条系统配置 —— 同一台 NAS 上的不同设备、不同人各选各的才合理，
 * 也免得换个人登录就被别人的偏好套住。
 */
const STORAGE_KEY = 'fnwg-theme'

function readStored(): ThemeMode {
  if (typeof localStorage === 'undefined') return 'system'
  try {
    const v = localStorage.getItem(STORAGE_KEY)
    if (v === 'light' || v === 'dark' || v === 'system') return v
  } catch {
    // 隐私模式等场景下读取会抛错：不影响使用，按「跟随系统」处理
  }
  return 'system'
}

const mode = ref<ThemeMode>(readStored())
/** 系统当前是否偏爱深色（「跟随系统」时以它为准）。 */
const systemDark = ref(false)

/** 当前实际生效的是不是深色 —— 界面上真正要看的是它，不是 mode。 */
const isDark = computed(() => (mode.value === 'system' ? systemDark.value : mode.value === 'dark'))

/**
 * 把当前应生效的外观写到 <html> 上。
 *
 * 用 class 而不是直接改 CSS 变量：Element Plus 的深色变量整包挂在 `html.dark` 下，
 * 本应用自己的 `--fnwg-*` 也照此组织（见 styles/main.css），一处切换全局生效。
 */
function apply() {
  if (typeof document === 'undefined') return
  const html = document.documentElement
  html.classList.toggle('dark', isDark.value)
  // color-scheme 让浏览器自己的东西也跟上：滚动条、下拉的原生控件、
  // 输入法候选框、以及深色下不应自动变白的表单控件。
  html.style.colorScheme = isDark.value ? 'dark' : 'light'
}

/** 切换外观偏好并记住它。 */
export function setThemeMode(next: ThemeMode) {
  mode.value = next
  try {
    localStorage.setItem(STORAGE_KEY, next)
  } catch {
    // 存不下只是下次打开会退回默认值，本次切换照常生效
  }
  apply()
}

/**
 * 由 main.ts 在挂载前调用一次：应用已保存的偏好，并订阅系统主题变化。
 *
 * 订阅不区分当前是不是「跟随系统」：用户可能在系统切过主题之后才选「跟随系统」，
 * 那时如果没订阅，界面会一直用着过期的判断，直到他再去改一次系统设置。
 */
export function initTheme() {
  if (typeof window === 'undefined') return
  const mq = window.matchMedia('(prefers-color-scheme: dark)')
  systemDark.value = mq.matches
  apply()
  mq.addEventListener('change', (e) => {
    systemDark.value = e.matches
    apply()
  })
}

export function useTheme() {
  return { mode, isDark, setMode: setThemeMode }
}
