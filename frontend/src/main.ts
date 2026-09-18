// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import * as Icons from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

import App from './App.vue'
import router from './router'
import './styles/main.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(ElementPlus, { locale: zhCn })
for (const [name, comp] of Object.entries(Icons)) {
  app.component(name, comp as never)
}

// 跟随 fnOS 桌面的深浅色主题（应用以 iframe 形式内嵌在桌面窗口中）
function syncTheme() {
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches
  const html = document.documentElement
  html.classList.toggle('dark', prefersDark)
}
syncTheme()
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', syncTheme)

app.mount('#app')
