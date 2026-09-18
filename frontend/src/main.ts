// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import zhCn from 'element-plus/es/locale/lang/zh-cn'
import * as Icons from '@element-plus/icons-vue'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'

import App from './App.vue'
import router from './router'
import { initTheme } from './composables/useTheme'
import './styles/main.css'

const app = createApp(App)
app.use(createPinia())
app.use(router)
app.use(ElementPlus, { locale: zhCn })
for (const [name, comp] of Object.entries(Icons)) {
  app.component(name, comp as never)
}

// 外观：用户选定浅色/深色/跟随系统，未选过时跟随系统（应用内嵌在 fnOS 桌面窗口中时，
// 系统的深浅色就是桌面的深浅色）。偏好的应用与系统订阅都在 useTheme 里，见其注释。
initTheme()

app.mount('#app')
