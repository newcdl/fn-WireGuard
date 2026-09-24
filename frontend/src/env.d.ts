// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

/// <reference types="vite/client" />

// Vite 的 ?inline 后缀：把资源在构建期内联成 data URI。
// 二维码中心的应用图标必须走这条路 —— 运行时去 fetch 一个资源路径，
// 在飞牛的子路径部署下可能取不到（取不到的表现是二维码中心留一块空白）。
declare module '*.png?inline' {
  const src: string
  export default src
}

declare module '*.vue' {
  import type { DefineComponent } from 'vue'
  const component: DefineComponent<{}, {}, any>
  export default component
}
