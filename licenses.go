// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

// Package fnwg 提供模块级的许可证文本，供「系统设置 → 关于 → 开源许可」展示。
//
// 为什么放在模块根目录、并且内嵌根目录的那两个文件本身：许可证正文一旦复制到别处，
// 迟早会出现「界面里显示的许可」与「仓库里那一份」不一致 —— 而合规文件里
// 最不该有的就是这种不一致。内嵌而不是运行时读磁盘，则是因为安装包里只有 apps 侧
// 的那一份（COPYING），从磁盘读会让「装了什么、显示什么」取决于运行环境。
package fnwg

import _ "embed"

// GPLText 是 GNU 通用公共许可证第 3 版的全文（= 根目录 LICENSE）。
//
//go:embed LICENSE
var GPLText string

// ThirdPartyLicenses 是第三方组件与许可证清单，含各组件逐字原文
// （= 根目录 THIRD_PARTY_LICENSES.md，由依赖枚举自动生成）。
//
//go:embed THIRD_PARTY_LICENSES.md
var ThirdPartyLicenses string
