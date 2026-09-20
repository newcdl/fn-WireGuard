// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 小柿子 <newxsz@163.com>

/**
 * 带样式的二维码：深色模块画成圆点，中心留一块底放应用图标（企业微信那种观感）。
 *
 * 为什么不是直接给 `qrcode` 传个参数：那个库只出方块码。这里用 `QRCode.create()`
 * 取到**模块矩阵**（0/1 的二维数据），自己画成 SVG —— 圆点、定位角、中心图标都好控制，
 * 也不用为了样式再引一个依赖。
 *
 * 三个不能省的约束（都是扫不出来的直接原因）：
 *  1. **纠错等级必须是 H（约 30%）**：中心图标盖住的模块靠纠错补回来，等级低一点就报废；
 *  2. **三个定位角保持方形（圆角矩形）**：定位角是扫码器最先找的东西，跟着变成圆点会明显变难找；
 *  3. **永远是白底深色模块**，不跟随深色主题反色 —— 反色的二维码多数扫码器不认。
 * 另外中心图标控制在整幅的 20% 以内，并衬一块白色圆角底、四周留白，避免与深色模块连成一片。
 */
import QRCode from 'qrcode'
import iconInline from '@/assets/app-icon.png?inline'

const DARK = '#111111'
const LIGHT = '#ffffff'
/** 静默区：规范要求四周至少留 4 个模块，少了扫码器会找不到边界 */
const QUIET = 4
/**
 * 「稀疏码」的模块数上限：超过它就算数据密的码，中心图标要多留一圈白。
 *
 * 数据越大 → 模块越多 → 纠错余量被摊得越薄，中心一块带细节的标记就越容易被解码器**当成数据读**，
 * 读错整张就废。所以密碼的中心必须多留一圈白（白色会被当成「污损」交给纠错去补）。
 * 两个数都是量出来的（Chrome 内置条码识别，720/1080px 双尺寸）：
 *   - 69×69 模块（绑定二次验证，199 字符）：图标 7~10 个模块 + **一圈**白，都能解；
 *   - 93×93 模块（设备配置 336 字符、带 image 的绑定码 341 字符）：**一圈白解不出来**，
 *     换成「15 模块白底 + 11 模块图标」（即两圈白）就能解 —— 多留的这一圈就是能否扫出来的分界。
 */
const LOGO_SPARSE_MAX_MODULES = 75
/** 图标边长占二维码边长的比例：稀疏码可以大一点，密碼要收一点（把余量让给白圈） */
const LOGO_SIDE_RATIO_SPARSE = 0.16
const LOGO_SIDE_RATIO_DENSE = 0.12
/** 图标模块数上限：量过的最大安全值分别是一圈白下的 10、两圈白下的 11 */
const LOGO_MAX_ICON_SPARSE = 10
const LOGO_MAX_ICON_DENSE = 11
/** 图标四周的白色留白（模块数）：稀疏码一圈（多数带图标二维码的紧凑观感），密碼两圈 */
const LOGO_MARGIN_SPARSE = 1
const LOGO_MARGIN_DENSE = 2
/** 图标本体的模块数下限，太小的图标等于没有 */
const LOGO_MIN_MODULES = 6

/**
 * 圆点半径（以模块为单位）：0.5 表示点与点正好相接。
 *
 * 这个数是**量出来的**：0.46 这种「留一点缝」的写法看着更像点，但它处在临界上 ——
 * 同一张码在 720px 下解得出来、换到 1080px 就解不出来了（解码器的采样网格随分辨率变），
 * 而真实场景里二维码的显示尺寸本来就五花八门。0.5 在两种尺寸下都稳定，
 * 视觉上仍是圆点（只在四个角留出小缺口），不跟可识别性赌运气。
 */
const DOT_RADIUS = 0.5

let iconCache: Promise<string> | null = null

/**
 * 应用图标（先缩到实际用得到的像素），返回可直接内联进 SVG 的 data URI；
 * 取不到时返回空串，调用方会**完全不画中心图标**。
 *
 * 两处细节都是踩出来的：
 *  1. 图标走 `?inline` 在**构建期**变成 data URI，不在运行时去 fetch 资源路径 ——
 *     子路径部署下取不到时，中心会只剩一块白（比没有图标更难看，也更让人以为坏了）；
 *  2. 必须**先缩放到接近实际显示的尺寸**：原图 192px 直接内联，降采样后边缘发虚，
 *     解码器在图标边缘二值化时会连错模块 —— 实测同一张二维码，只删掉中心那行
 *     `<image>` 就能解、留着就解不出来。
 * 用 canvas 重新编码一次，顺带把图标统一成方形 PNG，省得受原图格式影响。
 */
async function iconDataUri(): Promise<string> {
  if (!iconCache) {
    iconCache = new Promise<string>((resolve) => {
      if (!iconInline) return resolve('')
      const img = new Image()
      img.onload = () => {
        try {
          const side = 96 // 比实际显示（几十像素）大一档，缩小时仍然锐利
          const c = document.createElement('canvas')
          c.width = side
          c.height = side
          const ctx = c.getContext('2d')
          if (!ctx) return resolve('')
          ctx.imageSmoothingQuality = 'high'
          ctx.drawImage(img, 0, 0, side, side)
          resolve(c.toDataURL('image/png'))
        } catch {
          resolve('')
        }
      }
      img.onerror = () => resolve('')
      img.src = iconInline
    })
  }
  return iconCache
}

/** 三个定位角的位置：左上、右上、左下（各 7×7 模块）。 */
function isFinder(row: number, col: number, size: number): boolean {
  const inTL = row < 7 && col < 7
  const inTR = row < 7 && col >= size - 7
  const inBL = row >= size - 7 && col < 7
  return inTL || inTR || inBL
}

/**
 * 定位角（三个角上的 7×7 回字）。
 *
 * 这里必须是标准的 1:1:3:1:1 明暗比例：外圈 1 个模块、浅色环 1 个、中心 3 个。
 * 曾经用「6×6 描边矩形」画外圈，看起来一样，实际浅色环只剩半个模块，
 * 比例变成 1:0.5:3:0.5:1 —— 扫码器找不到定位角，连最朴素的方块码都解不出来。
 * 画法因此改成三块实心矩形逐层收窄（圆角也逐层收，环的宽度才均匀）。
 */
function finderSvg(row: number, col: number): string {
  // 传进来的是**模块坐标**，落笔时要加上静默区偏移 ——
  // 漏掉它，三个定位角会被画到画布左上角，真正该有定位角的地方一片空白，
  // 于是整张码看上去完好无损、扫码器却一个都找不到（真机上就是这种表现）。
  const x = QUIET + col
  const y = QUIET + row
  return (
    `<rect x="${x}" y="${y}" width="7" height="7" rx="1.6" fill="${DARK}"/>` +
    `<rect x="${x + 1}" y="${y + 1}" width="5" height="5" rx="1.1" fill="${LIGHT}"/>` +
    `<rect x="${x + 2}" y="${y + 2}" width="3" height="3" rx="0.7" fill="${DARK}"/>`
  )
}

/**
 * 生成带样式的二维码（返回可直接喂给 `<img src>` 的 data URI）。
 *
 * @param text 二维码内容（设备配置、TOTP 的 otpauth URI 等）
 * @param px   期望的像素尺寸；SVG 本身是矢量，这里只决定 viewBox 的粒度
 */
export async function styledQrDataUrl(text: string, px = 480): Promise<string> {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'H' })
  const size = qr.modules.size
  const data = qr.modules.data
  const total = size + QUIET * 2

  // 中心图标始终画（用户要求「不管怎么样都有图标」）：数据密的码多留一圈白来换可识别性。
  // 只有图标本身取不到时不画 —— 那时既不铺白块也不跳过模块，跳过而不画会留下一个空洞。
  const icon = await iconDataUri()
  const dense = size > LOGO_SPARSE_MAX_MODULES
  const margin = dense ? LOGO_MARGIN_DENSE : LOGO_MARGIN_SPARSE
  const iconCap = dense ? LOGO_MAX_ICON_DENSE : LOGO_MAX_ICON_SPARSE
  const ratio = dense ? LOGO_SIDE_RATIO_DENSE : LOGO_SIDE_RATIO_SPARSE
  const iconModules = icon
    ? Math.min(iconCap, Math.max(LOGO_MIN_MODULES, Math.round(size * ratio)))
    : 0
  const logoModules = iconModules ? iconModules + margin * 2 : 0
  const logoStart = logoModules ? Math.floor((size - logoModules) / 2) : -1
  const inLogo = (row: number, col: number) =>
    logoModules > 0 &&
    row >= logoStart &&
    row < logoStart + logoModules &&
    col >= logoStart &&
    col < logoStart + logoModules

  let body = ''
  for (let row = 0; row < size; row++) {
    for (let col = 0; col < size; col++) {
      if (!data[row * size + col]) continue
      if (isFinder(row, col, size)) continue
      if (inLogo(row, col)) continue
      const cx = (QUIET + col + 0.5).toFixed(2)
      const cy = (QUIET + row + 0.5).toFixed(2)
      body += `<circle cx="${cx}" cy="${cy}" r="${DOT_RADIUS}"/>`
    }
  }

  // 图标底衬白色圆角块并留白：深色模块与图标之间没有过渡，连在一起就扫不出来
  // 白底 = 图标 + 一圈留白；那一圈白是留给解码器的过渡区，不是审美留白
  const tileSize = logoModules
  const tileX = QUIET + logoStart
  const markSize = iconModules
  const markInset = margin
  const logo = icon
    ? `<rect x="${tileX}" y="${tileX}" width="${tileSize}" height="${tileSize}" rx="1.4" fill="${LIGHT}"/>` +
      `<image x="${(QUIET + logoStart + markInset).toFixed(2)}" y="${(QUIET + logoStart + markInset).toFixed(2)}" ` +
      `width="${markSize.toFixed(2)}" height="${markSize.toFixed(2)}" href="${icon}" preserveAspectRatio="xMidYMid meet"/>`
    : ''

  const svg =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${total} ${total}" width="${px}" height="${px}" ` +
    `shape-rendering="geometricPrecision">` +
    `<rect width="${total}" height="${total}" fill="${LIGHT}"/>` +
    `<g fill="${DARK}">${body}</g>` +
    finderSvg(0, 0) +
    finderSvg(0, size - 7) +
    finderSvg(size - 7, 0) +
    logo +
    `</svg>`

  // 用 encodeURIComponent 而不是 btoa：SVG 里是中文与 base64 图标，btoa 会直接报错
  return `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`
}
