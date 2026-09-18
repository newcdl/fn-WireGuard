// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 newcdl <newcdl@163.com>

/**
 * 复制文本到剪贴板，返回是否成功。
 *
 * 为什么不能只用 navigator.clipboard：那是**安全上下文**才有的 API —— 只有 HTTPS
 * 或 localhost 才会把它暴露出来。而本应用最常见的访问方式是「局域网 IP + 端口」，
 * 那是 http，`navigator.clipboard` 直接是 undefined，于是复制按钮只会回一句
 * 「浏览器拒绝了剪贴板访问」—— 恰恰在用户最需要复制（把安全码存下来）的场景失效。
 *
 * 所以这里保留一条退路：document.execCommand('copy')。它虽已标记废弃，
 * 但在非安全上下文里依然有效，且同样必须由用户点击触发，不会绕过任何权限。
 *
 * 失败时返回 false 而不是抛错：调用方更清楚该传达什么（安全码那里会顺手替用户选中文本），
 * 而且这条路径本来就有「复制不了就手动选」的正当出口，不该当成异常。
 */
export async function copyText(text: string): Promise<boolean> {
  // 优先用标准 API：它不受页面滚动与选区影响，成功与否也不会误伤用户当前的选中内容
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch {
      // API 在也可能被拒（文档未聚焦、权限被策略拦下），继续走退路
    }
  }
  return legacyCopy(text)
}

/** 退路：借一个临时 textarea 走浏览器原生的复制命令。 */
function legacyCopy(text: string): boolean {
  const ta = document.createElement('textarea')
  ta.value = text
  ta.setAttribute('readonly', '')
  // 位置固定在视口内但不可见：为 0 尺寸或移出视口的元素，部分浏览器会忽略选区导致复制出空内容
  ta.style.position = 'fixed'
  ta.style.top = '0'
  ta.style.left = '0'
  ta.style.width = '1px'
  ta.style.height = '1px'
  ta.style.padding = '0'
  ta.style.border = 'none'
  ta.style.opacity = '0'
  document.body.appendChild(ta)

  // 记下用户原本的选区，复制完还回去：这次点击不该顺手毁掉他在别处选中的内容
  const selection = document.getSelection()
  const prevRange = selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null

  let ok = false
  try {
    ta.select()
    ta.setSelectionRange(0, text.length)
    ok = document.execCommand('copy')
  } catch {
    ok = false
  }

  document.body.removeChild(ta)
  if (prevRange && selection) {
    selection.removeAllRanges()
    selection.addRange(prevRange)
  }
  return ok
}
