<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div class="sc-block">
    <code ref="codeEl" class="sc-code">{{ grouped }}</code>
    <div class="sc-actions">
      <el-button size="small" @click="copy">{{ copied ? '已复制' : '复制安全码' }}</el-button>
      <el-button size="small" @click="download">下载为文本</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { copyText } from '@/utils/clipboard'

const props = defineProps<{ code: string }>()

const copied = ref(false)
const codeEl = ref<HTMLElement | null>(null)

/** 每 5 个字符分组，52 个字符的长串这样才好核对与抄录。 */
const grouped = computed(() => props.code.match(/.{1,5}/g)?.join('-') || props.code)

/**
 * 复制安全码。
 *
 * 复制的是**屏幕上那一串**（带分组连字符），而不是内部存的裸串：两边不一致时，
 * 用户会怀疑「是不是漏了几位」「复制残了」——而这个码是要被抄到纸上、存进密码管理器的，
 * 对不上就得回头找原因。输入侧本来就会忽略连字符与大小写（见后端 NormalizeSecurityCode），
 * 所以带上分组没有任何副作用，只是让「看到的」与「拿到的」一致。
 */
async function copy() {
  if (await copyText(grouped.value)) {
    copied.value = true
    ElMessage.success('已复制到剪贴板')
    return
  }
  // 自动复制不可用时不留一句「请手动选择」就完事：替用户选中，他按一下 Ctrl/⌘ + C 即可。
  selectCode()
  ElMessage.warning('当前访问方式下浏览器不允许自动复制，已为你选中，请按 Ctrl/⌘ + C')
}

/** 选中安全码文本，供用户手动复制。 */
function selectCode() {
  const el = codeEl.value
  if (!el) return
  const range = document.createRange()
  range.selectNodeContents(el)
  const selection = window.getSelection()
  selection?.removeAllRanges()
  selection?.addRange(range)
}

/**
 * 下载成文本文件。
 *
 * 刻意带上用途说明与「只能用一次」的提醒：这个文件多半会被放进密码管理器或某个文件夹，
 * 光秃秃一串字符过几个月就没人知道它是干什么的了。
 */
function download() {
  const text = [
    'WireGuard 管理工具 · 应急安全码',
    '',
    grouped.value,
    '',
    '用途：当管理员忘记登录密码、手机丢失且恢复码也遗失、或界面根本打不开时，',
    '在登录页点击「应急登录」并输入它，即可进入并把控制权收回来。',
    '输入时连字符、空格与大小写都可以忽略，怎么方便怎么抄。',
    '',
    '注意：',
    '1. 只能使用一次。用过之后系统会立即作废它并下发新的一码，并强制你保存；',
    '2. 请离线保存（密码管理器或纸质），不要截图转发、不要上传网盘；',
    '3. 系统只保存它的哈希，明文无法再次查看，我们也无法帮你找回。',
    '',
  ].join('\n')
  const blob = new Blob([text], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'fnwg-security-code.txt'
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
</script>

<style scoped>
.sc-block {
  border: 1px solid var(--fnwg-border);
  border-radius: 8px;
  padding: 12px;
  background: var(--el-fill-color-light);
}
.sc-code {
  display: block;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: 0.5px;
  line-height: 1.9;
  word-break: break-all;
  user-select: all;
}
.sc-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}
</style>
