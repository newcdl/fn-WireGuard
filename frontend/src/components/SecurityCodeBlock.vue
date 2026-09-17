<template>
  <div class="sc-block">
    <code class="sc-code">{{ grouped }}</code>
    <div class="sc-actions">
      <el-button size="small" @click="copy">{{ copied ? '已复制' : '复制安全码' }}</el-button>
      <el-button size="small" @click="download">下载为文本</el-button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue'
import { ElMessage } from 'element-plus'

const props = defineProps<{ code: string }>()

const copied = ref(false)

/** 每 5 个字符分组，52 个字符的长串这样才好核对与抄录。 */
const grouped = computed(() => props.code.match(/.{1,5}/g)?.join('-') || props.code)

async function copy() {
  try {
    await navigator.clipboard.writeText(props.code)
    copied.value = true
    ElMessage.success('已复制到剪贴板')
  } catch {
    ElMessage.warning('浏览器拒绝了剪贴板访问，请手动选择复制')
  }
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
    props.code,
    '',
    '用途：当管理员忘记登录密码、手机丢失且恢复码也遗失、或飞牛网关异常导致界面进不去时，',
    '在登录页点击「应急登录」并输入它，即可进入并把控制权收回来。',
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
