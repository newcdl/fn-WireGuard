<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
  敏感操作前的二次验证（step-up）。

  它只会在「以飞牛账号登录」的身份上出现：那种身份没有在登录时输过本应用的口令，
  所以做敏感操作前再确认一次是本人。用账号密码从端口进入时不会弹这个框 ——
  登录本身就是一次凭据校验，而且那是用户被自己开的开关挡住时的退路。
-->
<template>
  <el-dialog
    :model-value="modelValue"
    title="再验证一次身份"
    :width="dialogWidth || '420px'"
    :close-on-click-modal="false"
    @update:model-value="onToggle"
  >
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
      <template #title>
        这一步属于敏感操作（会看到密钥、会覆盖数据或改动账号）。当前身份来自飞牛账号，
        请再输入一次本应用动态口令以确认是本人操作；验证后 10 分钟内不必重复输入。
      </template>
    </el-alert>

    <el-form class="fnwg-form" label-position="top" @submit.prevent="submit">
      <el-form-item label="动态口令">
        <el-input
          v-model="code"
          maxlength="6"
          placeholder="验证器 App 里显示的 6 位数字"
          @keyup.enter="submit"
        />
      </el-form-item>
    </el-form>

    <el-alert v-if="error" type="error" :closable="false" show-icon :title="error" />

    <template #footer>
      <el-button @click="onToggle(false)">取消</el-button>
      <el-button type="primary" :loading="busy" @click="submit">验证</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { api } from '@/api/client'
import { useBreakpoint } from '@/composables/useBreakpoint'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{
  (e: 'update:modelValue', v: boolean): void
  /** 验证结果：true = 已通过，调用方（请求层）可以重放原请求。 */
  (e: 'done', ok: boolean): void
}>()

const { dialogWidth } = useBreakpoint()

const code = ref('')
const busy = ref(false)
const error = ref('')

// 每次打开都清空上一次的输入与错误：留着上次的失败信息会让人以为这次也失败
watch(
  () => props.modelValue,
  (v) => {
    if (v) {
      code.value = ''
      error.value = ''
    }
  },
)

function onToggle(v: boolean): void {
  emit('update:modelValue', v)
  if (!v) emit('done', false)
}

async function submit(): Promise<void> {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    await api.post('/auth/step-up', { code: code.value })
    emit('update:modelValue', false)
    emit('done', true)
  } catch (e) {
    // 例如「这个账号还没有绑定动态口令，请先绑定一次」：原样显示，让人知道下一步该做什么
    error.value = (e as Error).message
  } finally {
    busy.value = false
  }
}
</script>
