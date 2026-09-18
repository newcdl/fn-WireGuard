<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <el-dialog
    :model-value="modelValue"
    :title="`为「${userName}」开启二次验证`"
    :width="dialogWidth || '560px'"
    @update:model-value="onToggle"
  >
    <div v-loading="busy">
      <el-alert v-if="loadError" type="error" :closable="false" show-icon :title="loadError" />

      <!-- 第一步：生成绑定信息，交给账号主人扫 -->
      <template v-else-if="!recoveryCodes.length">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 14px">
          <template #title>
            把二维码交给账号主人，让他用自己的验证器 App 扫；扫完他读出 6 位动态口令，
            你填在下面即可完成绑定。全程不需要知道对方的密码。
          </template>
        </el-alert>
        <div class="fnwg-hint" style="margin-bottom: 10px">
          用验证器 App 扫描下面的二维码；扫不了就手动输入右侧的密钥。
        </div>
        <div class="tfa-bind">
          <img v-if="qr" :src="qr" class="tfa-qr" alt="二次验证二维码" />
          <div class="tfa-secret">
            <div style="font-size: 12px; opacity: 0.65; margin-bottom: 4px">手动输入用的密钥</div>
            <code class="tfa-secret-text">{{ secret }}</code>
            <el-button size="small" style="margin-top: 8px" @click="copy(secret)">复制密钥</el-button>
          </div>
        </div>
        <el-form class="fnwg-form" label-position="top" style="margin-top: 14px">
          <el-form-item label="验证器里显示的 6 位数字">
            <el-input v-model="code" placeholder="由账号主人读给你" @keyup.enter="confirm" />
          </el-form-item>
        </el-form>
        <el-alert type="warning" :closable="false" show-icon>
          <template #title>
            这一步不能跳过：只有用当前口令验证过一次，才能确认对方的验证器真的绑上了。
            否则生成了密钥却没绑成功，账号主人下次登录会被锁在门外。
          </template>
        </el-alert>
      </template>

      <!-- 第二步：一次性恢复码，转交给账号主人 -->
      <template v-else>
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            请把下面的恢复码交给账号主人保存。它们只显示这一次，之后任何人都无法再取回
            （服务端只存哈希，连管理员和备份文件里都没有明文）。
          </template>
        </el-alert>
        <div class="fnwg-hint" style="margin-bottom: 10px">
          手机丢失或换机时，用其中任意一枚即可登录（每枚只能用一次）。
        </div>
        <div class="tfa-codes">
          <code v-for="c in recoveryCodes" :key="c">{{ c }}</code>
        </div>
        <el-button style="margin-top: 12px" @click="copy(recoveryCodes.join('\n'))">
          复制全部恢复码
        </el-button>
      </template>
    </div>

    <template #footer>
      <!-- 恢复码只此一次，必须由管理员主动确认已转交 -->
      <template v-if="recoveryCodes.length">
        <el-button type="primary" @click="close">我已转交，完成</el-button>
      </template>
      <template v-else>
        <el-button @click="close">取消</el-button>
        <el-button type="primary" :loading="busy" :disabled="!qr" @click="confirm">确认开启</el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import QRCode from 'qrcode'
import { api } from '@/api/client'
import type { TOTPSetup } from '@/api/types'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { copyText } from '@/utils/clipboard'

const props = defineProps<{ modelValue: boolean; userId: number; userName: string }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; done: [] }>()

const { dialogWidth } = useBreakpoint()

const busy = ref(false)
const loadError = ref('')
const secret = ref('')
const qr = ref('')
const code = ref('')
const recoveryCodes = ref<string[]>([])

watch(
  () => props.modelValue,
  (open) => {
    if (open) void start()
  },
)

function onToggle(v: boolean) {
  if (!v) close()
}

/**
 * 打开即生成一份新的绑定信息。
 * 此时尚未落库、更未生效，所以直接关掉对话框不会在账号上留下任何痕迹 ——
 * 半途而废的绑定不会把对方锁在门外。
 */
async function start() {
  secret.value = ''
  qr.value = ''
  code.value = ''
  recoveryCodes.value = []
  loadError.value = ''
  busy.value = true
  try {
    const out = await api.post<TOTPSetup>(`/users/${props.userId}/totp/setup`, {})
    secret.value = out.secret
    qr.value = await QRCode.toDataURL(out.uri, { margin: 1, width: 320 })
  } catch (e) {
    // 失败原因由服务端给全（例如账号已停用），这里原样展示，不自己编一个说法
    loadError.value = (e as Error).message
  } finally {
    busy.value = false
  }
}

async function confirm() {
  if (!code.value.trim()) {
    ElMessage.warning('请输入验证器里显示的 6 位数字')
    return
  }
  busy.value = true
  try {
    const res = await api.post<{ recovery_codes: string[] }>(`/users/${props.userId}/totp/enable`, {
      secret: secret.value,
      code: code.value.trim(),
    })
    recoveryCodes.value = res.recovery_codes || []
    ElMessage.success('二次验证已开启')
    emit('done')
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    busy.value = false
  }
}

function close() {
  emit('update:modelValue', false)
}

async function copy(text: string) {
  // 局域网 http 访问下 navigator.clipboard 不存在，走 copyText 的退路（见 utils/clipboard.ts）
  if (await copyText(text)) {
    ElMessage.success('已复制到剪贴板')
    return
  }
  ElMessage.warning('当前访问方式下浏览器不允许自动复制，请手动选择复制')
}
</script>

<style scoped>
.tfa-bind {
  display: flex;
  gap: 16px;
  align-items: center;
  flex-wrap: wrap;
}
.tfa-qr {
  width: 180px;
  height: 180px;
  border: 1px solid var(--fnwg-border);
  border-radius: 8px;
  background: #fff;
  padding: 6px;
}
.tfa-secret {
  flex: 1;
  min-width: 180px;
}
.tfa-secret-text {
  display: block;
  word-break: break-all;
  font-size: 13px;
  padding: 8px 10px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
}
.tfa-codes {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
  gap: 8px;
}
.tfa-codes code {
  padding: 7px 10px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
  font-size: 13px;
  text-align: center;
}
</style>