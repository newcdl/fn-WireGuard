<template>
  <el-dialog
    :model-value="modelValue"
    :title="status?.enabled ? '二次验证（已开启）' : '开启二次验证'"
    :width="dialogWidth || '560px'"
    @update:model-value="onToggle"
  >
    <div v-loading="busy">
      <el-alert v-if="loadError" type="error" :closable="false" show-icon :title="loadError" />

      <!-- ============ 尚未开启：引导绑定 ============ -->
      <template v-else-if="!status?.enabled">
        <!-- 一、先验证身份，再生成密钥 -->
        <template v-if="step === 'intro'">
          <el-alert type="info" :closable="false" show-icon style="margin-bottom: 14px">
            <template #title>
              开启后，登录时除密码外还需输入手机验证器 App（如 Microsoft Authenticator、
              1Password、Authy）里显示的 6 位动态口令。即使密码泄露，别人也进不来。
            </template>
          </el-alert>
          <el-form class="fnwg-form" label-position="top">
            <el-form-item label="当前密码">
              <el-input
                v-model="password"
                type="password"
                show-password
                placeholder="为确认是本人操作，请重新输入当前密码"
                @keyup.enter="startBind"
              />
            </el-form-item>
          </el-form>
        </template>

        <!-- 二、扫码 + 用一次动态口令确认绑定 -->
        <template v-else-if="step === 'bind'">
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
              <el-input
                v-model="code"
                placeholder="请输入以确认绑定成功"
                @keyup.enter="confirmEnable"
              />
            </el-form-item>
          </el-form>
          <el-alert type="warning" :closable="false" show-icon>
            <template #title>
              这一步不能跳过：必须用当前口令验证一次，确认验证器确实绑好了，
              否则一旦密钥抄错，下次登录会被自己锁在门外。
            </template>
          </el-alert>
        </template>

        <!-- 三、一次性恢复码 -->
        <template v-else>
          <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px">
            <template #title>
              请立刻保存下面的恢复码。它们只显示这一次，之后任何人都无法再取回
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
      </template>

      <!-- ============ 已开启：可关闭 ============ -->
      <template v-else>
        <el-alert type="success" :closable="false" show-icon style="margin-bottom: 14px">
          <template #title>
            二次验证已开启：登录时需要密码 + 验证器里的动态口令。
          </template>
        </el-alert>
        <div class="fnwg-hint" style="margin-bottom: 6px">
          剩余可用恢复码：<strong>{{ status.recovery_remaining }}</strong> 枚
        </div>
        <div v-if="status.recovery_remaining === 0" class="fnwg-hint" style="color: var(--el-color-danger)">
          恢复码已用完。建议先关闭再重新开启一次，以获取新的一批。
        </div>

        <el-divider />

        <!-- 受信任设备：登录取自「信任本设备」的勾选，是绕过二次验证的唯一凭据，必须可见可撤销 -->
        <div style="font-weight: 600; margin-bottom: 10px">
          受信任设备<span v-if="devices.length">（{{ devices.length }}）</span>
        </div>
        <div v-if="!devices.length" class="fnwg-hint" style="margin-bottom: 10px">
          暂无。登录时勾选「信任本设备」，该设备 30 天内登录就无需再输入验证码。
        </div>
        <template v-else>
          <el-table :data="devices" size="small">
            <el-table-column prop="name" label="设备" min-width="130" />
            <el-table-column prop="src_ip" label="来源 IP" width="130" />
            <el-table-column label="最近使用" width="160">
              <template #default="{ row }">{{ formatTime(row.last_used_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="70">
              <template #default="{ row }">
                <el-button link type="danger" @click="revokeDevice(row)">撤销</el-button>
              </template>
            </el-table-column>
          </el-table>
          <div class="fnwg-hint" style="margin: 8px 0 10px">
            看到不认识的设备请立即撤销，并顺手改一次密码（改密码会自动作废全部受信任设备）。
          </div>
          <el-button size="small" @click="revokeAllDevices">全部撤销</el-button>
        </template>

        <el-divider />

        <div style="font-weight: 600; margin-bottom: 10px">关闭二次验证</div>
        <el-form class="fnwg-form" label-position="top">
          <el-form-item label="当前密码">
            <el-input v-model="password" type="password" show-password />
          </el-form-item>
          <el-form-item label="验证码">
            <el-input v-model="code" placeholder="验证器当前 6 位数字，或一枚恢复码" />
          </el-form-item>
        </el-form>
        <el-alert type="info" :closable="false" show-icon>
          <template #title>
            关闭是「降低安全」的操作，因此除密码外还要求一次动态口令。
            关闭后仅凭密码即可登录（与开启前一致），所有恢复码同时作废。
          </template>
        </el-alert>
      </template>
    </div>

    <template #footer>
      <!-- 状态尚未取回时不给出任何会改状态的操作按钮 -->
      <template v-if="!status">
        <el-button @click="close">关闭</el-button>
      </template>
      <template v-else-if="status.enabled">
        <el-button @click="close">取消</el-button>
        <el-button type="danger" :loading="busy" @click="disable">关闭二次验证</el-button>
      </template>
      <!-- 恢复码只此一次，必须由用户主动确认看过 -->
      <template v-else-if="step === 'recovery'">
        <el-button type="primary" @click="close">我已保存，完成</el-button>
      </template>
      <template v-else-if="step === 'bind'">
        <el-button @click="step = 'intro'">上一步</el-button>
        <el-button type="primary" :loading="busy" @click="confirmEnable">确认开启</el-button>
      </template>
      <template v-else>
        <el-button @click="close">取消</el-button>
        <el-button type="primary" :loading="busy" @click="startBind">生成二维码</el-button>
      </template>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import QRCode from 'qrcode'
import { api } from '@/api/client'
import type { TOTPSetup, TOTPStatus, TrustedDevice } from '@/api/types'
import { formatTime } from '@/utils/format'
import { copyText } from '@/utils/clipboard'
import { useSession } from '@/stores/session'
import { useBreakpoint } from '@/composables/useBreakpoint'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [boolean] }>()

const session = useSession()
const { dialogWidth } = useBreakpoint()

const status = ref<TOTPStatus | null>(null)
const step = ref<'intro' | 'bind' | 'recovery'>('intro')
const busy = ref(false)
const loadError = ref('')

const password = ref('')
const code = ref('')
const secret = ref('')
const qr = ref('')
const recoveryCodes = ref<string[]>([])
const devices = ref<TrustedDevice[]>([])

watch(
  () => props.modelValue,
  (open) => {
    if (open) void openDialog()
  },
)

function onToggle(v: boolean) {
  if (!v) close()
}

/** 每次打开都重新拉状态：期间可能已在别处开启或关闭过。 */
async function openDialog() {
  step.value = 'intro'
  password.value = ''
  code.value = ''
  secret.value = ''
  qr.value = ''
  recoveryCodes.value = []
  devices.value = []
  loadError.value = ''
  busy.value = true
  try {
    status.value = await api.get<TOTPStatus>('/auth/totp')
    if (status.value.enabled) await loadDevices()
  } catch (e) {
    loadError.value = (e as Error).message
  } finally {
    busy.value = false
  }
}

/** 读取受信任设备列表。它只是展示与撤销用途，取不到就不显示，不阻断主流程。 */
async function loadDevices() {
  try {
    const res = await api.get<{ items: TrustedDevice[] }>('/auth/trusted-devices')
    devices.value = res.items || []
  } catch {
    devices.value = []
  }
}

async function revokeDevice(row: TrustedDevice) {
  try {
    await ElMessageBox.confirm(
      `撤销后，「${row.name || '该设备'}」下次登录需要重新输入验证码。确认撤销？`,
      '撤销受信任设备',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.del(`/auth/trusted-devices/${row.id}`)
    ElMessage.success('已撤销')
    await loadDevices()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function revokeAllDevices() {
  try {
    await ElMessageBox.confirm(
      '撤销后，所有设备下次登录都需要重新输入验证码。确认全部撤销？',
      '撤销全部受信任设备',
      { type: 'warning' },
    )
  } catch {
    return
  }
  try {
    await api.del('/auth/trusted-devices')
    ElMessage.success('已全部撤销')
    await loadDevices()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function startBind() {
  if (!password.value) {
    ElMessage.warning('请输入当前密码')
    return
  }
  busy.value = true
  try {
    const out = await api.post<TOTPSetup>('/auth/totp/setup', { password: password.value })
    secret.value = out.secret
    qr.value = await QRCode.toDataURL(out.uri, { margin: 1, width: 320 })
    code.value = ''
    step.value = 'bind'
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    busy.value = false
  }
}

async function confirmEnable() {
  if (!code.value.trim()) {
    ElMessage.warning('请输入验证器里显示的 6 位数字')
    return
  }
  busy.value = true
  try {
    const res = await api.post<{ recovery_codes: string[] }>('/auth/totp/enable', {
      password: password.value,
      secret: secret.value,
      code: code.value.trim(),
    })
    recoveryCodes.value = res.recovery_codes || []
    step.value = 'recovery'
    status.value = { enabled: true, recovery_remaining: recoveryCodes.value.length }
    await session.loadMe()
    ElMessage.success('二次验证已开启')
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    busy.value = false
  }
}

async function disable() {
  if (!password.value || !code.value.trim()) {
    ElMessage.warning('请填写当前密码与验证码')
    return
  }
  busy.value = true
  try {
    await api.post('/auth/totp/disable', { password: password.value, code: code.value.trim() })
    await session.loadMe()
    ElMessage.success('二次验证已关闭')
    close()
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
