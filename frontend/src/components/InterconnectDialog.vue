<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <el-dialog
    :model-value="modelValue"
    title="与另一台 NAS 互联"
    :width="isMobile ? '94%' : '720px'"
    @update:model-value="close"
    @closed="reset"
  >
    <el-tabs v-model="tab">
      <!-- 生成邀请：本机先建好一半，把文件交给对方 -->
      <el-tab-pane label="生成邀请" name="create">
        <div class="fnwg-hint">
          在本机把这条互联建好一半（隧道地址、端口、对端条目都由系统分配与推导），
          再把生成的邀请文件交给另一台 NAS 导入。两端的隧道地址、该放行的网段来自同一份数据，
          不必两头照着填 —— 手工填四处、错一处就只是「不通」，最难自查。
        </div>

        <el-form v-if="!created" label-width="150px" style="margin-top: 10px">
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">对端名称 <FieldLabel :meta="S.interconnect_peer_name" icon-only /></span>
            </template>
            <el-input v-model="form.peer_name" placeholder="例如：老家 NAS" style="width: 240px" />
          </el-form-item>
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">对端内网网段 <FieldLabel :meta="S.interconnect_peer_lan" icon-only /></span>
            </template>
            <el-input
              v-model="form.peerLAN"
              type="textarea"
              :rows="2"
              placeholder="192.168.2.0/24（多个用逗号或换行分隔）"
            />
          </el-form-item>
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">对端对外地址 <FieldLabel :meta="S.interconnect_peer_endpoint" icon-only /></span>
            </template>
            <el-input v-model="form.peer_endpoint" placeholder="可留空，例如 nas-b.example.com:51820" style="width: 300px" />
          </el-form-item>
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">本机暴露给对端 <FieldLabel :meta="S.interconnect_local_lan" icon-only /></span>
            </template>
            <el-input v-model="form.localLAN" type="textarea" :rows="2" :placeholder="detectedHint" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" @click="create">生成邀请</el-button>
            <span class="fnwg-hint" style="margin-left: 10px">本机这一半会立刻建好并生效</span>
          </el-form-item>
        </el-form>

        <template v-else>
          <el-alert
            v-for="(w, i) in created.warnings"
            :key="i"
            type="warning"
            :closable="false"
            show-icon
            :title="w"
            style="margin-bottom: 8px"
          />
          <el-descriptions :column="isMobile ? 1 : 2" border size="small">
            <el-descriptions-item label="本机连接">{{ created.interface_name }}</el-descriptions-item>
            <el-descriptions-item label="隧道网段">{{ created.tunnel_subnet }}</el-descriptions-item>
            <el-descriptions-item label="对端隧道地址">{{ created.peer_tunnel_address }}</el-descriptions-item>
            <el-descriptions-item label="对端设备条目">已创建</el-descriptions-item>
          </el-descriptions>

          <div class="fnwg-invoke-head">
            <strong>交给对端的邀请</strong>
            <FieldLabel :meta="S.interconnect_invite" icon-only />
            <div style="flex: 1"></div>
            <el-button size="small" @click="copy(created.invite_json)">复制</el-button>
            <el-button size="small" @click="downloadInvite">下载文件</el-button>
          </div>
          <el-input v-model="created.invite_json" type="textarea" :rows="8" readonly />

          <el-collapse v-if="created.peer_conf" style="margin-top: 10px">
            <el-collapse-item title="对端不装本应用时：这份 wg-quick 配置可以直接用">
              <el-input :model-value="created.peer_conf" type="textarea" :rows="10" readonly />
              <div style="margin-top: 6px">
                <el-button size="small" @click="copy(created.peer_conf)">复制配置</el-button>
              </div>
            </el-collapse-item>
          </el-collapse>

          <div style="margin-top: 12px">
            <el-button @click="created = null">再建一条</el-button>
          </div>
        </template>
      </el-tab-pane>

      <!-- 导入邀请：把对方发来的内容贴进来 -->
      <el-tab-pane label="导入邀请" name="import">
        <div class="fnwg-hint">
          粘贴另一台 NAS 生成的邀请内容（以 <span class="fnwg-mono">{{ '{' }}</span> 开头的那一整段），
          导入后本机会自动建好对称的连接与对端条目。
        </div>
        <el-input
          v-model="importText"
          type="textarea"
          :rows="10"
          placeholder="粘贴邀请内容…"
          style="margin-top: 10px"
        />
        <div style="margin-top: 10px">
          <el-button type="primary" :loading="importing" @click="doImport">导入</el-button>
          <span class="fnwg-hint" style="margin-left: 10px">
            导入会把本机已有的配置也检查一遍：隧道网段冲突、两端内网网段相同、公钥重复都会当场拒绝并说明原因
          </span>
        </div>

        <template v-if="imported">
          <el-alert
            v-for="(w, i) in imported.warnings"
            :key="i"
            type="warning"
            :closable="false"
            show-icon
            :title="w"
            style="margin: 10px 0 0"
          />
          <el-descriptions :column="isMobile ? 1 : 2" border size="small" style="margin-top: 12px">
            <el-descriptions-item label="本机连接">{{ imported.interface_name }}</el-descriptions-item>
            <el-descriptions-item label="隧道地址">{{ imported.tunnel_address }}</el-descriptions-item>
            <el-descriptions-item label="隧道网段">{{ imported.tunnel_subnet }}</el-descriptions-item>
            <el-descriptions-item label="对端名称">{{ imported.peer_name }}</el-descriptions-item>
            <el-descriptions-item label="放行对端来源" :span="2">
              <span class="fnwg-mono">{{ imported.allowed_ips.join('、') }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="本机暴露给对端" :span="2">
              <span class="fnwg-mono">{{ imported.client_allowed_ips.join('、') }}</span>
            </el-descriptions-item>
          </el-descriptions>
        </template>
      </el-tab-pane>
    </el-tabs>

    <template #footer>
      <el-button @click="close(false)">关闭</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { api } from '@/api/client'
import type { InterconnectCreated, InterconnectImported, NetworkCheckResult } from '@/api/types'
import FieldLabel from '@/components/FieldLabel.vue'
import { interconnectFields as S } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { copyText } from '@/utils/clipboard'

const props = defineProps<{ modelValue: boolean }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; done: [] }>()

const { isMobile } = useBreakpoint()
const tab = ref<'create' | 'import'>('create')
const saving = ref(false)
const importing = ref(false)
const created = ref<InterconnectCreated | null>(null)
const imported = ref<InterconnectImported | null>(null)
const importText = ref('')
/** 探测到的本机网段，作为「暴露给对端」的默认值提示。 */
const detected = ref<string[]>([])

// 网段用「逗号/换行分隔的一行文本」而不是多选框：用户往往是照着路由表或说明书填，
// 直接粘贴一串更顺手；后端会逐个校验并指出哪一段不合法。
const form = reactive({ peer_name: '', peerLAN: '', peer_endpoint: '', localLAN: '' })

const detectedHint = computed(() =>
  detected.value.length
    ? `留空则用探测到的本机网段：${detected.value.join('、')}`
    : '留空则用探测到的本机网段（探测不到时必须手工填写）',
)

function splitSubnets(text: string): string[] {
  return text
    .split(/[,，\n]/)
    .map((v) => v.trim())
    .filter(Boolean)
}

async function loadDetected(): Promise<void> {
  try {
    const net = await api.get<NetworkCheckResult>('/system/network')
    detected.value = net.home_subnets || []
  } catch {
    // 探测不到不影响使用：用户可以手工填写
  }
}

async function create(): Promise<void> {
  saving.value = true
  try {
    created.value = await api.post<InterconnectCreated>('/interconnect', {
      peer_name: form.peer_name.trim(),
      peer_lan_subnets: splitSubnets(form.peerLAN),
      peer_endpoint: form.peer_endpoint.trim(),
      local_lan_subnets: splitSubnets(form.localLAN),
    })
    ElMessage.success('本机这一半已建好，把邀请交给另一台 NAS 导入即可')
  } catch (e) {
    ElMessage.error((e as Error)?.message || '生成邀请失败')
  } finally {
    saving.value = false
  }
}

async function doImport(): Promise<void> {
  importing.value = true
  try {
    imported.value = await api.post<InterconnectImported>('/interconnect/import', { text: importText.value })
    ElMessage.success('已导入：本机侧连接与对端条目都建好了')
    emit('done')
  } catch (e) {
    imported.value = null
    ElMessage.error((e as Error)?.message || '导入失败')
  } finally {
    importing.value = false
  }
}

function downloadInvite(): void {
  if (!created.value) return
  // 邀请是本地生成的文本，不走服务端下载：拼一个 Blob 直接存文件。
  const blob = new Blob([created.value.invite_json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `fnwg-interconnect-${created.value.interface_name}.json`
  a.click()
  URL.revokeObjectURL(url)
}

async function copy(text: string): Promise<void> {
  // 局域网 http 访问下 navigator.clipboard 不存在，走 copyText 的退路（见 utils/clipboard.ts）
  if (await copyText(text)) {
    ElMessage.success('已复制')
    return
  }
  ElMessage.warning('复制失败，请手动选中复制')
}

function close(v = false): void {
  emit('update:modelValue', v)
}

function reset(): void {
  // 关闭即复位：邀请含私钥，留着既没有意义也不该在屏幕上多停一秒
  created.value = null
  imported.value = null
  importText.value = ''
  tab.value = 'create'
  form.peer_name = ''
  form.peerLAN = ''
  form.peer_endpoint = ''
  form.localLAN = ''
}

// 每次打开时探测一次本机网段（对话框只创建一次，不能只在 setup 里做一次）
watch(
  () => props.modelValue,
  (open) => {
    if (open) void loadDetected()
  },
  { immediate: true },
)
</script>

<style scoped>
.fnwg-label-with-help {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.fnwg-invoke-head {
  display: flex;
  align-items: center;
  gap: 6px;
  margin: 12px 0 6px;
}
</style>
