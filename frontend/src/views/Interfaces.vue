<template>
  <div>
    <div class="fnwg-toolbar">
      <el-button v-if="session.can('iface.write')" type="primary" :icon="Plus" @click="openCreate">
        新建连接
      </el-button>
      <el-button :icon="Upload" @click="importVisible = true">导入已有配置</el-button>
      <el-button :icon="Download" @click="exportAll">导出备份</el-button>
      <el-button v-if="session.can('iface.write')" :icon="Refresh" @click="applyNow">立即应用</el-button>
      <el-button :icon="Reading" @click="helpVisible = true">配置说明</el-button>
      <div style="flex: 1"></div>
      <el-tag size="small" type="info" effect="plain">共 {{ list.length }} 条连接</el-tag>
    </div>

    <!-- 桌面端：表格 -->
    <div v-if="!isMobile" class="fnwg-card">
      <el-table :data="list" v-loading="loading" empty-text="还没有连接，点击「新建连接」开始">
        <el-table-column label="连接" width="140">
          <template #default="{ row }">
            <span :class="['fnwg-dot', row.up ? 'ok' : 'down']"></span>
            <strong>{{ row.name }}</strong>
          </template>
        </el-table-column>
        <el-table-column label="工作状态" width="110">
          <template #default="{ row }">
            <el-tag size="small" :type="row.up ? 'success' : 'danger'" effect="plain">
              {{ row.up ? '正常' : '未工作' }}
            </el-tag>
            <el-tag v-if="!row.enabled" size="small" type="info" effect="plain" style="margin-left: 4px">
              已停用
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="内部地址" min-width="170">
          <template #default="{ row }">
            <span class="fnwg-mono">{{ (row.addresses || []).join(', ') }}</span>
          </template>
        </el-table-column>
        <el-table-column label="端口" width="80">
          <template #default="{ row }">{{ row.listen_port }}</template>
        </el-table-column>
        <el-table-column label="设备" width="90">
          <template #default="{ row }">{{ row.peer_online ?? 0 }} / {{ row.peer_count ?? 0 }}</template>
        </el-table-column>
        <el-table-column label="累计流量" width="170">
          <template #default="{ row }">
            ↓{{ formatBytes(row.rx_bytes) }} ↑{{ formatBytes(row.tx_bytes) }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="300" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="gotoPeers(row)">设备</el-button>
            <el-button link type="primary" @click="showConf(row)">配置</el-button>
            <el-button v-if="session.can('iface.write')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-dropdown @command="(c: string) => onCommand(c, row)">
              <el-button link type="primary">更多<el-icon><ArrowDown /></el-icon></el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item v-if="session.can('iface.write')" command="toggle">
                    {{ row.enabled ? '停用这条连接' : '启用这条连接' }}
                  </el-dropdown-item>
                  <el-dropdown-item v-if="session.can('iface.write')" command="apply">立即应用</el-dropdown-item>
                  <el-dropdown-item v-if="session.can('key.reveal')" command="reveal" divided>
                    查看本机密钥
                  </el-dropdown-item>
                  <el-dropdown-item v-if="session.can('iface.write')" command="rotate">更换密钥</el-dropdown-item>
                  <el-dropdown-item v-if="session.can('iface.write')" command="delete" divided>
                    删除这条连接
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 移动端：卡片列表 -->
    <div v-else v-loading="loading">
      <ItemCard
        v-for="row in list"
        :key="row.id"
        :status="row.up ? 'ok' : 'down'"
        :title="row.name"
      >
        <template #extra>
          <el-tag size="small" :type="row.up ? 'success' : 'danger'" effect="plain">
            {{ row.up ? '正常' : '未工作' }}
          </el-tag>
          <el-tag v-if="!row.enabled" size="small" type="info" effect="plain">已停用</el-tag>
        </template>

        <div class="fnwg-kv">
          <span class="fnwg-kv-key">内部地址</span>
          <span class="fnwg-kv-val fnwg-mono">{{ (row.addresses || []).join(', ') }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">入口端口</span>
          <span class="fnwg-kv-val">{{ row.listen_port }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">已接设备</span>
          <span class="fnwg-kv-val">{{ row.peer_online ?? 0 }} 在线 / 共 {{ row.peer_count ?? 0 }} 台</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">累计流量</span>
          <span class="fnwg-kv-val">↓ {{ formatBytes(row.rx_bytes) }}　↑ {{ formatBytes(row.tx_bytes) }}</span>
        </div>

        <template #actions>
          <el-button size="small" @click="gotoPeers(row)">设备</el-button>
          <el-button size="small" @click="showConf(row)">配置</el-button>
          <el-button v-if="session.can('iface.write')" size="small" @click="openEdit(row)">编辑</el-button>
          <el-dropdown @command="(c: string) => onCommand(c, row)">
            <el-button size="small">更多<el-icon><ArrowDown /></el-icon></el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item v-if="session.can('iface.write')" command="toggle">
                  {{ row.enabled ? '停用这条连接' : '启用这条连接' }}
                </el-dropdown-item>
                <el-dropdown-item v-if="session.can('iface.write')" command="apply">立即应用</el-dropdown-item>
                <el-dropdown-item v-if="session.can('key.reveal')" command="reveal" divided>查看本机密钥</el-dropdown-item>
                <el-dropdown-item v-if="session.can('iface.write')" command="rotate">更换密钥</el-dropdown-item>
                <el-dropdown-item v-if="session.can('iface.write')" command="delete" divided>删除这条连接</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </template>
      </ItemCard>
      <div v-if="!list.length && !loading" class="fnwg-empty">还没有连接，点击上方「新建连接」开始</div>
    </div>

    <!-- 新建 / 编辑 -->
    <el-drawer v-model="drawerVisible" :title="form.id ? '编辑连接' : '新建连接'" :size="drawerSize">
      <el-form :model="form" class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="130px">
        <ScenarioPicker
          v-if="!form.id"
          v-model="scenario"
          :presets="interfacePresets"
          @apply="applyScenario"
        />

        <el-alert
          v-if="!form.id"
          type="info"
          :closable="false"
          show-icon
          title="下面的参数已按推荐值填好，不确定时直接保存即可"
          style="margin-bottom: 12px"
        />

        <el-alert
          type="success"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        >
          <template #title>
            本应用不会修改 NAS 自身的网络设置：不碰系统上网路线、不碰 DNS、不碰防火墙，
            也不会接管不是自己创建的网卡。FN Connect、Docker 等系统功能不受影响。
          </template>
        </el-alert>

        <el-form-item>
          <template #label><FieldLabel :meta="F.name" /></template>
          <el-input v-model="form.name" placeholder="wg0" />
          <FieldTips :meta="F.name" />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.addresses" /></template>
          <el-select
            v-model="form.addresses"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="输入后回车，例如 10.10.0.1/24"
            style="width: 100%"
          />
          <FieldTips :meta="F.addresses" example />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.listen_port" /></template>
          <el-input-number v-model="form.listen_port" :min="1" :max="65535" />
          <FieldTips :meta="F.listen_port" example />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.dns" /></template>
          <el-select
            v-model="form.dns"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="可留空，例如 223.5.5.5"
            style="width: 100%"
          />
          <FieldTips :meta="F.dns" example />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.dns_mode" /></template>
          <el-radio-group v-model="form.dns_mode">
            <el-radio value="client">仅下发给设备</el-radio>
            <el-radio value="host">NAS 也一起使用</el-radio>
            <el-radio value="off">不参与</el-radio>
          </el-radio-group>
          <FieldTips :meta="F.dns_mode" />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.mtu" /></template>
          <el-input-number v-model="form.mtu" :min="500" :max="65535" :step="10" />
          <FieldTips :meta="F.mtu" example />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.route_table" /></template>
          <el-radio-group v-model="form.route_table">
            <el-radio value="off" class="fnwg-radio-line">不管理（推荐）</el-radio>
            <el-radio value="client" class="fnwg-radio-line">客户端模式</el-radio>
          </el-radio-group>
          <FieldTips :meta="F.route_table" example />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="F.enabled" /></template>
          <el-switch v-model="form.enabled" active-text="启用" />
          <el-switch v-model="form.autostart" active-text="开机自动启用" style="margin-left: 16px" />
          <FieldTips :meta="F.autostart" />
        </el-form-item>

        <el-collapse style="margin-top: 8px">
          <el-collapse-item title="高级设置（不了解请保持默认）" name="adv">
            <el-alert
              type="warning"
              :closable="false"
              show-icon
              title="下面的命令会以管理员权限执行，请仅粘贴你完全信任的内容；普通使用无需填写"
              style="margin-bottom: 12px"
            />
            <el-form-item>
              <template #label><FieldLabel :meta="F.post_up" /></template>
              <el-input v-model="form.post_up" type="textarea" :rows="2" placeholder="可留空" />
              <FieldTips :meta="F.post_up" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="F.post_down" /></template>
              <el-input v-model="form.post_down" type="textarea" :rows="2" placeholder="可留空" />
              <FieldTips :meta="F.post_down" example />
            </el-form-item>
          </el-collapse-item>
        </el-collapse>
      </el-form>

      <template #footer>
        <div style="display: flex; gap: 8px; justify-content: flex-end; width: 100%">
          <el-button @click="drawerVisible = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="submit">
            {{ form.id ? '保存并应用' : '创建' }}
          </el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 导入 -->
    <el-dialog v-model="importVisible" title="导入已有配置" :width="dialogWidth || '640px'">
      <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
        <template #title>
          如果你之前手工配置过或使用过其他工具，可以直接把配置粘贴进来，系统会自动识别并导入其中的连接与设备。
        </template>
      </el-alert>
      <el-form class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="90px">
        <el-form-item label="连接名称">
          <el-input v-model="importName" placeholder="留空自动命名（例如 wg0）" />
        </el-form-item>
      </el-form>
      <el-input
        v-model="importText"
        type="textarea"
        :rows="isMobile ? 10 : 14"
        placeholder="在此粘贴配置内容，例如：&#10;[Interface]&#10;PrivateKey = ...&#10;Address = 10.10.0.1/24&#10;ListenPort = 51820&#10;&#10;[Peer]&#10;PublicKey = ...&#10;AllowedIPs = 10.10.0.2/32"
      />
      <template #footer>
        <el-button @click="importVisible = false">取消</el-button>
        <el-button type="primary" :loading="importing" @click="submitImport">识别并导入</el-button>
      </template>
    </el-dialog>

    <!-- 配置内容 / 密钥 -->
    <el-dialog v-model="confVisible" :title="confTitle" :width="dialogWidth || '680px'">
      <div class="fnwg-pre">{{ confText }}</div>
      <template #footer>
        <el-button @click="copy(confText)">复制</el-button>
        <el-button @click="confVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Upload, Download, Refresh, ArrowDown, Reading } from '@element-plus/icons-vue'
import { api, download } from '@/api/client'
import type { WgInterface } from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import FieldLabel from '@/components/FieldLabel.vue'
import FieldTips from '@/components/FieldTips.vue'
import ItemCard from '@/components/ItemCard.vue'
import ScenarioPicker from '@/components/ScenarioPicker.vue'
import { allHelpGroups, interfaceFields, interfacePresets } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import { formatBytes } from '@/utils/format'

const router = useRouter()
const session = useSession()
const realtime = useRealtime()
const { isMobile, drawerSize, dialogWidth } = useBreakpoint()

const F = interfaceFields
const helpGroups = allHelpGroups

const list = ref<WgInterface[]>([])
const loading = ref(false)
const saving = ref(false)
const drawerVisible = ref(false)
const importVisible = ref(false)
const importing = ref(false)
const importText = ref('')
const importName = ref('')
const confVisible = ref(false)
const confTitle = ref('')
const confText = ref('')
const helpVisible = ref(false)
const scenario = ref('home')

const emptyForm = () => ({
  id: 0,
  name: 'wg0',
  listen_port: 51820,
  mtu: 1420,
  addresses: ['10.10.0.1/24'] as string[],
  dns: ['223.5.5.5'] as string[],
  dns_mode: 'client' as string,
  route_table: 'off' as string,
  post_up: '',
  post_down: '',
  enabled: true,
  autostart: true,
})
const form = reactive(emptyForm())

async function load() {
  loading.value = true
  try {
    const data = await api.get<{ items: WgInterface[] }>('/interfaces')
    list.value = data.items || []
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

function openCreate() {
  Object.assign(form, emptyForm())
  scenario.value = 'home'
  drawerVisible.value = true
}

function openEdit(row: WgInterface) {
  Object.assign(form, {
    id: row.id,
    name: row.name,
    listen_port: row.listen_port,
    mtu: row.mtu,
    addresses: [...(row.addresses || [])],
    dns: [...(row.dns || [])],
    dns_mode: row.dns_mode || 'client',
    route_table: row.route_table === 'client' ? 'client' : 'off',
    post_up: row.post_up || '',
    post_down: row.post_down || '',
    enabled: row.enabled,
    autostart: row.autostart,
  })
  drawerVisible.value = true
}

/** 应用场景预设：只覆盖与该场景相关的字段 */
function applyScenario(values: Record<string, unknown>) {
  Object.assign(form, values)
}

async function submit() {
  saving.value = true
  try {
    const payload = {
      name: form.name,
      listen_port: form.listen_port,
      mtu: form.mtu,
      addresses: form.addresses,
      dns: form.dns,
      dns_mode: form.dns_mode,
      route_table: form.route_table,
      post_up: form.post_up,
      post_down: form.post_down,
      enabled: form.enabled,
      autostart: form.autostart,
    }
    if (form.id) {
      await api.patch(`/interfaces/${form.id}`, payload)
      ElMessage.success('已保存并应用')
    } else {
      const created = await api.post<WgInterface>('/interfaces', payload)
      ElMessage.success('连接已创建')
      if (created?.private_key) {
        await ElMessageBox.alert(
          `这条连接的私密密钥（系统已自动保存，此内容仅本次完整显示，请妥善留存）：\n\n${created.private_key}`,
          '请保存好密钥',
          { confirmButtonText: '我已保存' },
        )
      }
    }
    drawerVisible.value = false
    await load()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

async function onCommand(cmd: string, row: WgInterface) {
  try {
    if (cmd === 'toggle') {
      await api.post(`/interfaces/${row.id}/toggle`, { enabled: !row.enabled })
      ElMessage.success(row.enabled ? '已停用，该连接上的设备会立即断开' : '已启用')
      await load()
    } else if (cmd === 'apply') {
      await api.post(`/interfaces/${row.id}/apply`)
      ElMessage.success('已按当前配置应用到系统')
      await load()
    } else if (cmd === 'reveal') {
      const res = await api.post<{ private_key: string }>(`/interfaces/${row.id}/reveal-key`)
      confTitle.value = `${row.name} 的本机密钥`
      confText.value = res.private_key
      confVisible.value = true
    } else if (cmd === 'rotate') {
      await ElMessageBox.confirm(
        '更换密钥后，所有已连接设备都需要重新扫码导入新配置，否则会连不上。确认继续？',
        '更换密钥',
        { type: 'warning' },
      )
      const res = await api.post<{ public_key: string }>(`/interfaces/${row.id}/rotate-key`)
      ElMessage.success('密钥已更换，请重新给设备分发二维码')
      confTitle.value = '新的本机识别码'
      confText.value = res.public_key
      confVisible.value = true
    } else if (cmd === 'delete') {
      await ElMessageBox.confirm(
        `确认删除连接「${row.name}」？\n该连接下的 ${row.peer_count ?? 0} 台设备也会一并删除，且无法恢复（建议先导出备份）。`,
        '删除连接',
        { type: 'warning' },
      )
      await api.del(`/interfaces/${row.id}`)
      ElMessage.success('已删除')
      await load()
    }
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function showConf(row: WgInterface) {
  try {
    const res = await api.get<{ name: string; conf: string }>(`/interfaces/${row.id}/conf`)
    confTitle.value = `${res.name} 的完整配置`
    confText.value = res.conf
    confVisible.value = true
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function submitImport() {
  importing.value = true
  try {
    const res = await api.post<{ peer_count: number }>('/config/import', {
      text: importText.value,
      name: importName.value,
    })
    ElMessage.success(`导入成功，识别到 ${res.peer_count} 台设备`)
    importVisible.value = false
    importText.value = ''
    importName.value = ''
    await load()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    importing.value = false
  }
}

async function applyNow() {
  try {
    const res = await api.post<{ actions: string[] }>('/system/reconcile')
    ElMessage.success(res.actions?.length ? `已应用 ${res.actions.length} 项变更` : '当前配置已是最新，无需变更')
    realtime.connect()
    await load()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

function exportAll() {
  download('/config/export')
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制到剪贴板')
  } catch {
    ElMessage.warning('浏览器拒绝了剪贴板访问，请手动选择复制')
  }
}

function gotoPeers(row: WgInterface) {
  router.push({ name: 'peers', query: { iface: String(row.id) } })
}

onMounted(load)
</script>
