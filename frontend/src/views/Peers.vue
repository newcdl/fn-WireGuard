<template>
  <div>
    <div class="fnwg-toolbar">
      <el-select v-model="ifaceFilter" placeholder="全部连接" clearable style="width: 160px" @change="load">
        <el-option v-for="it in interfaces" :key="it.id" :label="it.name" :value="it.id" />
      </el-select>
      <el-input v-model="keyword" placeholder="搜索设备名称" clearable style="width: 180px" />
      <el-button v-if="session.can('peer.write')" type="primary" :icon="Plus" @click="openCreate">
        添加设备
      </el-button>
      <el-dropdown v-if="session.can('peer.write')" :disabled="!selectedIds.length" @command="batch">
        <el-button :disabled="!selectedIds.length">
          批量操作（{{ selectedIds.length }}）<el-icon><ArrowDown /></el-icon>
        </el-button>
        <template #dropdown>
          <el-dropdown-menu>
            <el-dropdown-item command="enable">启用所选设备</el-dropdown-item>
            <el-dropdown-item command="disable">停用所选设备（临时收回权限）</el-dropdown-item>
            <el-dropdown-item command="keepalive" divided>统一设置心跳间隔</el-dropdown-item>
            <el-dropdown-item command="group">统一设置分组标签</el-dropdown-item>
            <el-dropdown-item command="extend">统一延长使用期限</el-dropdown-item>
            <el-dropdown-item command="quota">统一设置流量上限</el-dropdown-item>
            <el-dropdown-item command="delete" divided>永久删除所选设备</el-dropdown-item>
          </el-dropdown-menu>
        </template>
      </el-dropdown>
      <el-button :icon="Refresh" @click="load">刷新</el-button>
      <el-button :icon="Reading" @click="helpVisible = true">配置说明</el-button>
      <div style="flex: 1"></div>
      <el-tag size="small" type="info" effect="plain">在线 {{ onlineCount }} / 共 {{ filtered.length }} 台</el-tag>
    </div>

    <!-- 桌面端：表格 -->
    <div v-if="!isMobile" class="fnwg-card">
      <el-table
        :data="filtered"
        v-loading="loading"
        row-key="id"
        empty-text="还没有设备，点击「添加设备」开始"
        @selection-change="onSelectionChange"
      >
        <el-table-column type="selection" width="46" />
        <el-table-column label="设备" min-width="150">
          <template #default="{ row }">
            <span :class="['fnwg-dot', handshakeLevel(row.last_handshake)]"></span>
            <strong>{{ row.name }}</strong>
            <el-tag v-if="!row.enabled" size="small" type="info" effect="plain" style="margin-left: 6px">已停用</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="90">
          <template #default="{ row }">
            <el-tag size="small" :type="stateTagType(row)" effect="plain">{{ stateLabel(row) }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="interface_name" label="所属连接" width="100" />
        <el-table-column label="允许访问" min-width="170">
          <template #default="{ row }">
            <span class="fnwg-mono">{{ describeAllowed(row.allowed_ips) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="最近通信" width="110">
          <template #default="{ row }">{{ timeAgo(row.last_handshake) }}</template>
        </el-table-column>
        <el-table-column label="累计流量" width="160">
          <template #default="{ row }">
            ↓{{ formatBytes(row.rx_bytes) }} ↑{{ formatBytes(row.tx_bytes) }}
          </template>
        </el-table-column>
        <el-table-column label="有效期" width="90">
          <template #default="{ row }">
            <span v-if="!row.expire_at">长期</span>
            <el-tag v-else size="small" :type="(daysLeft(row.expire_at) ?? 0) <= 3 ? 'danger' : 'info'" effect="plain">
              剩 {{ daysLeft(row.expire_at) }} 天
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="220" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" @click="showConfig(row)">扫码连接</el-button>
            <el-button v-if="session.can('peer.write')" link type="primary" @click="openEdit(row)">编辑</el-button>
            <el-button v-if="session.can('peer.write')" link type="danger" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <!-- 移动端：卡片列表 -->
    <div v-else v-loading="loading">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px">
        <el-button size="small" @click="selectAll">
          {{ selectedIds.length === filtered.length && filtered.length ? '取消全选' : '全选' }}
        </el-button>
        <span style="font-size: 12px; opacity: 0.65">已选 {{ selectedIds.length }} 台</span>
      </div>

      <ItemCard
        v-for="row in filtered"
        :key="row.id"
        :status="handshakeLevel(row.last_handshake)"
        :title="row.name"
        selectable
        :selected="selectedIds.includes(row.id)"
        @toggle="toggleSelect(row.id)"
      >
        <template #extra>
          <el-tag size="small" :type="stateTagType(row)" effect="plain">{{ stateLabel(row) }}</el-tag>
          <el-tag v-if="!row.enabled" size="small" type="info" effect="plain">已停用</el-tag>
        </template>

        <div class="fnwg-kv">
          <span class="fnwg-kv-key">所属连接</span>
          <span class="fnwg-kv-val">{{ row.interface_name }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">允许访问</span>
          <span class="fnwg-kv-val">{{ describeAllowed(row.allowed_ips) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">最近通信</span>
          <span class="fnwg-kv-val">{{ timeAgo(row.last_handshake) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">累计流量</span>
          <span class="fnwg-kv-val">↓ {{ formatBytes(row.rx_bytes) }}　↑ {{ formatBytes(row.tx_bytes) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">有效期</span>
          <span class="fnwg-kv-val">{{ row.expire_at ? `剩 ${daysLeft(row.expire_at)} 天` : '长期有效' }}</span>
        </div>

        <template #actions>
          <el-button size="small" type="primary" @click="showConfig(row)">扫码连接</el-button>
          <el-button v-if="session.can('peer.write')" size="small" @click="openEdit(row)">编辑</el-button>
          <el-button v-if="session.can('peer.write')" size="small" @click="remove(row)">删除</el-button>
        </template>
      </ItemCard>
      <div v-if="!filtered.length && !loading" class="fnwg-empty">还没有设备，点击上方「添加设备」开始</div>
    </div>

    <!-- 添加 / 编辑设备 -->
    <el-drawer v-model="drawerVisible" :title="form.id ? '编辑设备' : '添加设备'" :size="drawerSize">
      <el-form :model="form" class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="130px">
        <ScenarioPicker
          v-if="!form.id"
          v-model="scenario"
          :presets="peerPresets"
          title="这台设备要怎么用？"
          @apply="applyScenario"
        />

        <el-form-item>
          <template #label><FieldLabel :meta="P.name" /></template>
          <el-input v-model="form.name" placeholder="例如：妈妈的手机" />
          <FieldTips :meta="P.name" example />
        </el-form-item>

        <el-form-item v-if="interfaces.length > 1">
          <template #label><FieldLabel :meta="P.interface_id" /></template>
          <el-select v-model="form.interface_id" style="width: 100%">
            <el-option v-for="it in interfaces" :key="it.id" :label="it.name" :value="it.id" />
          </el-select>
          <FieldTips :meta="P.interface_id" />
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="P.route_mode" /></template>
          <el-radio-group v-model="form.route_mode">
            <el-radio v-for="o in routeModeOptions" :key="o.value" :value="o.value" class="fnwg-radio-line">
              {{ o.label }}
              <span class="fnwg-radio-desc">{{ o.desc }}</span>
            </el-radio>
          </el-radio-group>
          <FieldTips :meta="P.route_mode" example />
        </el-form-item>

        <el-form-item v-if="form.route_mode === 'custom'">
          <template #label>自定义可访问范围</template>
          <el-select
            v-model="form.client_allowed_ips"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="例如 192.168.2.0/24，输入后回车"
            style="width: 100%"
          />
          <div class="fnwg-hint">
            列出这台设备需要访问的网段；只有这些网段的流量会走本连接，其它上网流量不受影响。
          </div>
        </el-form-item>

        <el-form-item>
          <template #label><FieldLabel :meta="P.allowed_ips" /></template>
          <el-select
            v-model="form.allowed_ips"
            multiple
            filterable
            allow-create
            default-first-option
            placeholder="留空即自动分配（推荐）"
            style="width: 100%"
          />
          <FieldTips :meta="P.allowed_ips" example />
        </el-form-item>

        <el-form-item v-if="!form.id">
          <template #label><FieldLabel :meta="P.generate_keys" /></template>
          <el-switch v-model="form.generate_keys" active-text="自动生成" />
          <div style="margin-top: 6px">
            <el-switch v-model="form.generate_psk" />
            <span style="margin-left: 6px; font-size: 13px">
              <FieldLabel :meta="P.generate_psk" />
            </span>
          </div>
        </el-form-item>

        <template v-else>
          <el-form-item>
            <template #label><FieldLabel :meta="P.public_key" /></template>
            <el-input v-model="form.public_key" class="fnwg-mono" />
            <FieldTips :meta="P.public_key" />
          </el-form-item>
          <el-form-item label="更换密钥">
            <el-switch v-model="form.generate_keys" active-text="保存时生成新的密钥对" />
            <el-switch v-model="form.generate_psk" active-text="生成新口令" style="margin-left: 12px" />
          </el-form-item>
        </template>

        <el-form-item>
          <template #label><FieldLabel :meta="P.persistent_keepalive" /></template>
          <el-input-number v-model="form.persistent_keepalive" :min="0" :max="3600" :step="5" />
          <FieldTips :meta="P.persistent_keepalive" example />
        </el-form-item>

        <el-collapse style="margin-top: 8px">
          <el-collapse-item title="更多设置（可选）" name="more">
            <el-form-item>
              <template #label><FieldLabel :meta="P.group_tag" /></template>
              <el-input v-model="form.group_tag" placeholder="例如：家人设备" />
              <FieldTips :meta="P.group_tag" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.remark" /></template>
              <el-input v-model="form.remark" placeholder="例如：2026-09 发放" />
              <FieldTips :meta="P.remark" />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.expire_at" /></template>
              <el-date-picker
                v-model="form.expire_at"
                type="datetime"
                placeholder="留空表示长期有效"
                style="width: 100%"
              />
              <FieldTips :meta="P.expire_at" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.quota_rx" /></template>
              <el-input-number v-model="form.quota_rx" :min="0" :step="1073741824" controls-position="right" />
              <FieldTips :meta="P.quota_rx" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="P.endpoint_host" /></template>
              <el-input v-model="form.endpoint_host" placeholder="一般留空" />
              <FieldTips :meta="P.endpoint_host" example />
            </el-form-item>
            <el-form-item v-if="form.endpoint_host">
              <template #label><FieldLabel :meta="P.endpoint_port" /></template>
              <el-input-number v-model="form.endpoint_port" :min="0" :max="65535" />
              <FieldTips :meta="P.endpoint_port" example />
            </el-form-item>
          </el-collapse-item>
        </el-collapse>

        <el-form-item>
          <template #label><FieldLabel :meta="P.enabled" /></template>
          <el-switch v-model="form.enabled" active-text="允许这台设备连接" />
          <FieldTips :meta="P.enabled" />
        </el-form-item>
      </el-form>

      <template #footer>
        <div style="display: flex; gap: 8px; justify-content: flex-end; width: 100%">
          <el-button @click="drawerVisible = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="submit">
            {{ form.id ? '保存' : '创建并生成二维码' }}
          </el-button>
        </div>
      </template>
    </el-drawer>

    <!-- 扫码连接 -->
    <el-dialog v-model="cfgVisible" title="用手机扫码连接" :width="dialogWidth || '680px'">
      <el-alert v-if="cfg?.warning" type="warning" :closable="false" show-icon :title="cfg.warning" style="margin-bottom: 12px" />
      <div class="fnwg-steps">
        <span>1. 手机应用商店安装 <strong>WireGuard</strong> 官方 App</span>
        <span>2. 打开 App 点击「+」→「扫描二维码」</span>
        <span>3. 扫下方二维码，完成后打开开关即可连回家</span>
      </div>

      <el-tabs>
        <el-tab-pane label="二维码（推荐）">
          <div class="fnwg-qr">
            <img v-if="qrDataUrl" :src="qrDataUrl" alt="连接二维码" />
            <div style="font-size: 12px; opacity: 0.7; text-align: center; line-height: 1.7">
              连接地址：{{ cfg?.endpoint || '未配置（请到系统设置填写对外访问地址）' }}<br />
              分配给本设备的内部地址：{{ (cfg?.client_address || []).join(', ') || '-' }}
            </div>
          </div>
        </el-tab-pane>
        <el-tab-pane label="配置文件（手动导入）">
          <div class="fnwg-pre">{{ cfg?.conf }}</div>
        </el-tab-pane>
      </el-tabs>

      <template #footer>
        <el-button @click="copy(cfg?.conf || '')">复制配置内容</el-button>
        <el-button type="primary" @click="downloadConf">下载配置文件</el-button>
        <el-button @click="cfgVisible = false">关闭</el-button>
      </template>
    </el-dialog>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Refresh, ArrowDown, Reading } from '@element-plus/icons-vue'
import QRCode from 'qrcode'
import { api } from '@/api/client'
import type { PeerConfigResult, WgInterface, WgPeer } from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import FieldLabel from '@/components/FieldLabel.vue'
import FieldTips from '@/components/FieldTips.vue'
import ItemCard from '@/components/ItemCard.vue'
import ScenarioPicker from '@/components/ScenarioPicker.vue'
import {
  allHelpGroups,
  interfaceFields,
  peerFields,
  peerPresets,
  routeModeOptions,
} from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'
import { daysLeft, formatBytes, handshakeLevel, timeAgo } from '@/utils/format'

const route = useRoute()
const session = useSession()
const { isMobile, drawerSize, dialogWidth } = useBreakpoint()

const P = peerFields
const helpGroups = allHelpGroups
void interfaceFields

const interfaces = ref<WgInterface[]>([])
const peers = ref<WgPeer[]>([])
const loading = ref(false)
const saving = ref(false)
const selectedIds = ref<number[]>([])
const ifaceFilter = ref<number | undefined>(undefined)
const keyword = ref('')

const drawerVisible = ref(false)
const cfgVisible = ref(false)
const helpVisible = ref(false)
const cfg = ref<PeerConfigResult | null>(null)
const qrDataUrl = ref('')
const scenario = ref('split')

const emptyForm = () => ({
  id: 0,
  interface_id: undefined as number | undefined,
  name: '',
  public_key: '',
  generate_keys: true,
  generate_psk: true,
  route_mode: 'lan',
  client_allowed_ips: [] as string[],
  allowed_ips: [] as string[],
  endpoint_host: '',
  endpoint_port: 0,
  persistent_keepalive: 25,
  group_tag: '',
  remark: '',
  expire_at: null as string | null,
  quota_rx: 0,
  quota_tx: 0,
  enabled: true,
})
const form = reactive(emptyForm())

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return peers.value
  return peers.value.filter(
    (p) =>
      p.name.toLowerCase().includes(kw) ||
      p.remark.toLowerCase().includes(kw) ||
      p.group_tag.toLowerCase().includes(kw),
  )
})

const onlineCount = computed(
  () => filtered.value.filter((p) => handshakeLevel(p.last_handshake) !== 'off').length,
)

/** 把技术化的 AllowedIPs 翻译成用户能理解的描述 */
function describeAllowed(ips?: string[]): string {
  if (!ips || !ips.length) return '未设置'
  if (ips.includes('0.0.0.0/0')) return '全部上网流量都走这里'
  const lan = ips.filter((i) => !i.endsWith('/32') && !i.endsWith('/128'))
  if (lan.length) return `可访问 ${lan.length} 个网段（含家庭内网）`
  return '仅本机内部地址'
}

function stateLabel(row: WgPeer): string {
  if (!row.enabled) return '已停用'
  const lv = handshakeLevel(row.last_handshake)
  if (lv === 'ok') return '在线'
  if (lv === 'warn') return '刚刚在线'
  return '离线'
}

function stateTagType(row: WgPeer): 'success' | 'warning' | 'info' {
  if (!row.enabled) return 'info'
  const lv = handshakeLevel(row.last_handshake)
  if (lv === 'ok') return 'success'
  if (lv === 'warn') return 'warning'
  return 'info'
}

async function loadInterfaces() {
  const data = await api.get<{ items: WgInterface[] }>('/interfaces')
  interfaces.value = data.items || []
  if (!form.interface_id && interfaces.value.length) form.interface_id = interfaces.value[0].id
}

async function load() {
  loading.value = true
  try {
    const q = ifaceFilter.value ? `?interface_id=${ifaceFilter.value}` : ''
    const data = await api.get<{ items: WgPeer[] }>(`/peers${q}`)
    peers.value = data.items || []
    selectedIds.value = []
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

function onSelectionChange(rows: WgPeer[]) {
  selectedIds.value = rows.map((r) => r.id)
}

function toggleSelect(id: number) {
  const i = selectedIds.value.indexOf(id)
  if (i >= 0) selectedIds.value.splice(i, 1)
  else selectedIds.value.push(id)
}

function selectAll() {
  selectedIds.value =
    selectedIds.value.length === filtered.value.length ? [] : filtered.value.map((p) => p.id)
}

function openCreate() {
  if (!interfaces.value.length) {
    ElMessage.warning('请先创建一条连接，再添加设备')
    return
  }
  Object.assign(form, emptyForm())
  form.interface_id = ifaceFilter.value || interfaces.value[0].id
  scenario.value = 'split'
  drawerVisible.value = true
}

function openEdit(row: WgPeer) {
  Object.assign(form, {
    id: row.id,
    interface_id: row.interface_id,
    name: row.name,
    public_key: row.public_key,
    generate_keys: false,
    generate_psk: false,
    route_mode: row.route_mode || 'lan',
    client_allowed_ips: [...(row.client_allowed_ips || [])],
    allowed_ips: [...(row.allowed_ips || [])],
    endpoint_host: row.endpoint_host,
    endpoint_port: row.endpoint_port,
    persistent_keepalive: row.persistent_keepalive,
    group_tag: row.group_tag,
    remark: row.remark,
    expire_at: row.expire_at || null,
    quota_rx: row.quota_rx,
    quota_tx: row.quota_tx,
    enabled: row.enabled,
  })
  drawerVisible.value = true
}

function applyScenario(values: Record<string, unknown>) {
  Object.assign(form, values)
}

async function submit() {
  saving.value = true
  try {
    const payload = {
      interface_id: form.interface_id,
      name: form.name,
      public_key: form.public_key,
      generate_keys: form.generate_keys,
      generate_psk: form.generate_psk,
      route_mode: form.route_mode,
      client_allowed_ips: form.client_allowed_ips,
      auto_address: true,
      allowed_ips: form.allowed_ips,
      endpoint_host: form.endpoint_host,
      endpoint_port: form.endpoint_port,
      persistent_keepalive: form.persistent_keepalive,
      group_tag: form.group_tag,
      remark: form.remark,
      expire_at: form.expire_at || null,
      quota_rx: form.quota_rx,
      quota_tx: form.quota_tx,
      enabled: form.enabled,
    }
    let created: WgPeer | null = null
    if (form.id) {
      await api.patch(`/peers/${form.id}`, payload)
      ElMessage.success('已保存')
    } else {
      created = await api.post<WgPeer>('/peers', payload)
      ElMessage.success('设备已添加')
    }
    drawerVisible.value = false
    await load()
    if (created) await showConfig(created)
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    saving.value = false
  }
}

async function showConfig(row: WgPeer) {
  try {
    const res = await api.get<PeerConfigResult>(`/peers/${row.id}/config`)
    cfg.value = res
    qrDataUrl.value = await QRCode.toDataURL(res.qr_payload || res.conf, { margin: 1, width: 480 })
    cfgVisible.value = true
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

function downloadConf() {
  if (!cfg.value) return
  const blob = new Blob([cfg.value.conf], { type: 'text/plain;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = cfg.value.filename
  a.click()
  URL.revokeObjectURL(url)
}

async function remove(row: WgPeer) {
  try {
    await ElMessageBox.confirm(
      `确认删除设备「${row.name}」？删除后该设备将无法连接，且需要重新扫码才能恢复。\n如果只是临时收回权限，建议改为「停用」。`,
      '删除设备',
      { type: 'warning' },
    )
    await api.del(`/peers/${row.id}`)
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function batch(action: string) {
  const ids = [...selectedIds.value]
  if (!ids.length) return
  const payload: Record<string, unknown> = { ids, action }
  try {
    if (action === 'delete') {
      await ElMessageBox.confirm(
        `确认永久删除选中的 ${ids.length} 台设备？此操作无法撤销。`,
        '批量删除',
        { type: 'warning' },
      )
    } else if (action === 'keepalive') {
      const { value } = await ElMessageBox.prompt(
        '每隔多少秒发送一次心跳，保持设备在线（推荐 25 秒）',
        '统一设置心跳间隔',
        { inputValue: '25', inputPattern: /^\d+$/, inputErrorMessage: '请输入数字' },
      )
      payload.persistent_keepalive = Number(value)
    } else if (action === 'group') {
      const { value } = await ElMessageBox.prompt('给这些设备打一个分类标签', '统一设置分组标签', {
        inputValue: '默认分组',
      })
      payload.group_tag = value
    } else if (action === 'extend') {
      const { value } = await ElMessageBox.prompt('从今天（或原到期日）起再延长多少天', '统一延长使用期限', {
        inputValue: '30',
        inputPattern: /^\d+$/,
        inputErrorMessage: '请输入数字',
      })
      payload.extend_days = Number(value)
    } else if (action === 'quota') {
      const { value } = await ElMessageBox.prompt(
        '每台设备的流量上限（字节）。1073741824 约等于 1 GB，填 0 表示不限制',
        '统一设置流量上限',
        { inputValue: '0', inputPattern: /^\d+$/, inputErrorMessage: '请输入数字' },
      )
      payload.quota_rx = Number(value)
      payload.quota_tx = Number(value)
    }
    const res = await api.post<{ message: string }>('/peers/batch', payload)
    ElMessage.success(res.message)
    await load()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.warning('浏览器拒绝了剪贴板访问')
  }
}

onMounted(async () => {
  const q = route.query.iface
  if (q) ifaceFilter.value = Number(q)
  await loadInterfaces()
  await load()
})
</script>

<style scoped>
.fnwg-steps {
  display: flex;
  flex-direction: column;
  gap: 4px;
  font-size: 12.5px;
  color: var(--el-text-color-regular);
  line-height: 1.7;
  margin-bottom: 12px;
  padding: 10px 12px;
  border-radius: 8px;
  background: var(--el-fill-color-light);
}
</style>
