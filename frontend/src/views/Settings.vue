<template>
  <div>
    <el-tabs v-model="tab">
      <!-- 接入设置 -->
      <el-tab-pane label="接入设置" name="general">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            这里决定手机、电脑在外网时如何找到并连回这台 NAS。只影响「之后新生成」的二维码与配置文件，
            已有设备不会自动改变。
          </template>
        </el-alert>

        <div class="fnwg-card" style="max-width: 760px">
          <el-form :model="settings" class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="150px">
            <el-form-item>
              <template #label><FieldLabel :meta="S.server_endpoint" /></template>
              <el-input v-model="settings.server_endpoint" placeholder="例如 home.example.com:51820" />
              <FieldTips :meta="S.server_endpoint" example />
            </el-form-item>

            <el-form-item>
              <template #label><FieldLabel :meta="S.default_dns" /></template>
              <el-input v-model="settings.default_dns" placeholder="例如 223.5.5.5" />
              <FieldTips :meta="S.default_dns" example />
            </el-form-item>

            <el-form-item>
              <template #label><FieldLabel :meta="S.notify_webhook" /></template>
              <el-input v-model="settings.notify_webhook" placeholder="可留空" />
              <FieldTips :meta="S.notify_webhook" example />
            </el-form-item>

            <el-form-item>
              <el-button v-if="session.isAdmin" type="primary" :loading="savingSettings" @click="saveSettings">
                保存
              </el-button>
              <span v-else class="fnwg-hint">仅管理员可以修改这些设置</span>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <!-- 运行状态 -->
      <el-tab-pane label="运行状态" name="health">
        <!-- NAS 系统网络安全自检：本应用唯一可能影响系统的地方，单列出来并可一键修复 -->
        <div class="fnwg-card" style="max-width: 760px; margin-bottom: 12px">
          <div class="fnwg-safety">
            <el-icon class="fnwg-safety-icon" :color="netTone"><CircleCheck /></el-icon>
            <div style="flex: 1; min-width: 0">
              <strong>NAS 系统网络安全检查</strong>
              <div class="fnwg-hint">
                确认本应用没有影响 NAS 自身的上网路线。FN Connect、Docker、应用市场与系统更新都依赖它。
                本应用只会清理自己造成的残留，绝不修改系统设置。
              </div>
            </div>
            <el-button :icon="Search" :loading="checkingNet" @click="checkNetwork">立即检查</el-button>
          </div>

          <template v-if="netResult">
            <el-alert
              :type="netAlert.type"
              :closable="false"
              show-icon
              :title="netAlert.title"
              style="margin-top: 12px"
            />
            <ul class="fnwg-net-list">
              <li v-for="(m, i) in netResult.messages" :key="i">{{ m }}</li>
            </ul>
            <el-button
              v-if="!netResult.healthy && session.can('iface.write')"
              type="danger"
              :icon="Refresh"
              :loading="repairingNet"
              @click="repairNetwork"
            >
              立即修复
            </el-button>

            <!-- 内网访问逐层诊断：把「连上了但访问不了家里其它设备」定位到具体环节 -->
            <div v-if="netResult.nat?.checks?.length" class="fnwg-nat-checks">
              <div class="fnwg-foreign-title">
                内网访问诊断（设备访问家里其它设备）
                <span v-if="natFailed" class="fnwg-nat-badge">有 {{ natFailed }} 项未通过</span>
              </div>
              <div v-for="c in netResult.nat.checks" :key="c.key" class="fnwg-nat-check">
                <el-tag size="small" :type="c.ok ? 'success' : 'danger'" effect="plain">
                  {{ c.ok ? '通过' : '未通过' }}
                </el-tag>
                <div class="fnwg-nat-check-body">
                  <strong>{{ c.label }}</strong>
                  <div class="fnwg-nat-check-detail">{{ c.detail }}</div>
                  <div v-if="!c.ok && c.fix" class="fnwg-nat-check-fix">处理建议：{{ c.fix }}</div>
                </div>
              </div>
            </div>

            <!-- 疑似残留：内核里有、但本应用不认的 WireGuard 网卡。只提示，删除需用户手工确认名称 -->
            <div v-if="netResult.foreign_interfaces?.length" class="fnwg-foreign-box">
              <div class="fnwg-foreign-title">疑似残留网卡</div>
              <div v-for="fi in netResult.foreign_interfaces" :key="fi.name" class="fnwg-foreign-item">
                <div class="fnwg-foreign-main">
                  <el-tag size="small" effect="plain" :type="fi.up ? 'warning' : 'info'">
                    {{ fi.up ? '运行中' : '已停止' }}
                  </el-tag>
                  <strong>{{ fi.name }}</strong>
                  <span class="fnwg-foreign-meta">
                    {{ fi.listen_port > 0 ? `占用 UDP 端口 ${fi.listen_port}` : '未监听端口' }}
                    · {{ fi.peer_count }} 个节点
                    <template v-if="fi.addresses?.length">· {{ fi.addresses.join('、') }}</template>
                  </span>
                </div>
                <el-button
                  v-if="session.can('iface.write')"
                  size="small"
                  type="danger"
                  plain
                  :loading="removingForeign === fi.name"
                  @click="removeForeign(fi)"
                >
                  清理
                </el-button>
              </div>
              <div class="fnwg-foreign-hint">
                这些网卡<b>不是本应用创建的</b>：可能是早期版本卸载时没清理干净的残留，
                也可能是你用 wg-quick 等工具手工建的。残留会一直占着上面标注的端口，
                导致新连接无法使用这些端口。<b>无法确认来源时请不要清理。</b>
              </div>
            </div>
          </template>
        </div>

        <div class="fnwg-card" style="max-width: 760px">
          <el-descriptions :column="isMobile ? 1 : 2" border size="small">
            <el-descriptions-item label="后台服务">
              <el-tag size="small" :type="health?.agent_up ? 'success' : 'danger'" effect="plain">
                {{ health?.agent_up ? '运行中' : '未运行' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="工作模式">{{ backendLabel }}</el-descriptions-item>
            <el-descriptions-item label="加密网络支持">
              <el-tag size="small" :type="health?.kernel_module ? 'success' : 'warning'" effect="plain">
                {{ health?.kernel_module ? '已开启' : '未开启' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="兼容模式支持">
              <el-tag size="small" :type="health?.tun_device ? 'success' : 'warning'" effect="plain">
                {{ health?.tun_device ? '可用' : '不可用' }}
              </el-tag>
            </el-descriptions-item>
            <el-descriptions-item label="已运行时长">{{ uptime }}</el-descriptions-item>
            <el-descriptions-item label="软件版本">{{ session.version || '-' }}</el-descriptions-item>
          </el-descriptions>

          <el-alert
            v-if="health?.error"
            type="error"
            :closable="false"
            show-icon
            :title="health.error"
            style="margin-top: 12px"
          />

          <div class="fnwg-explain">
            <div><strong>加密网络支持</strong>：标准模式，速度最快、资源占用最低。若显示「未开启」，新建的连接将无法工作。</div>
            <div><strong>兼容模式支持</strong>：当系统内核不支持标准模式时的备选方案，速度稍慢，目前版本尚未启用。</div>
          </div>

          <el-button
            v-if="session.can('iface.write')"
            :icon="Refresh"
            style="margin-top: 14px"
            @click="forceReconcile"
          >
            重新应用全部配置
          </el-button>
          <FieldTips
            :meta="{
              label: '重新应用全部配置',
              what: '让系统按照当前保存的设置，重新建立一次所有连接与设备。',
              why: '当你怀疑实际状态与界面显示不一致（例如手工改过系统设置、或连接异常）时使用。',
              effect: '不会改动你的任何配置，只会把系统状态纠正回配置描述的样子，通常几秒内完成。',
            }"
          />
        </div>
      </el-tab-pane>

      <!-- 账号管理 -->
      <el-tab-pane v-if="session.isAdmin" label="账号管理" name="users">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            管理谁能登录这个界面。可以给家人或同事开通「只读」查看权限，避免误改配置。
          </template>
        </el-alert>

        <div class="fnwg-toolbar">
          <el-button type="primary" :icon="Plus" @click="openUserDialog">新建账号</el-button>
        </div>

        <div v-if="!isMobile" class="fnwg-card">
          <el-table :data="users" size="small" empty-text="暂无账号">
            <el-table-column prop="username" label="登录账号" min-width="140" />
            <el-table-column label="权限" width="120">
              <template #default="{ row }">
                <el-tag size="small" effect="plain">{{ roleLabel(row.role) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="状态" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="row.status === 1 ? 'success' : 'info'" effect="plain">
                  {{ row.status === 1 ? '可登录' : '已停用' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="最近登录" width="180">
              <template #default="{ row }">{{ formatTime(row.last_login_at) }}</template>
            </el-table-column>
            <el-table-column label="操作" width="220">
              <template #default="{ row }">
                <el-button link type="primary" @click="toggleUser(row)">
                  {{ row.status === 1 ? '停用' : '启用' }}
                </el-button>
                <el-button link type="primary" @click="resetPassword(row)">重置密码</el-button>
                <el-button link type="danger" @click="removeUser(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <div v-else>
          <ItemCard
            v-for="row in users"
            :key="row.id"
            :status="row.status === 1 ? 'ok' : 'off'"
            :title="row.username"
          >
            <template #extra>
              <el-tag size="small" effect="plain">{{ roleLabel(row.role) }}</el-tag>
            </template>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">状态</span>
              <span class="fnwg-kv-val">{{ row.status === 1 ? '可登录' : '已停用' }}</span>
            </div>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">最近登录</span>
              <span class="fnwg-kv-val">{{ formatTime(row.last_login_at) }}</span>
            </div>
            <template #actions>
              <el-button size="small" @click="toggleUser(row)">{{ row.status === 1 ? '停用' : '启用' }}</el-button>
              <el-button size="small" @click="resetPassword(row)">重置密码</el-button>
              <el-button size="small" @click="removeUser(row)">删除</el-button>
            </template>
          </ItemCard>
        </div>
      </el-tab-pane>

      <!-- 备份与还原 -->
      <el-tab-pane label="备份还原" name="backup">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            备份会保存你的全部连接与设备设置，换机或误删后可以一键还原。建议在每次大改动前先备份一次。
          </template>
        </el-alert>

        <div class="fnwg-toolbar">
          <el-button v-if="session.can('backup.restore')" type="primary" :icon="Plus" @click="createBackup">
            立即备份
          </el-button>
          <el-button :icon="Download" @click="exportAll">导出全部配置（可读文本）</el-button>
          <div style="flex: 1"></div>
          <span class="fnwg-hint">备份文件位置：{{ shareDir || '-' }}</span>
        </div>

        <div v-if="!isMobile" class="fnwg-card">
          <el-table :data="backups" size="small" empty-text="还没有备份">
            <el-table-column prop="filename" label="备份文件" min-width="240" />
            <el-table-column label="大小" width="100">
              <template #default="{ row }">{{ formatBytes(row.size) }}</template>
            </el-table-column>
            <el-table-column label="是否含密钥" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="row.include_key ? 'warning' : 'info'" effect="plain">
                  {{ row.include_key ? '含密钥' : '不含密钥' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="备份时间" width="180">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <el-table-column prop="note" label="备注" min-width="140" />
            <el-table-column label="操作" width="160">
              <template #default="{ row }">
                <el-button v-if="session.can('backup.restore')" link type="primary" @click="restore(row)">还原</el-button>
                <el-button v-if="session.can('backup.restore')" link type="danger" @click="removeBackup(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <div v-else>
          <ItemCard v-for="row in backups" :key="row.id" :title="row.filename">
            <template #extra>
              <el-tag size="small" :type="row.include_key ? 'warning' : 'info'" effect="plain">
                {{ row.include_key ? '含密钥' : '不含密钥' }}
              </el-tag>
            </template>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">备份时间</span>
              <span class="fnwg-kv-val">{{ formatTime(row.created_at) }}</span>
            </div>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">大小</span>
              <span class="fnwg-kv-val">{{ formatBytes(row.size) }}</span>
            </div>
            <div v-if="row.note" class="fnwg-kv">
              <span class="fnwg-kv-key">备注</span>
              <span class="fnwg-kv-val">{{ row.note }}</span>
            </div>
            <template #actions>
              <el-button v-if="session.can('backup.restore')" size="small" type="primary" @click="restore(row)">
                还原
              </el-button>
              <el-button v-if="session.can('backup.restore')" size="small" @click="removeBackup(row)">删除</el-button>
            </template>
          </ItemCard>
          <div v-if="!backups.length" class="fnwg-empty">还没有备份</div>
        </div>
      </el-tab-pane>

      <!-- 关于 -->
      <el-tab-pane label="关于" name="about">
        <div class="fnwg-card" style="max-width: 760px">
          <h3 style="margin-top: 0">fn-WireGuard</h3>
          <p class="fnwg-about-text">
            这是一个运行在飞牛 NAS 上的 WireGuard 管理工具。你不需要记住任何命令，只要在界面上点几下，
            就能让手机、笔记本在外网安全地连回家里，或把两处网络连成一张网。
          </p>
          <el-descriptions :column="1" border size="small">
            <el-descriptions-item label="版本">{{ session.version || '-' }}</el-descriptions-item>
            <el-descriptions-item label="工作模式">{{ backendLabel }}</el-descriptions-item>
            <el-descriptions-item label="数据保存在">
              本机数据目录内（含配置与密钥）。密钥加密保存，即使文件被拿走也无法直接读出；
              任何信息都不会上传到外部服务器。
            </el-descriptions-item>
          </el-descriptions>

          <el-alert type="info" :closable="false" show-icon style="margin-top: 12px">
            <template #title>
              忘记某项设置是什么意思？点击「配置说明大全」，或直接点任意设置项旁边的问号图标。
            </template>
          </el-alert>
          <el-button style="margin-top: 12px" :icon="Reading" @click="helpVisible = true">打开配置说明大全</el-button>
        </div>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="userDialog" title="新建账号" :width="dialogWidth || '440px'">
      <el-form :model="newUser" class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="100px">
        <el-form-item>
          <template #label><FieldLabel :meta="U.username" /></template>
          <el-input v-model="newUser.username" />
        </el-form-item>
        <el-form-item>
          <template #label><FieldLabel :meta="U.password" /></template>
          <el-input v-model="newUser.password" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item>
          <template #label><FieldLabel :meta="U.role" /></template>
          <el-select v-model="newUser.role" style="width: 100%">
            <el-option label="管理员（可做任何操作）" value="admin" />
            <el-option label="运维（可改网络配置，不能管账号）" value="operator" />
            <el-option label="只读（只能查看）" value="viewer" />
          </el-select>
          <FieldTips :meta="U.role" example />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="userDialog = false">取消</el-button>
        <el-button type="primary" @click="createUser">创建</el-button>
      </template>
    </el-dialog>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Plus, Download, Refresh, Reading, CircleCheck, Search } from '@element-plus/icons-vue'
import { api, download } from '@/api/client'
import type { BackupRecord, ForeignInterface, Health, NetworkCheckResult, User } from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import FieldLabel from '@/components/FieldLabel.vue'
import FieldTips from '@/components/FieldTips.vue'
import ItemCard from '@/components/ItemCard.vue'
import { allHelpGroups, settingFields, userFields } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import { formatBytes, formatTime } from '@/utils/format'

const session = useSession()
const realtime = useRealtime()
const { isMobile, dialogWidth } = useBreakpoint()

const S = settingFields
const U = userFields
const helpGroups = allHelpGroups

const netResult = ref<NetworkCheckResult | null>(null)
const checkingNet = ref(false)
const repairingNet = ref(false)
const removingForeign = ref('')

/**
 * 自检结论的呈现方式。
 * 疑似残留网卡不算「异常」—— 它也可能真的在被别的工具使用，
 * 因此只给中性提醒，不把整块自检标成红色。
 */
const netAlert = computed<{ type: 'success' | 'warning' | 'error' | 'info'; title: string }>(() => {
  const r = netResult.value
  if (!r) return { type: 'info', title: '' }
  if (!r.healthy) return { type: 'error', title: '发现异常，建议立即修复' }
  if (r.foreign_interfaces?.length) {
    return { type: 'warning', title: '未发现路由异常，但有疑似残留网卡待你确认' }
  }
  return { type: 'success', title: '未发现影响 NAS 系统网络的问题' }
})
const netTone = computed(() =>
  !netResult.value ? '#909399' : netResult.value.healthy ? '#22c55e' : '#ef4444',
)

/** 内网访问自检里未通过的项数，0 表示这条链路完全就绪 */
const natFailed = computed(
  () => (netResult.value?.nat?.checks || []).filter((c) => !c.ok).length,
)

/**
 * 清理疑似残留网卡。
 * 这是应用里唯一能删除「非本应用创建」对象的操作，
 * 因此强制用户手工输入网卡名二次确认；后端还会再校验一次名称与网卡类型。
 */
async function removeForeign(fi: ForeignInterface) {
  const portTip = fi.listen_port > 0 ? `，并释放 UDP 端口 ${fi.listen_port}` : ''
  try {
    const { value } = await ElMessageBox.prompt(
      `将删除系统上的 WireGuard 网卡「${fi.name}」${portTip}。\n` +
        '如果它其实正被其它工具（例如你自己写的 wg-quick 配置）使用，删除会中断该连接。\n\n' +
        `请输入网卡名称「${fi.name}」以确认：`,
      '清理疑似残留网卡',
      {
        confirmButtonText: '确认删除',
        cancelButtonText: '取消',
        type: 'warning',
        inputPlaceholder: fi.name,
        inputValidator: (v: string) => (v === fi.name ? true : `请输入「${fi.name}」以确认`),
      },
    )
    removingForeign.value = fi.name
    const res = await api.post<{ actions: string[] }>('/system/network/foreign-interface/delete', {
      name: fi.name,
      confirm: value,
    })
    ElMessage.success(res.actions?.[0] || `已清理 ${fi.name}`)
    await checkNetwork()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error((e as Error).message)
  } finally {
    removingForeign.value = ''
  }
}

async function checkNetwork() {
  checkingNet.value = true
  try {
    netResult.value = await api.get<NetworkCheckResult>('/system/network')
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    checkingNet.value = false
  }
}

async function repairNetwork() {
  repairingNet.value = true
  try {
    const res = await api.post<{ actions: string[] }>('/system/network/repair')
    ElMessage.success(res.actions?.length ? `已修复 ${res.actions.length} 项` : '没有需要修复的内容')
    await checkNetwork()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    repairingNet.value = false
  }
}

const tab = ref('general')
const settings = reactive<Record<string, string>>({
  server_endpoint: '',
  default_dns: '',
  notify_webhook: '',
})
const savingSettings = ref(false)
const health = ref<Health | null>(null)
const helpVisible = ref(false)

const users = ref<User[]>([])
const userDialog = ref(false)
const newUser = reactive({ username: '', password: '', role: 'viewer' })

const backups = ref<BackupRecord[]>([])
const shareDir = ref('')

const backendLabel = computed(() => {
  const b = health.value?.backend || realtime.status?.backend
  return (
    ({ kernel: '标准模式', userspace: '兼容模式', mock: '演示模式' } as Record<string, string>)[b || ''] ||
    b ||
    '-'
  )
})

const uptime = computed(() => {
  const s = health.value?.uptime_sec || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h} 小时 ${m} 分钟` : `${m} 分钟`
})

function roleLabel(role: string) {
  return ({ admin: '管理员', operator: '运维', viewer: '只读' } as Record<string, string>)[role] || role
}

async function loadAll() {
  try {
    const kv = await api.get<Record<string, string>>('/settings')
    Object.assign(settings, {
      server_endpoint: kv.server_endpoint || '',
      default_dns: kv.default_dns || '',
      notify_webhook: kv.notify_webhook || '',
    })
  } catch {
    /* 忽略 */
  }
  await loadHealth()
  if (session.isAdmin) await loadUsers()
  await loadBackups()
}

async function loadHealth() {
  try {
    health.value = await api.get<Health>('/health')
  } catch {
    /* 忽略 */
  }
}

async function loadUsers() {
  try {
    const data = await api.get<{ items: User[] }>('/users')
    users.value = data.items || []
  } catch {
    /* 忽略 */
  }
}

async function loadBackups() {
  try {
    const data = await api.get<{ items: BackupRecord[]; share_dir: string }>('/backups')
    backups.value = data.items || []
    shareDir.value = data.share_dir || ''
  } catch {
    /* 忽略 */
  }
}

async function saveSettings() {
  savingSettings.value = true
  try {
    await api.put('/settings', { ...settings })
    ElMessage.success('已保存')
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    savingSettings.value = false
  }
}

async function forceReconcile() {
  try {
    const res = await api.post<{ actions: string[] }>('/system/reconcile')
    ElMessage.success(res.actions?.length ? `已重新应用 ${res.actions.length} 项设置` : '当前状态与配置一致，无需变更')
    await loadHealth()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

function openUserDialog() {
  newUser.username = ''
  newUser.password = ''
  newUser.role = 'viewer'
  userDialog.value = true
}

async function createUser() {
  try {
    await api.post('/users', { ...newUser })
    ElMessage.success('账号已创建')
    userDialog.value = false
    await loadUsers()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function toggleUser(row: User) {
  try {
    await api.patch(`/users/${row.id}`, { role: row.role, status: row.status === 1 ? 0 : 1 })
    await loadUsers()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function resetPassword(row: User) {
  try {
    const { value } = await ElMessageBox.prompt(`为「${row.username}」设置新密码（至少 8 位）`, '重置密码', {
      inputType: 'password',
    })
    await api.patch(`/users/${row.id}`, { role: row.role, password: value })
    ElMessage.success('密码已重置')
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function removeUser(row: User) {
  try {
    await ElMessageBox.confirm(`确认删除账号「${row.username}」？删除后该账号立即无法登录。`, '删除账号', {
      type: 'warning',
    })
    await api.del(`/users/${row.id}`)
    await loadUsers()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function createBackup() {
  let note = ''
  try {
    const r = await ElMessageBox.prompt('给这次备份写个备注（可留空）', '立即备份', { inputValue: '' })
    note = r.value
  } catch {
    return
  }
  let includeKey = false
  try {
    await ElMessageBox.confirm(
      '备份里是否同时保存密钥？\n· 含密钥：还原后设备可以直接继续使用\n· 不含密钥：更安全，但还原后设备需要重新扫码',
      '备份内容',
      { confirmButtonText: '含密钥', cancelButtonText: '不含密钥', distinguishCancelAndClose: true, type: 'warning' },
    )
    includeKey = true
  } catch (action) {
    if (action === 'close') return
    includeKey = false
  }
  try {
    await api.post('/backups', { note, include_key: includeKey })
    ElMessage.success('备份已完成')
    await loadBackups()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function restore(row: BackupRecord) {
  try {
    await ElMessageBox.confirm(
      `还原将用备份「${row.filename}」覆盖当前的全部连接与设备设置，现有配置会被替换。确认继续？`,
      '还原备份',
      { type: 'warning' },
    )
    const res = await api.post<{ restored_interfaces: number }>(`/backups/${row.id}/restore`)
    ElMessage.success(`已还原 ${res.restored_interfaces} 条连接`)
    await loadAll()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function removeBackup(row: BackupRecord) {
  try {
    await ElMessageBox.confirm(`确认删除备份「${row.filename}」？`, '删除备份', { type: 'warning' })
    await api.del(`/backups/${row.id}`)
    await loadBackups()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

function exportAll() {
  download('/config/export')
}

onMounted(async () => {
  await loadAll()
  await checkNetwork()
})
</script>

<style scoped>
.fnwg-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.fnwg-explain {
  margin-top: 12px;
  font-size: 12.5px;
  color: var(--el-text-color-secondary);
  line-height: 1.9;
}

.fnwg-about-text {
  color: var(--el-text-color-regular);
  line-height: 1.9;
  font-size: 13.5px;
}

.fnwg-net-list {
  margin: 10px 0 0;
  padding-left: 18px;
  font-size: 12.5px;
  line-height: 1.9;
  color: var(--el-text-color-regular);
}

.fnwg-foreign-box {
  margin-top: 14px;
  padding: 12px 14px;
  border: 1px solid var(--el-border-color);
  border-radius: 10px;
  background: var(--el-fill-color-lighter);
}

.fnwg-foreign-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
}

.fnwg-foreign-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 7px 0;
  border-top: 1px solid var(--el-border-color-lighter);
  flex-wrap: wrap;
}

.fnwg-foreign-main {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  font-size: 12.5px;
}

.fnwg-foreign-meta {
  color: var(--el-text-color-secondary);
}

.fnwg-foreign-hint {
  margin-top: 8px;
  font-size: 12.5px;
  line-height: 1.85;
  color: var(--el-text-color-regular);
}

.fnwg-nat-checks {
  margin-top: 14px;
  padding: 12px 14px;
  border: 1px solid var(--el-border-color);
  border-radius: 10px;
  background: var(--el-fill-color-lighter);
}

.fnwg-nat-check {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 0;
  border-top: 1px solid var(--el-border-color-lighter);
}

.fnwg-nat-check:first-of-type {
  border-top: none;
}

.fnwg-nat-check-body {
  font-size: 12.5px;
  line-height: 1.8;
  flex: 1;
  min-width: 0;
}

.fnwg-nat-check-detail {
  color: var(--el-text-color-regular);
  word-break: break-word;
}

.fnwg-nat-check-fix {
  color: var(--el-color-danger);
  margin-top: 2px;
}

.fnwg-nat-badge {
  margin-left: 8px;
  font-weight: 400;
  font-size: 12px;
  color: var(--el-color-danger);
}
</style>
