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
              这里只管「改配置」；查看系统状态、做体检与修复请到左侧「系统维护」。
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
import { Plus, Download, Reading } from '@element-plus/icons-vue'
import { api, download } from '@/api/client'
import type { BackupRecord, Health, User } from '@/api/types'
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
})
</script>

<style scoped>
.fnwg-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.6;
}

.fnwg-about-text {
  color: var(--el-text-color-regular);
  line-height: 1.9;
  font-size: 13.5px;
}

</style>
