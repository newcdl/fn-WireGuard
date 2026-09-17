<template>
  <div>
    <el-tabs v-model="tab">
      <!-- 操作记录 -->
      <el-tab-pane label="操作记录" name="audit">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            这里记录了每一次配置改动：谁改的、什么时候改的、结果如何。系统会为每条记录生成校验值，
            一旦有人篡改或删除记录，下面的「检查记录是否被篡改」会立刻发现。
          </template>
        </el-alert>

        <div class="fnwg-toolbar">
          <el-input v-model="auditFilter.username" placeholder="按操作人筛选" clearable style="width: 150px" />
          <el-select v-model="auditFilter.targetType" placeholder="按对象筛选" clearable style="width: 140px">
            <el-option label="连接" value="interface" />
            <el-option label="设备" value="peer" />
            <el-option label="账号" value="user" />
            <el-option label="备份" value="backup" />
            <el-option label="系统设置" value="settings" />
          </el-select>
          <el-button :icon="Search" @click="loadAudit">查询</el-button>
          <el-button :icon="CircleCheck" @click="verify">检查记录是否被篡改</el-button>
          <el-tag v-if="verifyResult" :type="verifyResult.intact ? 'success' : 'danger'" effect="plain">
            {{ verifyResult.intact ? '记录完整，未被篡改' : `第 ${verifyResult.first_broken_id} 条记录异常` }}
          </el-tag>
        </div>

        <!-- 桌面端表格 -->
        <div v-if="!isMobile" class="fnwg-card">
          <el-table :data="audit" v-loading="loadingAudit" size="small" empty-text="暂无操作记录">
            <el-table-column label="时间" width="170">
              <template #default="{ row }">{{ formatTime(row.ts) }}</template>
            </el-table-column>
            <el-table-column prop="username" label="操作人" width="110" />
            <el-table-column prop="src_ip" label="来源" width="130" />
            <el-table-column label="做了什么" width="150">
              <template #default="{ row }">
                <span>{{ actionLabel(row.action) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="对象" width="120">
              <template #default="{ row }">{{ targetLabel(row.target_type) }} #{{ row.target_id }}</template>
            </el-table-column>
            <el-table-column label="结果" width="80">
              <template #default="{ row }">
                <el-tag size="small" :type="row.result === 'ok' ? 'success' : 'danger'" effect="plain">
                  {{ row.result === 'ok' ? '成功' : '失败' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" label="补充说明" min-width="160" show-overflow-tooltip />
          </el-table>
          <el-pagination
            class="fnwg-pager"
            layout="total, prev, pager, next"
            :total="auditTotal"
            :page-size="auditFilter.limit"
            :current-page="auditPage"
            @current-change="onAuditPage"
          />
        </div>

        <!-- 移动端卡片 -->
        <div v-else v-loading="loadingAudit">
          <ItemCard
            v-for="row in audit"
            :key="row.id"
            :status="row.result === 'ok' ? 'ok' : 'down'"
            :title="actionLabel(row.action)"
          >
            <template #extra>
              <el-tag size="small" :type="row.result === 'ok' ? 'success' : 'danger'" effect="plain">
                {{ row.result === 'ok' ? '成功' : '失败' }}
              </el-tag>
            </template>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">时间</span>
              <span class="fnwg-kv-val">{{ formatTime(row.ts) }}</span>
            </div>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">操作人</span>
              <span class="fnwg-kv-val">{{ row.username }}（{{ row.src_ip }}）</span>
            </div>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">对象</span>
              <span class="fnwg-kv-val">{{ targetLabel(row.target_type) }} #{{ row.target_id }}</span>
            </div>
            <div v-if="row.message" class="fnwg-kv">
              <span class="fnwg-kv-key">说明</span>
              <span class="fnwg-kv-val">{{ row.message }}</span>
            </div>
          </ItemCard>
          <div v-if="!audit.length && !loadingAudit" class="fnwg-empty">暂无操作记录</div>
          <el-pagination
            class="fnwg-pager"
            layout="prev, pager, next"
            :total="auditTotal"
            :page-size="auditFilter.limit"
            :current-page="auditPage"
            @current-change="onAuditPage"
          />
        </div>
      </el-tab-pane>

      <!-- 运行日志 -->
      <el-tab-pane label="运行日志" name="app">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            这里记录程序自身的运行情况，例如「已应用配置」「某台设备因流量超额被自动停用」。
            连接不上或配置没生效时，可以在这里找到原因。
          </template>
        </el-alert>

        <div class="fnwg-toolbar">
          <el-select v-model="logFilter.level" placeholder="按重要程度" clearable style="width: 150px" @change="loadLogs">
            <el-option label="正常信息" value="info" />
            <el-option label="需要注意" value="warn" />
            <el-option label="出现错误" value="error" />
          </el-select>
          <el-input v-model="logFilter.keyword" placeholder="搜索关键字" clearable style="width: 180px" />
          <el-button :icon="Search" @click="loadLogs">查询</el-button>
        </div>

        <div v-if="!isMobile" class="fnwg-card">
          <el-table :data="logs" v-loading="loadingLogs" size="small" empty-text="暂无运行日志">
            <el-table-column label="时间" width="170">
              <template #default="{ row }">{{ formatTime(row.ts) }}</template>
            </el-table-column>
            <el-table-column label="重要程度" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="levelType(row.level)" effect="plain">{{ levelLabel(row.level) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="message" label="内容" min-width="240" />
            <el-table-column prop="fields" label="详细信息" min-width="200" show-overflow-tooltip />
          </el-table>
          <el-pagination
            class="fnwg-pager"
            layout="total, prev, pager, next"
            :total="logTotal"
            :page-size="logFilter.limit"
            :current-page="logPage"
            @current-change="onLogPage"
          />
        </div>

        <div v-else v-loading="loadingLogs">
          <ItemCard
            v-for="row in logs"
            :key="row.id"
            :status="row.level === 'error' ? 'down' : row.level === 'warn' ? 'warn' : 'off'"
            :title="row.message"
          >
            <template #extra>
              <el-tag size="small" :type="levelType(row.level)" effect="plain">{{ levelLabel(row.level) }}</el-tag>
            </template>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">时间</span>
              <span class="fnwg-kv-val">{{ formatTime(row.ts) }}</span>
            </div>
            <div v-if="row.fields" class="fnwg-kv">
              <span class="fnwg-kv-key">详情</span>
              <span class="fnwg-kv-val">{{ row.fields }}</span>
            </div>
          </ItemCard>
          <div v-if="!logs.length && !loadingLogs" class="fnwg-empty">暂无运行日志</div>
          <el-pagination
            class="fnwg-pager"
            layout="prev, pager, next"
            :total="logTotal"
            :page-size="logFilter.limit"
            :current-page="logPage"
            @current-change="onLogPage"
          />
        </div>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref, watch } from 'vue'
import { ElMessage } from 'element-plus'
import { Search, CircleCheck } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import type { AuditEntry, LogEntry } from '@/api/types'
import ItemCard from '@/components/ItemCard.vue'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { formatTime } from '@/utils/format'

const { isMobile } = useBreakpoint()

const tab = ref('audit')

const audit = ref<AuditEntry[]>([])
const auditTotal = ref(0)
const auditPage = ref(1)
const loadingAudit = ref(false)
const auditFilter = reactive({ username: '', targetType: '', limit: 50 })
const verifyResult = ref<{ intact: boolean; first_broken_id: number } | null>(null)

const logs = ref<LogEntry[]>([])
const logTotal = ref(0)
const logPage = ref(1)
const loadingLogs = ref(false)
const logFilter = reactive({ level: '', keyword: '', limit: 50 })

/** 把内部动作名翻译成普通话 */
const ACTION_LABELS: Record<string, string> = {
  'iface.create': '新建了一条连接',
  'iface.update': '修改了连接设置',
  'iface.delete': '删除了连接',
  'iface.toggle': '启用或停用了连接',
  'iface.reveal_key': '查看了连接密钥',
  'iface.rotate_key': '更换了连接密钥',
  'peer.create': '添加了一台设备',
  'peer.update': '修改了设备设置',
  'peer.delete': '删除了设备',
  'peer.batch_enable': '批量启用了设备',
  'peer.batch_disable': '批量停用了设备',
  'peer.batch_delete': '批量删除了设备',
  'peer.batch_keepalive': '批量设置了心跳间隔',
  'peer.batch_group': '批量设置了分组标签',
  'peer.batch_extend': '批量延长了使用期限',
  'peer.batch_quota': '批量设置了流量上限',
  'peer.reveal_key': '查看了设备密钥',
  'peer.auto_disable': '系统自动停用了设备',
  'config.import': '导入了已有配置',
  'backup.create': '创建了备份',
  'backup.import': '导入了备份',
  'backup.delete': '删除了备份',
  'backup.restore': '从备份恢复',
  'settings.update': '修改了系统设置',
  'key.generate': '生成了密钥',
  'key.generate_psk': '生成了加密口令',
  'user.create': '创建了账号',
  'user.update': '修改了账号',
  'user.delete': '删除了账号',
  'user.change_password': '修改了密码',
  'auth.login': '登录',
  'auth.login.totp': '二次验证登录',
  'totp.setup': '发起了二次验证绑定',
  'totp.enable': '开启了二次验证',
  'totp.disable': '关闭了二次验证',
  'totp.trust_device': '信任了一台设备',
  'totp.revoke_device': '撤销了受信任设备',
  'totp.admin_reset': '重置了账号的二次验证',
  'security.code_issue': '生成了新的安全码',
  'security.emergency_login': '用安全码应急登录',
  'user.reset_password': '重置了账号密码',
}

const TARGET_LABELS: Record<string, string> = {
  interface: '连接',
  peer: '设备',
  user: '账号',
  backup: '备份',
  settings: '系统设置',
  key: '密钥',
}

function actionLabel(action: string) {
  return ACTION_LABELS[action] || action
}

function targetLabel(t: string) {
  return TARGET_LABELS[t] || t || '—'
}

function levelLabel(level: string) {
  return ({ info: '正常', warn: '注意', error: '错误' } as Record<string, string>)[level] || level
}

function levelType(level: string): 'info' | 'warning' | 'danger' {
  if (level === 'error') return 'danger'
  if (level === 'warn') return 'warning'
  return 'info'
}

async function loadAudit() {
  loadingAudit.value = true
  try {
    const params = new URLSearchParams()
    if (auditFilter.username) params.set('username', auditFilter.username)
    if (auditFilter.targetType) params.set('target_type', auditFilter.targetType)
    params.set('limit', String(auditFilter.limit))
    params.set('offset', String((auditPage.value - 1) * auditFilter.limit))
    const data = await api.get<{ items: AuditEntry[]; total: number }>(`/audit?${params}`)
    audit.value = data.items || []
    auditTotal.value = data.total || 0
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loadingAudit.value = false
  }
}

async function loadLogs() {
  loadingLogs.value = true
  try {
    const params = new URLSearchParams()
    if (logFilter.level) params.set('level', logFilter.level)
    if (logFilter.keyword) params.set('keyword', logFilter.keyword)
    params.set('limit', String(logFilter.limit))
    params.set('offset', String((logPage.value - 1) * logFilter.limit))
    const data = await api.get<{ items: LogEntry[]; total: number }>(`/logs?${params}`)
    logs.value = data.items || []
    logTotal.value = data.total || 0
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loadingLogs.value = false
  }
}

async function verify() {
  try {
    verifyResult.value = await api.get<{ intact: boolean; first_broken_id: number }>('/audit/verify')
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

function onAuditPage(p: number) {
  auditPage.value = p
  loadAudit()
}

function onLogPage(p: number) {
  logPage.value = p
  loadLogs()
}

watch(tab, (v) => {
  if (v === 'app' && !logs.value.length) loadLogs()
})

onMounted(async () => {
  await loadAudit()
  await loadLogs()
})
</script>

<style scoped>
.fnwg-pager {
  margin-top: 12px;
  justify-content: flex-end;
}

@media (max-width: 767px) {
  .fnwg-pager {
    justify-content: center;
  }
}
</style>
