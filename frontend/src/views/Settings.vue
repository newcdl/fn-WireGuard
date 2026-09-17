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
              <el-button v-if="session.isAdmin" type="primary" :loading="savingSettings" @click="saveSettings">
                保存
              </el-button>
              <span v-else class="fnwg-hint">仅管理员可以修改这些设置</span>
            </el-form-item>
          </el-form>
        </div>
      </el-tab-pane>

      <!-- 事件通知 -->
      <el-tab-pane label="事件通知" name="notify">
        <el-alert v-if="!notifyStatus?.configured" type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            填一个推送地址就能收到告警：设备上下线、到期、流量用尽、连接中断、配置下发失败都会发到这里。
            留空则完全不推送，连接与设备的行为不受任何影响。
          </template>
        </el-alert>

        <div class="fnwg-card" style="max-width: 900px">
          <el-form :model="notify" class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="150px">
            <el-form-item>
              <template #label><FieldLabel :meta="S.notify_webhook" /></template>
              <el-input
                v-model="notify.webhook"
                placeholder="留空则不推送，例如 https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
              />
              <!-- 地址写错的表现是「配完了但一直没动静」，所以问题必须当场说清 -->
              <div v-if="notifyStatus?.problem" class="fnwg-row-warn">{{ notifyStatus.problem }}</div>
              <FieldTips :meta="S.notify_webhook" example />
            </el-form-item>

            <el-form-item>
              <template #label><FieldLabel :meta="S.notify_format" /></template>
              <el-select v-model="notify.format" style="max-width: 460px">
                <el-option label="JSON（默认，适合脚本与自动化平台）" value="json" />
                <el-option label="纯文本（适合自建推送服务）" value="text" />
                <el-option label="Markdown（钉钉 / 企业微信 / 飞书群机器人）" value="markdown" />
              </el-select>
              <FieldTips :meta="S.notify_format" example />
            </el-form-item>

            <el-form-item>
              <template #label><FieldLabel :meta="S.notify_off" /></template>
              <div v-if="!notifyStatus" class="fnwg-hint">正在读取可推送的事件…</div>
              <div v-else style="width: 100%">
                <div v-for="g in notifyStatus.groups" :key="g.key" style="margin-bottom: 8px">
                  <div style="font-size: 13px; opacity: 0.7; margin-bottom: 2px">{{ g.label }}</div>
                  <el-checkbox-group v-model="notifyEvents">
                    <el-checkbox
                      v-for="k in kindsOf(g.key)"
                      :key="k.kind"
                      :value="k.kind"
                      class="fnwg-radio-line"
                    >
                      {{ k.label }}
                      <span class="fnwg-radio-desc">{{ k.detail }}</span>
                    </el-checkbox>
                  </el-checkbox-group>
                </div>
                <div class="fnwg-hint">
                  未勾选的事件不会推送；已开启 {{ notifyEvents.length }} / {{ notifyStatus.all_kinds.length }} 类。
                  勾选状态随「保存」一起生效。
                </div>
              </div>
            </el-form-item>

            <el-form-item label="通知自检">
              <div>
                <el-button
                  v-if="session.isAdmin"
                  :loading="testingNotify"
                  :disabled="!notify.webhook"
                  @click="sendTestNotify"
                >
                  发送测试通知
                </el-button>
                <span v-else class="fnwg-hint">仅管理员可以发送测试通知</span>
              </div>
              <!-- 只说「已保存」不够：用户真正要知道的是「到底有没有发出去、发的是什么」 -->
              <div class="fnwg-hint" style="margin-top: 6px">
                发送测试会先保存上面的地址、格式与事件开关，再立刻推送一条，因此可以当场确认配置是否正确。
              </div>
              <div v-if="notifyStatus?.last" class="fnwg-hint" style="margin-top: 6px">
                最近一次：{{ formatTime(notifyStatus.last.at) }}
                <el-tag
                  size="small"
                  :type="notifyStatus.last.ok ? 'success' : 'danger'"
                  effect="plain"
                  style="margin: 0 6px"
                >
                  {{ notifyStatus.last.ok ? '成功' : '失败' }}
                </el-tag>
                {{ notifyStatus.last.message }}
              </div>
              <div v-else class="fnwg-hint" style="margin-top: 6px">还没有发送记录。</div>

              <el-collapse v-if="notifyStatus?.last?.payload" style="margin-top: 8px; width: 100%">
                <el-collapse-item title="查看实际发出的内容（排障用）">
                  <div
                    style="
                      white-space: pre-wrap;
                      word-break: break-all;
                      font-family: monospace;
                      font-size: 12px;
                      line-height: 1.6;
                    "
                  >
                    {{ notifyStatus.last.payload }}
                  </div>
                </el-collapse-item>
              </el-collapse>
            </el-form-item>

            <el-form-item>
              <el-button v-if="session.isAdmin" type="primary" :loading="savingNotify" @click="saveNotify">
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

      <!-- 内网域名：让设备用主机名访问家里设备 -->
      <el-tab-pane label="内网域名" name="dns">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            让连进来的设备用「主机名」访问家里设备（例如手机浏览器输入 nas.lan），不用去记 IP。
            开启后，下发给设备的 DNS 会指向本连接的隧道地址，由本应用代为解析：登记的域名由本应用应答，
            其余上网域名原样转发到你在连接里配置的 DNS。
          </template>
        </el-alert>

        <el-form-item>
          <template #label><FieldLabel :meta="S.dns_resolve" /></template>
          <el-switch
            v-model="dnsEnabled"
            :disabled="!session.isAdmin"
            :before-change="confirmDNSChange"
            active-text="开启内网域名解析"
            @change="saveDNSEnabled"
          />
          <FieldTips :meta="S.dns_resolve" />
          <div v-if="!session.isAdmin" class="fnwg-hint">仅管理员可以修改这项开关。</div>
        </el-form-item>

        <!--
          这条提示必须醒目：改动开关会波及**所有已接入设备**。
          用户最容易误解的就是「改完就生效了」—— 实际上设备用的是它自己那份配置，
          服务端改不到，必须让用户事先知道要重新扫码，并知道为什么。
        -->
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>注意：改动这个开关后，所有已接入的设备都需要重新扫码</template>
          <div class="fnwg-dns-warn">
            <p>
              <strong>为什么：</strong>DNS 是写在「设备自己那份配置」里的。手机、电脑连上后用的是它当初扫码导入的那份配置，
              NAS 这边改不到设备里的东西，所以服务端换了 DNS，设备并不会自动知道。
            </p>
            <p>
              <strong>怎么做：</strong>改动后，设备列表里这些设备会被标出「<strong>需重新扫码</strong>」，
              点一下重新生成二维码、用设备再扫一次即可。<strong>不需要删除设备</strong>，设备上的其它设置也不会变。
            </p>
          </div>
        </el-alert>

        <!-- 运行状态：只说「开关是开着的」不够，用户要知道它到底有没有在工作 -->
        <el-alert
          v-if="dnsStatus?.enabled && !(dnsStatus.listen || []).length"
          type="warning"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
          :title="`已开启但解析服务还没生效：${dnsStatus.note || '当前没有可用的隧道地址（连接可能未启用）'}`"
        />
        <div v-else-if="dnsStatus?.enabled" class="fnwg-hint" style="margin-bottom: 12px">
          正在监听 {{ (dnsStatus.listen || []).join('、') }}，已登记 {{ dnsStatus.records }} 条记录，
          累计查询 {{ dnsStatus.queries }} 次<template v-if="dnsStatus.failed">（失败 {{ dnsStatus.failed }} 次）</template>。
        </div>

        <div class="fnwg-toolbar">
          <el-button v-if="session.can('iface.write')" type="primary" :icon="Plus" @click="openDNSRecord()">
            添加域名
          </el-button>
          <el-button :icon="Refresh" @click="loadDNS">刷新</el-button>
          <div style="flex: 1"></div>
          <span class="fnwg-hint">共 {{ dnsRecords.length }} 条</span>
        </div>

        <el-table :data="dnsRecords" size="small" empty-text="还没有域名记录">
          <el-table-column prop="name" label="主机名" min-width="160" />
          <el-table-column prop="ip" label="指向的地址" min-width="140" />
          <el-table-column prop="note" label="备注" min-width="140" />
          <el-table-column label="操作" width="140">
            <template #default="{ row }">
              <el-button v-if="session.can('iface.write')" link type="primary" @click="openDNSRecord(row)">
                编辑
              </el-button>
              <el-button v-if="session.can('iface.write')" link type="danger" @click="removeDNSRecord(row)">
                删除
              </el-button>
            </template>
          </el-table-column>
        </el-table>

        <!-- 新增 / 编辑域名 -->
        <el-dialog v-model="dnsVisible" :title="dnsForm.id ? '编辑域名' : '添加域名'" :width="dialogWidth || '460px'">
          <el-form class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="100px">
            <el-form-item>
              <template #label><FieldLabel :meta="S.dns_name" /></template>
              <el-input v-model="dnsForm.name" placeholder="例如 nas.lan" />
              <FieldTips :meta="S.dns_name" example />
            </el-form-item>
            <el-form-item>
              <template #label><FieldLabel :meta="S.dns_ip" /></template>
              <el-input v-model="dnsForm.ip" placeholder="例如 192.168.1.10" />
              <FieldTips :meta="S.dns_ip" example />
            </el-form-item>
            <el-form-item label="备注">
              <el-input v-model="dnsForm.note" placeholder="例如 家里的 NAS" />
            </el-form-item>
          </el-form>
          <template #footer>
            <el-button @click="dnsVisible = false">取消</el-button>
            <el-button type="primary" :loading="dnsSaving" @click="saveDNSRecord">保存</el-button>
          </template>
        </el-dialog>
      </el-tab-pane>

      <!-- 备份与还原 -->
      <el-tab-pane label="备份还原" name="backup">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            备份会保存全部连接、设备、系统设置与账号（含管理员密码与密钥），换机或误删后可一键完整还原。建议在每次大改动前先备份一次。
          </template>
        </el-alert>

        <div class="fnwg-toolbar">
          <el-button v-if="session.can('backup.restore')" type="primary" :icon="Plus" @click="createBackup">
            立即备份
          </el-button>
          <el-button v-if="session.can('backup.restore')" :icon="Upload" @click="openImportBackup">
            导入备份
          </el-button>
          <input
            ref="backupFileInput"
            type="file"
            accept=".json,application/json"
            style="display: none"
            @change="onImportFile"
          />
          <div style="flex: 1"></div>
          <span class="fnwg-hint">备份文件位置：{{ shareDir || '-' }}</span>
        </div>

        <div v-if="!isMobile" class="fnwg-card">
          <el-table :data="backups" size="small" empty-text="还没有备份">
            <el-table-column prop="filename" label="备份文件" min-width="240" />
            <el-table-column label="大小" width="100">
              <template #default="{ row }">{{ formatBytes(row.size) }}</template>
            </el-table-column>
            <el-table-column label="备份内容" width="110">
              <template #default>
                <el-tag size="small" type="warning" effect="plain">全量备份</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="备份时间" width="180">
              <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
            </el-table-column>
            <el-table-column prop="note" label="备注" min-width="140" />
            <el-table-column label="操作" width="200">
              <template #default="{ row }">
                <el-button v-if="session.can('backup.restore')" link type="primary" @click="restore(row)">还原</el-button>
                <el-button v-if="session.can('backup.restore')" link type="primary" @click="downloadBackup(row)">下载</el-button>
                <el-button v-if="session.can('backup.restore')" link type="danger" @click="removeBackup(row)">删除</el-button>
              </template>
            </el-table-column>
          </el-table>
        </div>

        <div v-else>
          <ItemCard v-for="row in backups" :key="row.id" :title="row.filename">
            <template #extra>
              <el-tag size="small" type="warning" effect="plain">全量备份</el-tag>
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
              <el-button v-if="session.can('backup.restore')" size="small" @click="downloadBackup(row)">下载</el-button>
              <el-button v-if="session.can('backup.restore')" size="small" @click="removeBackup(row)">删除</el-button>
            </template>
          </ItemCard>
          <div v-if="!backups.length" class="fnwg-empty">还没有备份</div>
        </div>
      </el-tab-pane>

      <!-- 关于 -->
      <el-tab-pane label="关于" name="about">
        <div class="fnwg-card" style="max-width: 760px">
          <h3 style="margin-top: 0">WireGuard 管理工具</h3>
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
import { Plus, Upload, Reading, Refresh } from '@element-plus/icons-vue'
import { api, download, postRaw } from '@/api/client'
import type { BackupRecord, DNSRecord, Health, NotifyResult, NotifyStatus, User } from '@/api/types'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import FieldLabel from '@/components/FieldLabel.vue'
import FieldTips from '@/components/FieldTips.vue'
import ItemCard from '@/components/ItemCard.vue'
import { allHelpGroups, settingFields, userFields } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { refreshSystemHealth, useSystemHealth } from '@/composables/useSystemHealth'
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
})
const savingSettings = ref(false)

// 事件通知单独一组状态，与「接入设置」各自保存：
// 改通知渠道不该连带改动对外访问地址这类会影响所有设备的配置。
const notify = reactive({ webhook: '', format: 'json' })
const savingNotify = ref(false)
// 通知能力的状态与事件开关。
// 事件清单与分组都由后端下发：前后端各维护一份，迟早出现「界面能勾、后端不认识」的选项。
const notifyStatus = ref<NotifyStatus | null>(null)
const notifyEvents = ref<string[]>([])
const testingNotify = ref(false)
const health = ref<Health | null>(null)
const helpVisible = ref(false)

const users = ref<User[]>([])
const userDialog = ref(false)
const newUser = reactive({ username: '', password: '', role: 'viewer' })

const backups = ref<BackupRecord[]>([])
const shareDir = ref('')
const backupFileInput = ref<HTMLInputElement | null>(null)

// 内网域名解析：开关走设置项，记录走独立接口；
// 运行状态复用全局体检的同一份数据，避免「设置页说正常、维护页说异常」。
const dnsEnabled = ref(false)
const dnsRecords = ref<DNSRecord[]>([])
const dnsVisible = ref(false)
const dnsSaving = ref(false)
const dnsForm = reactive({ id: 0, name: '', ip: '', note: '' })
const { net } = useSystemHealth()
const dnsStatus = computed(() => net.value?.dns)

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
    })
    notify.webhook = kv.notify_webhook || ''
    notify.format = (['text', 'markdown'] as string[]).includes(kv.notify_format || '')
      ? kv.notify_format
      : 'json'
    dnsEnabled.value = kv.dns_resolve_enabled === '1'
  } catch {
    /* 忽略 */
  }
  await loadNotify()
  await loadHealth()
  if (session.isAdmin) await loadUsers()
  await loadBackups()
  await loadDNS()
  void refreshSystemHealth()
}

async function loadDNS() {
  try {
    const data = await api.get<{ items: DNSRecord[] }>('/dns/records')
    dnsRecords.value = data.items || []
  } catch {
    /* 忽略 */
  }
}

/** 改动开关会波及所有已接入设备，先让用户确认（返回 false 表示不改）。 */
function confirmDNSChange(): Promise<boolean> {
  const turningOn = !dnsEnabled.value
  return ElMessageBox.confirm(
    `${turningOn ? '开启' : '关闭'}后，下发给设备的 DNS 会${
      turningOn ? '改成本连接的隧道地址' : '恢复成你在连接里配置的 DNS'
    }。\n\n` +
      'DNS 写在设备自己那份配置里，服务端改不到它，所以：\n' +
      '所有已接入的设备都需要重新扫码导入一次才会生效。\n\n' +
      '设备列表会标出「需重新扫码」，点一下重新生成二维码即可，不需要删除设备。',
    turningOn ? '确认开启内网域名解析？' : '确认关闭内网域名解析？',
    { type: 'warning', confirmButtonText: turningOn ? '确认开启' : '确认关闭', cancelButtonText: '先不改' },
  )
    .then(() => true)
    .catch(() => false)
}

async function saveDNSEnabled() {
  const v = dnsEnabled.value ? '1' : ''
  try {
    await api.put('/settings', { dns_resolve_enabled: v })
    ElMessage.success(
      v
        ? '已开启：请到设备列表，对标记「需重新扫码」的设备重新生成二维码'
        : '已关闭：设备同样需要重新扫码才会恢复原来的 DNS',
    )
    await refreshSystemHealth()
  } catch (e) {
    dnsEnabled.value = !dnsEnabled.value // 保存失败要回滚，否则界面显示的开关状态是假的
    ElMessage.error((e as Error).message)
  }
}

function openDNSRecord(row?: DNSRecord) {
  Object.assign(
    dnsForm,
    row ? { id: row.id, name: row.name, ip: row.ip, note: row.note } : { id: 0, name: '', ip: '', note: '' },
  )
  dnsVisible.value = true
}

async function saveDNSRecord() {
  dnsSaving.value = true
  try {
    const payload = { name: dnsForm.name, ip: dnsForm.ip, note: dnsForm.note }
    if (dnsForm.id) await api.patch(`/dns/records/${dnsForm.id}`, payload)
    else await api.post('/dns/records', payload)
    ElMessage.success('已保存')
    dnsVisible.value = false
    await loadDNS()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    dnsSaving.value = false
  }
}

async function removeDNSRecord(row: DNSRecord) {
  try {
    await ElMessageBox.confirm(`确认删除域名「${row.name}」？删除后设备将无法再用它访问。`, '删除域名', {
      type: 'warning',
    })
    await api.del(`/dns/records/${row.id}`)
    ElMessage.success('已删除')
    await loadDNS()
  } catch (e) {
    if (e !== 'cancel') ElMessage.error((e as Error).message)
  }
}

async function loadNotify() {
  try {
    const st = await api.get<NotifyStatus>('/system/notify')
    notifyStatus.value = st
    notifyEvents.value = st.events || []
  } catch {
    // 读不到时保持 null：此时提交事件开关会被理解成「全部关闭」，
    // 那等于把用户的推送静默关掉，宁可不提交这一项。
    notifyStatus.value = null
  }
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

/** kindsOf 取某个分组下的事件（用于分组渲染开关）。 */
function kindsOf(group: string) {
  return (notifyStatus.value?.all_kinds || []).filter((k) => k.group === group)
}

/** persistNotify 保存通知设置（地址、格式、事件开关），不触碰接入设置。 */
async function persistNotify() {
  const payload: Record<string, string> = {
    notify_webhook: notify.webhook,
    notify_format: notify.format,
  }
  if (notifyStatus.value) {
    // 后端存的是「被明确关闭的事件」，这里把未勾选的换算出来。
    // 关掉全部事件时会写满所有类型 —— 与「没配置过（全部开启）」区分得清清楚楚。
    const enabled = new Set(notifyEvents.value)
    payload.notify_off = notifyStatus.value.all_kinds
      .filter((k) => !enabled.has(k.kind))
      .map((k) => k.kind)
      .join(',')
  }
  await api.put('/settings', payload)
  await loadNotify()
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

async function saveNotify() {
  savingNotify.value = true
  try {
    await persistNotify()
    ElMessage.success('已保存')
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    savingNotify.value = false
  }
}

async function sendTestNotify() {
  testingNotify.value = true
  try {
    // 先保存再测试：否则测的是上次保存的地址与格式，
    // 用户会以为新填的配置不通，而实际上只是还没保存
    await persistNotify()
    const res = await api.post<NotifyResult>('/system/notify/test')
    if (res.ok) ElMessage.success(res.message)
    else ElMessage.error(res.message)
    await loadNotify()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    testingNotify.value = false
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
  try {
    await api.post('/backups', { note })
    ElMessage.success('备份已完成')
    await loadBackups()
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}

async function restore(row: BackupRecord) {
  try {
    await ElMessageBox.confirm(
      `还原将用备份「${row.filename}」覆盖当前的全部连接、设备、系统设置与账号（含管理员密码），现有配置会被替换。确认继续？`,
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

function downloadBackup(row: BackupRecord) {
  download(`/backups/${row.id}/download`)
}

function openImportBackup() {
  backupFileInput.value?.click()
}

async function onImportFile(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  try {
    const text = await file.text()
    await postRaw(`/backups/import?filename=${encodeURIComponent(file.name)}`, text)
    ElMessage.success('备份已导入，可在列表中选择「还原」')
    await loadBackups()
  } catch (err) {
    ElMessage.error((err as Error).message)
  }
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

/* 内网域名解析的影响提示：正文分「为什么 / 怎么做」两段，行距放松一点便于扫读 */
.fnwg-dns-warn {
  font-size: 12.5px;
  line-height: 1.7;
}

.fnwg-dns-warn p {
  margin: 4px 0 0;
}

.fnwg-about-text {
  color: var(--el-text-color-regular);
  line-height: 1.9;
  font-size: 13.5px;
}

</style>
