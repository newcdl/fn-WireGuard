<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <el-dialog
    :model-value="modelValue"
    title="与另一台 NAS 互联"
    :width="isMobile ? '94%' : '760px'"
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
          <br />
          互联建好后：两台 NAS 可互访对方内网；<strong>连上任一台 NAS 的设备也会自动带上对端内网</strong>，
          可访问两处的机器（已连上的设备需重新扫码一次，让新范围写进它的配置）。
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
              placeholder="192.168.3.0/24（多个用逗号或换行分隔）"
            />
            <div class="fnwg-hint">{{ S.interconnect_peer_lan.hint }}</div>
          </el-form-item>
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">对端对外地址 <FieldLabel :meta="S.interconnect_peer_endpoint" icon-only /></span>
            </template>
            <el-input v-model="form.peer_endpoint" placeholder="可留空，例如 nas-b.example.com:51821" style="width: 300px" />
            <div class="fnwg-hint">{{ S.interconnect_peer_endpoint.hint }}</div>
          </el-form-item>
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">本机暴露给对端 <FieldLabel :meta="S.interconnect_local_lan" icon-only /></span>
            </template>
            <el-input v-model="form.localLAN" type="textarea" :rows="2" :placeholder="detectedHint" />
            <div class="fnwg-hint">{{ S.interconnect_local_lan.hint }}</div>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="saving" @click="create">生成邀请</el-button>
            <span class="fnwg-hint" style="margin-left: 10px">本机这一半会立刻建好并生效</span>
          </el-form-item>
        </el-form>

        <template v-else>
          <el-alert
            v-if="created.port_note"
            type="info"
            :closable="false"
            show-icon
            :title="created.port_note"
            style="margin-bottom: 8px"
          />
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
            <el-button size="small" @click="downloadInvite(created)">下载文件</el-button>
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
            <el-button @click="showExisting">查看已生成的邀请</el-button>
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
          :rows="8"
          placeholder="粘贴邀请内容…"
          style="margin-top: 10px"
        />

        <div class="fnwg-formline" style="margin-top: 10px">
          <span class="fnwg-label-with-help">
            本机监听端口 <FieldLabel :meta="S.interconnect_listen_port" icon-only />
          </span>
          <el-input v-model="importPortText" placeholder="留空 = 自动（默认 51820）" style="width: 220px" />
        </div>
        <div class="fnwg-hint">{{ S.interconnect_listen_port.hint }}</div>

        <div style="margin-top: 10px">
          <el-button :loading="previewing" @click="doPreview">检查一下（先看会做什么）</el-button>
          <span class="fnwg-hint" style="margin-left: 10px">
            检查会把本机已有配置一并核对：隧道网段冲突、两端内网网段相同、公钥或端口重复都会当场说明
          </span>
        </div>

        <template v-if="preview">
          <el-alert
            v-for="(w, i) in preview.warnings"
            :key="i"
            type="warning"
            :closable="false"
            show-icon
            :title="w"
            style="margin: 10px 0 0"
          />
          <el-descriptions :column="isMobile ? 1 : 2" border size="small" style="margin-top: 12px">
            <el-descriptions-item label="将要新建的连接">{{ preview.interface_name }}</el-descriptions-item>
            <el-descriptions-item label="隧道地址">{{ preview.tunnel_address }}</el-descriptions-item>
            <el-descriptions-item label="隧道网段">{{ preview.tunnel_subnet }}</el-descriptions-item>
            <el-descriptions-item label="对端名称">{{ preview.peer_name }}</el-descriptions-item>
            <el-descriptions-item label="本机监听端口">
              <span class="fnwg-mono">{{ preview.listen_port }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="对端地址">
              <span class="fnwg-mono">{{ preview.peer_endpoint || '未提供（由对端发起连接）' }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="放行对端来源" :span="2">
              <span class="fnwg-mono">{{ preview.allowed_ips.join('、') }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="本机暴露给对端" :span="2">
              <span class="fnwg-mono">{{ preview.client_allowed_ips.join('、') }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="会写进策略路由表的网段" :span="2">
              <span v-if="preview.route_subnets.length" class="fnwg-mono">
                {{ preview.route_subnets.join('、') }}
              </span>
              <span v-else class="fnwg-hint">无（放行范围都落在本连接的隧道网段内）</span>
            </el-descriptions-item>
            <el-descriptions-item label="对端已占用的网段" :span="2">
              <span v-if="preview.occupied_by_peer.length" class="fnwg-mono">
                {{ preview.occupied_by_peer.join('、') }}
              </span>
              <span v-else class="fnwg-hint">邀请里没有这项信息（对方版本较旧，或对方也没有其它连接）</span>
            </el-descriptions-item>
          </el-descriptions>
          <div class="fnwg-hint" style="margin-top: 8px">
            点「确认导入」后，上面这些内容就会建到本机（随时可在「我的连接 / 我的设备」里删除）。
          </div>
          <div style="margin-top: 10px">
            <el-button
              type="primary"
              :loading="importing"
              :disabled="!previewFresh"
              @click="doImport"
            >
              确认导入
            </el-button>
            <span v-if="!previewFresh" class="fnwg-hint" style="margin-left: 10px">
              上面的内容已经变了，请重新点一次「检查一下」
            </span>
          </div>
        </template>

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
            <el-descriptions-item label="本机监听端口">
              <span class="fnwg-mono">{{ imported.listen_port }}</span>
            </el-descriptions-item>
            <el-descriptions-item label="对外访问地址">
              <span class="fnwg-mono">{{ imported.public_endpoint || '未配置' }}</span>
            </el-descriptions-item>
          </el-descriptions>
          <el-alert
            v-if="imported.port_note"
            type="info"
            :closable="false"
            show-icon
            :title="imported.port_note"
            style="margin-top: 10px"
          />
          <div v-else class="fnwg-hint" style="margin-top: 8px">
            请确认路由器或内网穿透把「对外访问地址的端口」转到了本机 {{ imported.listen_port }} 端口。
          </div>
        </template>
      </el-tab-pane>

      <!-- 已生成的邀请：给对面重装/换机、或当时没保存时再取一份 -->
      <el-tab-pane label="已生成的邀请" name="existing">
        <div class="fnwg-hint">
          这里列出本机现有的互联条目。<strong>邀请是按「当前设置」重新生成的</strong>：
          如果你改过对外地址或暴露给对端的网段，请把新的这份重新交给对端导入才会生效。
          <FieldLabel :meta="S.interconnect_existing" icon-only />
        </div>
        <div style="margin-top: 8px">
          <el-button size="small" :loading="loadingExisting" @click="loadExisting">刷新</el-button>
        </div>

        <div v-if="!existing.length && !loadingExisting" class="fnwg-empty">
          本机还没有「与另一台 NAS 互联」建出来的条目。
          <div v-if="manualSites.length" class="fnwg-hint" style="margin-top: 6px; text-align: left">
            检测到 {{ manualSites.length }} 条<strong>看起来像对端 NAS 的条目</strong>（
            {{ manualSites.join('、') }}）：它们的准入地址里带着隧道之外的网段，说明链路是通的，
            但不是用互联向导建的（备注不是「{{ siteRemark }}」），所以这里没有它们，本应用也无法替它们重现邀请。
            <br />
            想让这里能再取一份邀请：用「生成邀请」按同样的网段重建一条（推荐），
            或到「我的设备」把那条对端条目的备注改成以「{{ siteRemark }}」开头 —— 后者只是让列表认得它，
            网段信息仍以该条目里登记的内容为准。
          </div>
          <div v-else class="fnwg-hint" style="margin-top: 6px; text-align: left">
            这个列表只认互联向导写下的「{{ siteRemark }}」标记。想以后能随时再取一份邀请，请用「生成邀请」建一条。
          </div>
        </div>
        <el-table v-if="existing.length" :data="existing" size="small" style="margin-top: 10px">
          <el-table-column prop="peerName" label="对端名称" min-width="120" />
          <el-table-column prop="interfaceName" label="连接" width="90" />
          <el-table-column label="对端隧道地址" min-width="140">
            <template #default="{ row }">
              <span class="fnwg-mono">{{ row.tunnelAddress || '未知' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="对端内网" min-width="150">
            <template #default="{ row }">
              <span class="fnwg-mono">{{ remoteLANs(row) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="80">
            <template #default="{ row }">
              <el-tag size="small" :type="row.online ? 'success' : 'info'" effect="plain">
                {{ row.online ? '在线' : '离线' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="110" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" :loading="viewing === row.peerId" @click="viewInvite(row)">
                查看邀请
              </el-button>
            </template>
          </el-table-column>
        </el-table>

        <template v-if="viewed">
          <el-alert
            v-if="viewed.port_note"
            type="info"
            :closable="false"
            show-icon
            :title="viewed.port_note"
            style="margin: 12px 0 0"
          />
          <el-alert
            v-for="(w, i) in viewed.warnings"
            :key="i"
            type="warning"
            :closable="false"
            show-icon
            :title="w"
            style="margin: 8px 0 0"
          />
          <div class="fnwg-invoke-head">
            <strong>邀请：{{ viewedPeerName }}</strong>
            <div style="flex: 1"></div>
            <el-button size="small" @click="copy(viewed.invite_json)">复制</el-button>
            <el-button size="small" @click="downloadInvite(viewed)">下载文件</el-button>
          </div>
          <el-input :model-value="viewed.invite_json" type="textarea" :rows="12" readonly />
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
import type {
  InterconnectCreated,
  InterconnectImportInput,
  InterconnectImported,
  InterconnectInput,
  InterconnectPreview,
  NetworkCheckResult,
  WgInterface,
  WgPeer,
} from '@/api/types'
import FieldLabel from '@/components/FieldLabel.vue'
import { interconnectFields as S } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { copyText } from '@/utils/clipboard'

type TabName = 'create' | 'import' | 'existing'

const props = defineProps<{
  modelValue: boolean
  /** 打开时落在哪个页签（默认「生成邀请」） */
  initialTab?: TabName
  /** 打开后直接查看这条条目的邀请（配合 initialTab='existing'） */
  focusPeerId?: number
}>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; done: [] }>()

/** 「已生成的邀请」里的一行：本机某条互联条目 + 它对应的对端信息。 */
interface ExistingRow {
  peerId: number
  peerName: string
  interfaceName: string
  tunnelAddress: string
  allowedIps: string[]
  online: boolean
}

const { isMobile } = useBreakpoint()
const tab = ref<TabName>('create')
const saving = ref(false)
const importing = ref(false)
const created = ref<InterconnectCreated | null>(null)
const imported = ref<InterconnectImported | null>(null)
const previewing = ref(false)
const preview = ref<InterconnectPreview | null>(null)
/**
 * 这份预检是「基于什么输入」算出来的。
 *
 * 必须记下来并在确认前比对：用户先点了检查、又改了粘贴的文本或端口，
 * 若还能确认，他就是在「A 的清单」上按了确认、实际执行下去的却是 B ——
 * 这类不一致只能靠事后比对发现，所以在这里直接拦住（见 previewFresh）。
 */
const previewForKey = ref('')
const importText = ref('')
// 端口用文本承载：留空表示自动分配（数字输入框在「留空」这个语义上不好用）
const importPortText = ref('')
/** 探测到的本机网段，作为「暴露给对端」的默认值提示。 */
const detected = ref<string[]>([])

const existing = ref<ExistingRow[]>([])
const loadingExisting = ref(false)
// 准入地址里带着「隧道之外网段」、但没有向导标记的条目：多半是手工配的站点链路。
// 只在列表为空时提示，避免平时打扰（正常设备条目的准入地址只有一个 /32）。
const manualSites = ref<string[]>([])
const viewed = ref<InterconnectCreated | null>(null)
const viewedPeerName = ref('')
const viewing = ref(0)
/** 互联向导写在设备备注里的标记（后端 InterconnectRemark）：这个列表只认它。 */
const siteRemark = '站点互联'

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

/** 对端内网 = 准入地址里去掉「对端自己的隧道地址」（/32）。 */
function remoteLANs(row: ExistingRow): string {
  const lans = row.allowedIps.filter((a) => !a.endsWith('/32'))
  return lans.length ? lans.join('、') : '未配置'
}

async function loadDetected(): Promise<void> {
  try {
    const net = await api.get<NetworkCheckResult>('/system/network')
    detected.value = net.home_subnets || []
  } catch {
    // 探测不到不影响使用：用户可以手工填写
  }
}

async function loadExisting(): Promise<void> {
  // 并发去重：页签的 watcher 与打开对话框时的调用可能同时触发，没必要读两遍
  if (loadingExisting.value) return
  loadingExisting.value = true
  try {
    const [ifs, prs] = await Promise.all([
      api.get<{ items: WgInterface[] }>('/interfaces'),
      api.get<{ items: WgPeer[] }>('/peers'),
    ])
    const byId = new Map<number, WgInterface>()
    for (const it of ifs.items) byId.set(it.id, it)
    existing.value = prs.items
      .filter((p) => p.site_link)
      .map((p) => ({
        peerId: p.id,
        peerName: p.name || '未命名',
        interfaceName: byId.get(p.interface_id)?.name || p.interface_name || '',
        tunnelAddress: (p.allowed_ips || []).find((a) => a.endsWith('/32')) || '',
        allowedIps: p.allowed_ips || [],
        online: !!p.online,
      }))
    manualSites.value = prs.items
      .filter((p) => !p.site_link && (p.allowed_ips || []).some((a) => !a.endsWith('/32')))
      .map((p) => p.name || '未命名')
  } catch (e) {
    ElMessage.error((e as Error)?.message || '读取互联条目失败')
  } finally {
    loadingExisting.value = false
  }
}

/** 切到「已生成的邀请」并取数；focusId 用于从设备列表点进来时直接展开某一条的邀请。 */
async function openExisting(focusId?: number): Promise<void> {
  tab.value = 'existing'
  viewed.value = null
  await loadExisting()
  if (!focusId) return
  const row = existing.value.find((r) => r.peerId === focusId)
  if (row) await viewInvite(row)
}

async function viewInvite(row: ExistingRow): Promise<void> {
  viewing.value = row.peerId
  try {
    viewed.value = await api.get<InterconnectCreated>(`/interconnect/invite/${row.peerId}`)
    viewedPeerName.value = row.peerName
  } catch (e) {
    viewed.value = null
    ElMessage.error((e as Error)?.message || '读取邀请失败')
  } finally {
    viewing.value = 0
  }
}

async function showExisting(): Promise<void> {
  await openExisting()
}

async function create(): Promise<void> {
  saving.value = true
  try {
    // 请求体的形状用 types.ts 里的类型钉住：后端字段名一改，这里编译期就会报错，
    // 而不是等到运行时报「缺少参数」。
    const body: InterconnectInput = {
      peer_name: form.peer_name.trim(),
      peer_lan_subnets: splitSubnets(form.peerLAN),
      peer_endpoint: form.peer_endpoint.trim(),
      local_lan_subnets: splitSubnets(form.localLAN),
    }
    created.value = await api.post<InterconnectCreated>('/interconnect', body)
    ElMessage.success('本机这一半已建好，把邀请交给另一台 NAS 导入即可')
    // 立刻通知外层刷新列表：本机这一半（连接 + 对端条目）这一下就已经建好了。
    //
    // 原先只在「导入成功」后通知，于是「生成邀请 → 复制配置 → 关掉对话框」这条
    // 最常见的路径会让列表一直是旧的 —— 用户关掉对话框后看到的是一份
    // 没有刚建那条连接的列表，只能自己按刷新（真机反馈过）。
    emit('done')
  } catch (e) {
    ElMessage.error((e as Error)?.message || '生成邀请失败')
  } finally {
    saving.value = false
  }
}

/** 端口输入 → 请求值；非法时提示并返回 null（0 表示交给后端自动分配）。 */
function parseImportPort(): number | null {
  const raw = importPortText.value.trim()
  if (!raw) return 0
  if (!/^\d+$/.test(raw)) {
    ElMessage.error('「本机监听端口」请填 1–65535 的数字，或留空交给自动分配')
    return null
  }
  return Number(raw)
}

/** 当前输入对应的「预检身份」：文本 + 端口，任一变化都让已算好的预检作废。 */
function previewKey(): string {
  return `${importText.value.trim()}|${importPortText.value.trim()}`
}

/** 已算好的预检是否仍对应当前输入（不对应时不允许确认，必须重新检查一遍）。 */
const previewFresh = computed(() => preview.value !== null && previewForKey.value === previewKey())

/**
 * 预检：只读地问后端「这次导入会做什么」，把清单摆给用户看。
 *
 * 为什么不让「导入」一步到位：导入会一次建出连接 + 对端条目，并往策略路由表里写网段。
 * 在此之前用户看到的只有一段看不懂的文本，直接建完再报告「做了什么」，
 * 他就只能靠事后去两个页面里逐个核对。
 */
async function doPreview(): Promise<void> {
  const port = parseImportPort()
  if (port === null) return
  previewing.value = true
  try {
    // 与执行导入共用同一个请求体类型：这两步一旦形状不一致，
    // 确认框里的清单就与实际执行的内容无关了（见 previewFresh）。
    const body: InterconnectImportInput = { text: importText.value, listen_port: port }
    const p = await api.post<InterconnectPreview>('/interconnect/import/preview', body)
    // 把预检选定的端口回填进输入框：用户看到的就是最终会用的那个，确认后也按它建。
    importPortText.value = String(p.listen_port)
    preview.value = p
    previewForKey.value = previewKey()
  } catch (e) {
    preview.value = null
    previewForKey.value = ''
    ElMessage.error((e as Error)?.message || '检查失败')
  } finally {
    previewing.value = false
  }
}

async function doImport(): Promise<void> {
  if (!previewFresh.value) {
    ElMessage.warning('请先点「检查一下」看一遍将要做什么，确认后再导入')
    return
  }
  const port = parseImportPort()
  if (port === null) return
  importing.value = true
  try {
    const body: InterconnectImportInput = { text: importText.value, listen_port: port }
    imported.value = await api.post<InterconnectImported>('/interconnect/import', body)
    preview.value = null
    previewForKey.value = ''
    ElMessage.success('已导入：本机侧连接与对端条目都建好了')
    emit('done')
  } catch (e) {
    imported.value = null
    ElMessage.error((e as Error)?.message || '导入失败')
  } finally {
    importing.value = false
  }
}

function downloadInvite(obj: InterconnectCreated): void {
  // 邀请是本地生成的文本，不走服务端下载：拼一个 Blob 直接存文件。
  const blob = new Blob([obj.invite_json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `fnwg-interconnect-${obj.interface_name || 'invite'}.json`
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
  // 预检结果同样要清掉：它只是「刚才那份输入会做什么」的快照，
  // 留着会让下次打开时看到一份与当前输入无关的清单。
  preview.value = null
  previewForKey.value = ''
  viewed.value = null
  viewedPeerName.value = ''
  importText.value = ''
  importPortText.value = ''
  tab.value = 'create'
  form.peer_name = ''
  form.peerLAN = ''
  form.peer_endpoint = ''
  form.localLAN = ''
}

// 每次打开时按需取数（对话框只创建一次，不能只在 setup 里做一次）
watch(
  () => props.modelValue,
  (open) => {
    if (!open) return
    void loadDetected()
    const want = props.initialTab || 'create'
    if (want === 'existing') {
      void openExisting(props.focusPeerId)
      return
    }
    tab.value = want
  },
  { immediate: true },
)

// 页签被手动点击时也要取数：否则「已生成的邀请」点进去永远空空如也，
// 用户只会以为「我以前生成的邀请丢了」（真机踩到过）。
watch(tab, (v) => {
  if (v === 'existing') void openExisting()
})
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

.fnwg-formline {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.fnwg-empty {
  padding: 18px 0;
  text-align: center;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
</style>
