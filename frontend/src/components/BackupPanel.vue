<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
备份与还原。

一个页面同时管三件事：现在备份、定时备份、把备份拿回来。它们以前分成两块
（上面「备份列表」、下面「计划备份」，各自还带一份副本列表），结果是同一批东西
出现在两个地方，而用户最需要一眼看清的「我到底有没有能用的备份」反而要自己对。
现在合并成一个列表：本机的备份与计划备份写到共享文件夹的副本都在这里，
来源用标签区分，可按来源筛选、按文件名或备注搜索。

说明文字从「铺在页面上的几行灰字」改成字段旁的问号（点击开气泡，内容不变）：
字段一多，那几行灰字会连成一大片，真正要看的输入框反而找不到。
-->
<template>
  <div>
    <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
      <template #title>
        备份会保存全部连接、设备、系统设置与账号（含管理员密码与密钥），换机或误删后可一键完整还原。建议在每次大改动前先备份一次。
      </template>
    </el-alert>

    <!--
      失败提示常驻在页面顶部，而不是一闪而过的消息条：
      这里的失败大多需要用户做点什么（去授权目录、重新导一份文件），
      一句话说完就消失，等于让人凭记忆去猜「刚才那句说的是什么」。
    -->
    <el-alert
      v-if="problem"
      type="error"
      show-icon
      closable
      :title="problem.title"
      style="margin-bottom: 12px"
      @close="problem = null"
    >
      <div class="fnwg-problem-msg">{{ problem.message }}</div>
      <div v-if="problem.advice" class="fnwg-problem-advice">可以这样处理：{{ problem.advice }}</div>
    </el-alert>

    <div class="fnwg-toolbar">
      <el-button v-if="can" type="primary" :icon="Plus" @click="openCreate">立即备份</el-button>
      <FieldLabel v-if="can" :meta="B.backup_now" icon-only />
      <el-button v-if="can" :icon="Upload" @click="openImportBackup">导入备份</el-button>
      <FieldLabel v-if="can" :meta="B.backup_import" icon-only />
      <input
        ref="fileInput"
        type="file"
        accept=".json,application/json"
        style="display: none"
        @change="onImportFile"
      />

      <div style="flex: 1"></div>

      <!-- 查询：备份一多，「上次那份是什么时候的」就只能靠搜 -->
      <el-input
        v-model="keyword"
        :prefix-icon="Search"
        placeholder="搜索文件名或备注"
        clearable
        style="width: 200px"
      />
      <el-select v-model="source" style="width: 130px">
        <el-option label="全部来源" value="all" />
        <el-option label="本机备份" value="local" />
        <el-option label="计划备份" value="plan" />
      </el-select>
      <el-button :icon="Refresh" :loading="loading" @click="loadAll">刷新</el-button>
      <FieldLabel :meta="B.backup_list" icon-only />
    </div>

    <div class="fnwg-card">
      <div class="fnwg-card-head">
        备份（{{ filtered.length }} / {{ rows.length }} 份）
        <span class="fnwg-hint" style="margin-left: 8px">本机备份目录：{{ shareDir || '-' }}</span>
      </div>

      <!--
        列表为空分两种情况，说的话不一样：
        「一份都没有」要给下一步动作，「搜出来是空的」只说明筛选条件。
        都写成「还没有备份」的话，搜索没命中会让人以为备份全丢了。
      -->
      <div v-if="!rows.length" class="fnwg-empty">
        还没有备份。点「立即备份」现在做一份，或在下面开启「计划备份」让它自动做。
      </div>
      <div v-else-if="!filtered.length" class="fnwg-empty">没有符合条件的备份，换个关键词或来源试试。</div>

      <template v-else>
        <!-- 表格 / 卡片视图：由用户决定并记住（切一次，之后一直用这种） -->
        <ViewSwitch v-model="viewMode" />

        <el-table v-if="isTable" :data="filtered" size="small" style="width: 100%">
          <el-table-column label="来源" width="110">
            <template #default="{ row }">
              <el-tag v-if="row.source === 'local'" size="small" effect="plain">本机</el-tag>
              <el-tooltip v-else :content="`计划备份写到：${row.dir}`" placement="top">
                <el-tag size="small" type="success" effect="plain">计划备份</el-tag>
              </el-tooltip>
            </template>
          </el-table-column>
          <el-table-column label="备份文件" min-width="250">
            <template #default="{ row }">
              <span :class="{ 'fnwg-missing-name': row.missing }">{{ row.name }}</span>
              <el-tag v-if="row.missing" size="small" type="danger" effect="plain" style="margin-left: 6px">
                文件已不在
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="大小" width="90">
            <template #default="{ row }">{{ row.missing ? '—' : formatBytes(row.size) }}</template>
          </el-table-column>
          <el-table-column label="备份时间" width="170">
            <template #default="{ row }">{{ formatTime(row.time) }}</template>
          </el-table-column>
          <el-table-column label="备注" min-width="120">
            <template #default="{ row }">
              <span v-if="row.note">{{ row.note }}</span>
              <span v-else class="fnwg-hint">—</span>
            </template>
          </el-table-column>
          <el-table-column label="操作" width="180">
            <template #default="{ row }">
              <el-button
                v-if="can"
                link
                type="primary"
                :disabled="row.missing"
                :title="row.missing ? '备份文件已经不在了，无法还原' : ''"
                @click="restore(row)"
              >
                还原
              </el-button>
              <el-button
                v-if="can"
                link
                type="primary"
                :disabled="row.missing"
                :title="row.missing ? '备份文件已经不在了，无法下载' : ''"
                @click="downloadRow(row)"
              >
                下载
              </el-button>
              <el-button v-if="can && row.source === 'local'" link type="danger" @click="removeRow(row)">
                删除
              </el-button>
            </template>
          </el-table-column>
        </el-table>

        <div v-else>
          <div class="fnwg-card-grid">
          <ItemCard v-for="row in filtered" :key="row.key" :title="row.name">
            <template #extra>
              <el-tag v-if="row.source === 'local'" size="small" effect="plain">本机</el-tag>
              <el-tag v-else size="small" type="success" effect="plain">计划备份</el-tag>
              <el-tag v-if="row.missing" size="small" type="danger" effect="plain">文件已不在</el-tag>
            </template>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">备份时间</span>
              <span class="fnwg-kv-val">{{ formatTime(row.time) }}</span>
            </div>
            <div class="fnwg-kv">
              <span class="fnwg-kv-key">大小</span>
              <span class="fnwg-kv-val">{{ row.missing ? '—' : formatBytes(row.size) }}</span>
            </div>
            <div v-if="row.note" class="fnwg-kv">
              <span class="fnwg-kv-key">备注</span>
              <span class="fnwg-kv-val">{{ row.note }}</span>
            </div>
            <div v-if="row.source === 'plan'" class="fnwg-kv">
              <span class="fnwg-kv-key">所在目录</span>
              <span class="fnwg-kv-val fnwg-mono">{{ row.dir }}</span>
            </div>
            <template #actions>
              <el-button v-if="can" size="small" type="primary" :disabled="row.missing" @click="restore(row)">
                还原
              </el-button>
              <el-button v-if="can" size="small" :disabled="row.missing" @click="downloadRow(row)">下载</el-button>
              <el-button v-if="can && row.source === 'local'" size="small" @click="removeRow(row)">删除</el-button>
            </template>
          </ItemCard>
          </div>
        </div>

        <div v-if="hasPlanRow" class="fnwg-hint" style="margin-top: 8px">
          计划备份写在共享文件夹里的副本不在这里删除（避免误删共享文件夹里的其它文件），要清理请到飞牛的「文件管理」里操作。
        </div>
      </template>
    </div>

    <!--
      计划备份：一次配置 + 一个长期后台行为，与「现在点一下备份」不是同类操作。
      所以它是一张单独卡片，并且默认收起 —— 配好之后用户真正要看的是上面那份列表。
    -->
    <div v-if="can" class="fnwg-card" style="margin-top: 12px">
      <div class="fnwg-plan-head" @click="planOpen = !planOpen">
        <el-icon class="fnwg-plan-caret" :class="{ 'fnwg-plan-caret-open': planOpen }"><ArrowRight /></el-icon>
        <span class="fnwg-card-head" style="margin: 0">计划备份</span>
        <FieldLabel :meta="B.plan_status" icon-only />
        <span class="fnwg-hint" style="margin-left: 10px">{{ planSummary }}</span>
      </div>

      <div v-if="planOpen" style="margin-top: 12px">
        <div class="fnwg-card-desc">
          备份文件与数据库在同一块盘上，盘坏、目录被误删、系统重装会一起没。
          开启后按日程把备份写到你授权的共享文件夹（通常放在另一块存储空间上），并只保留最近若干份。
        </div>

        <el-form label-width="110px" style="margin-top: 12px">
          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">启用 <FieldLabel :meta="B.plan_enabled" icon-only /></span>
            </template>
            <el-switch v-model="plan.enabled" />
          </el-form-item>

          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">执行频率 <FieldLabel :meta="B.plan_schedule" icon-only /></span>
            </template>
            <el-radio-group v-model="plan.freq">
              <el-radio value="daily">每天</el-radio>
              <el-radio value="weekly">每周</el-radio>
            </el-radio-group>
            <el-select v-if="plan.freq === 'weekly'" v-model="plan.weekday" style="width: 100px; margin-left: 8px">
              <el-option v-for="(label, i) in weekdays" :key="label" :label="`周${label}`" :value="i + 1" />
            </el-select>
            <el-time-picker
              v-model="plan.at"
              format="HH:mm"
              value-format="HH:mm"
              placeholder="03:30"
              style="width: 120px; margin-left: 8px"
            />
          </el-form-item>

          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">目标目录 <FieldLabel :meta="B.plan_target" icon-only /></span>
            </template>
            <!-- 两个来源：应用自己的备份目录，以及飞牛授权给本应用的目录。
                 不给手填入口：应用碰不到没被授权的目录，手填一个「看着对」的路径
                 只会让人得到「开关是开的、每天失败一次」，而界面上什么都看不出来。 -->
            <el-select v-model="planBaseDir" style="width: 280px">
              <el-option label="应用自己的备份目录" :value="OWN_DIR" />
              <el-option v-for="d in planStatus?.authorized_dirs || []" :key="d" :label="d" :value="d" />
              <!-- 已保存的目录不在授权清单里了（授权被撤销）：仍然显示出来，
                   免得下拉一片空白让人以为配置丢了；保存时后端会给出明确拒绝。 -->
              <el-option
                v-if="
                  planBaseDir &&
                  planBaseDir !== OWN_DIR &&
                  !(planStatus?.authorized_dirs || []).includes(planBaseDir)
                "
                :label="`${planBaseDir}（已不在授权列表里）`"
                :value="planBaseDir"
              />
            </el-select>
            <el-input
              v-if="planBaseDir !== OWN_DIR"
              v-model="planSubDir"
              placeholder="子目录（可留空）"
              style="width: 200px; margin-left: 8px"
            />
            <div class="fnwg-hint">
              备份会写到 <span class="fnwg-mono">{{ planTargetDir }}</span>
              <template v-if="planBaseDir !== OWN_DIR">；子目录不存在会自动创建。</template>
            </div>
            <!-- 选「自己的备份目录」时的代价必须说出来：它与源数据同盘，而且不做份数清理 -->
            <div v-if="planBaseDir === OWN_DIR" style="color: var(--el-color-warning)">
              这是与应用数据同一块盘上的目录：盘坏或目录被清时会一起丢，只适合当本地轮换副本。
              它也不适用下面的保留份数（那里还有你手动做的备份，一起清理会误删），请在备份列表里管理。
            </div>
            <!-- 列表是动态的：飞牛授权了哪些目录，这里就有哪些。
                 两条提示相互独立：一条讲「可选目录从哪来」，一条讲「现在为什么没有」——
                 用户选了「自己的备份目录」时同样需要知道怎么把外部目录加进来。 -->
            <div v-if="planStatus?.authorized_dirs.length" class="fnwg-hint">
              可选的目录就是你在飞牛里授权给本应用的那些；在飞牛里增删授权后回到本页刷新即可。
            </div>
            <div v-else style="color: var(--el-color-warning)">
              目前只有应用自己的备份目录可选：请到飞牛的「应用中心 → WireGuard 管理工具 → 应用设置」里，
              把要备份到的共享文件夹授权给本应用（授权由飞牛掌管，应用无法自己取得），
              它就会出现在上面的可选目录里。授权是在应用启动时读取的，刚在飞牛里改完时先回本页刷新；
              仍看不到就停用再启用一次本应用。
            </div>
          </el-form-item>

          <el-form-item>
            <template #label>
              <span class="fnwg-label-with-help">保留份数 <FieldLabel :meta="B.plan_keep" icon-only /></span>
            </template>
            <el-input-number v-model="plan.keep" :min="1" :max="90" controls-position="right" />
          </el-form-item>

          <el-form-item>
            <el-button type="primary" :loading="savingPlan" @click="savePlan">保存</el-button>
            <el-button :loading="runningPlan" @click="runPlanNow">立即执行一次</el-button>
          </el-form-item>
        </el-form>

        <div class="fnwg-kv">
          <span class="fnwg-kv-key">目标目录</span>
          <span class="fnwg-kv-val">
            <el-tag v-if="planStatus" size="small" :type="planStatus.dir_ok ? 'success' : 'danger'" effect="plain">
              {{ planStatus.dir_ok ? '可用' : '不可用' }}
            </el-tag>
            <span v-if="planStatus?.dir_note" class="fnwg-hint" style="margin-left: 6px">{{ planStatus.dir_note }}</span>
          </span>
        </div>
        <div v-if="planStatus?.next_at" class="fnwg-kv">
          <span class="fnwg-kv-key">下次执行</span>
          <span class="fnwg-kv-val">{{ formatTime(planStatus.next_at) }}</span>
        </div>
        <div class="fnwg-kv">
          <span class="fnwg-kv-key">最近一次</span>
          <span class="fnwg-kv-val">
            <template v-if="planStatus?.last">
              <el-tag size="small" :type="planStatus.last.ok ? 'success' : 'danger'" effect="plain">
                {{ planStatus.last.ok ? '成功' : '失败' }}
              </el-tag>
              <span style="margin-left: 6px">{{ formatTime(planStatus.last.at) }}</span>
              <span v-if="planStatus.last.file" class="fnwg-hint">
                · {{ planStatus.last.file }}（{{ formatBytes(planStatus.last.size) }}）
              </span>
              <div v-if="!planStatus.last.ok" style="color: var(--el-color-danger)">{{ planStatus.last.error }}</div>
            </template>
            <span v-else class="fnwg-hint">还没执行过</span>
          </span>
        </div>
      </div>
    </div>

    <el-dialog v-model="createDialog" title="立即备份" width="460px">
      <el-form label-width="90px">
        <el-form-item label="备注">
          <el-input v-model="note" placeholder="给这次备份写个备注（可留空）" />
        </el-form-item>
        <el-form-item>
          <template #label>
            <span class="fnwg-label-with-help">另存到 <FieldLabel :meta="B.plan_target" icon-only /></span>
          </template>
          <el-select v-model="targetDir" style="width: 100%">
            <el-option label="只存到应用自己的备份目录（默认）" value="" />
            <el-option v-for="d in planStatus?.authorized_dirs || []" :key="d" :label="d" :value="d" />
          </el-select>
          <div class="fnwg-hint">备份始终会出现在下面的列表里；选了别的目录，就在那儿再多留一份副本。</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="createDialog = false">取消</el-button>
        <el-button type="primary" :loading="creating" @click="submitCreate">开始备份</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowRight, Plus, Refresh, Search, Upload } from '@element-plus/icons-vue'
import { api, downloadText, postRaw } from '@/api/client'
import type { BackupPlan, BackupPlanStatus, BackupRecord } from '@/api/types'
import FieldLabel from '@/components/FieldLabel.vue'
import ItemCard from '@/components/ItemCard.vue'
import { backupFields as B } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'
import { formatBytes, formatTime } from '@/utils/format'
import ViewSwitch from '@/components/ViewSwitch.vue'
import { useViewMode } from '@/composables/useViewMode'

// 表格 / 卡片视图：由用户决定并记住
const { mode: viewMode, isTable } = useViewMode('backup-plans')

const session = useSession()
const { isMobile } = useBreakpoint()
const can = computed(() => session.can('backup.restore'))

/** 合并后的一行：本机记录，或计划备份写在共享文件夹里的副本。 */
interface Row {
  key: string
  source: 'local' | 'plan'
  name: string
  size: number
  time: string
  note: string
  /** 记录在、文件却不在了（只有本机记录会这样：外部副本是列目录得来的，列得到就存在） */
  missing: boolean
  /** 计划副本所在的目录（本机行为空） */
  dir: string
  /** 本机记录才有：用于还原 / 下载 / 删除 */
  id?: number
}

const loading = ref(false)
const keyword = ref('')
const source = ref<'all' | 'local' | 'plan'>('all')
const shareDir = ref('')

const localRows = ref<BackupRecord[]>([])
const planStatus = ref<BackupPlanStatus | null>(null)

/** 最近一次失败：常驻显示，带「接下来做什么」。 */
const problem = ref<{ title: string; message: string; advice: string } | null>(null)

/**
 * 「点下去会失败」的几类情况与对应处置。
 *
 * 后端给的原因本身已经是一句中文，但不含「接下来做什么」。只说失败不说怎么办的话，
 * 用户唯一的出口就是来问我们 —— 而这几件事他其实都能自己处理。
 * 顺序有意义：越具体的放前面，先匹配到的先算。
 */
const PROBLEM_ADVICE: { match: RegExp; advice: string }[] = [
  {
    match: /已经不在了|不存在或已被删除|记录不存在/,
    advice: '这份备份的文件已经不在了（可能被手动删除或移走）。可以删掉这条记录，或重新做一次备份。',
  },
  {
    match: /不是有效的备份文件|缺少有效内容|文件格式错误|解析配置失败/,
    advice: '这个文件不是本应用导出的备份，或者内容不完整。请换一份重新导入；若是从别处拷来的，先确认拷贝完整。',
  },
  {
    match: /还没有授权目录|不在已授权的目录里/,
    advice:
      '请到飞牛的「应用中心 → WireGuard 管理工具 → 应用设置」把要备份到的共享文件夹授权给本应用，再回到本页刷新。',
  },
  {
    match: /目标目录|不可写|无法创建/,
    advice: '检查这个目录是否还存在、是否可写：外接盘有没有挂上、共享是否还在飞牛的授权列表里。',
  },
  {
    match: /后台服务没有响应|连接特权代理失败/,
    advice: '后台服务（特权代理）没有响应：确认应用正在运行；仍未恢复就停用再启用一次本应用。',
  },
  {
    match: /权限|forbidden|unauthorized|401|403/i,
    advice: '当前账号没有备份还原权限，请换管理员账号操作。',
  },
]

/** 记一次失败：标题写「在做什么」，原因原样显示，再补一句怎么办。 */
function fail(title: string, e: unknown) {
  const message = (e as Error)?.message || String(e)
  const hit = PROBLEM_ADVICE.find((it) => it.match.test(message))
  problem.value = { title, message, advice: hit?.advice || '' }
}

const rows = computed<Row[]>(() => {
  const out: Row[] = localRows.value.map((r) => ({
    key: `local-${r.id}`,
    source: 'local' as const,
    name: r.filename,
    size: r.size,
    time: r.created_at,
    note: r.note || '',
    missing: !!r.missing,
    dir: '',
    id: r.id,
  }))
  for (const f of planStatus.value?.files || []) {
    out.push({
      key: `plan-${f.name}`,
      source: 'plan',
      name: f.name,
      size: f.size,
      time: f.mod_time,
      note: '',
      missing: false,
      dir: planStatus.value?.resolved_dir || '',
    })
  }
  // 新的在前：最常用的动作是「找最近那份」。同一时刻写出的两份按名字稳定排序 ——
  // 顺序每次刷新都变，用户会以为自己看错了行。
  out.sort((a, b) => (a.time === b.time ? a.name.localeCompare(b.name) : a.time < b.time ? 1 : -1))
  return out
})

const filtered = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  return rows.value.filter((r) => {
    if (source.value !== 'all' && r.source !== source.value) return false
    if (!kw) return true
    return r.name.toLowerCase().includes(kw) || r.note.toLowerCase().includes(kw)
  })
})

const hasPlanRow = computed(() => rows.value.some((r) => r.source === 'plan'))

// ---------------------------------------------------------------- 计划备份配置

const weekdays = ['一', '二', '三', '四', '五', '六', '日']
const plan = reactive<BackupPlan>({ enabled: false, freq: 'daily', at: '03:30', weekday: 1, dir: '', keep: 7 })
const planOpen = ref(false)
const savingPlan = ref(false)
const runningPlan = ref(false)

// 目标目录在界面上是「授权目录 + 子目录」两段，存的时候仍是一个绝对路径。
// 拆成两段是为了让用户只能从授权过的目录里挑：应用碰不到没授权的路径。
// 「应用自己的备份目录」在下拉里必须是个**非空**值：空串会被 Element Plus 当成
// 「没有选中」，界面上就显示成灰色的「请选择」——功能是对的，看起来却像没选。
// 它不可能与真实路径相撞，保存时会换回空串（由后端解析成应用自己的目录，不写死路径）。
const OWN_DIR = '__own__'
const planBaseDir = ref(OWN_DIR)
const planSubDir = ref('')

/** 目标目录的实际路径，显示给用户确认。选「应用自己的备份目录」时用后端解析出来的那个。 */
const planTargetDir = computed(() => {
  if (planBaseDir.value === OWN_DIR) {
    return planStatus.value?.resolved_dir || shareDir.value || '应用自己的备份目录'
  }
  const base = planBaseDir.value.replace(/\/+$/, '')
  const sub = planSubDir.value.replace(/^\/+|\/+$/g, '')
  return sub ? `${base}/${sub}` : base
})

/** 保存时提交的目录：空串表示「应用自己的备份目录」，由后端解析——不把路径写死在配置里。 */
const planDirForSave = computed(() => (planBaseDir.value === OWN_DIR ? '' : planTargetDir.value))

/** 收起状态下的摘要：不展开就能知道「它在不在跑、上次成没成」。 */
const planSummary = computed(() => {
  const st = planStatus.value
  if (!st) return ''
  if (!st.plan.enabled) return '未开启'
  const when =
    st.plan.freq === 'weekly'
      ? `每周${weekdays[(st.plan.weekday || 1) - 1]} ${st.plan.at}`
      : `每天 ${st.plan.at}`
  const last = st.last ? (st.last.ok ? '上次成功' : '上次失败') : '还没执行过'
  return `${when} · ${last}`
})

/**
 * 把已保存的目录拆回「基础目录 + 子目录」两段。
 *
 * 空串归到「应用自己的备份目录」那一项：配置里存的就是空串（见 planDirForSave），
 * 由后端解析成应用自己的目录，不把路径写死在配置里。
 *
 * ownDir 用的是**应用自己的备份目录**（shareDir），不是接口返回的 resolved_dir：
 * 后者的定义就是「已保存的目录，没保存时才是应用自己的目录」，拿它来比等于拿配置比自己，
 * 永远成立 —— 于是任何外部目录一刷新都会被显示成「应用自己的备份目录」，
 * 而实际执行的仍是用户选的那个（真机上就是这样看起来「自己变回去了」）。
 * 带上 shareDir 只为止住一种历史数据：早期版本会把应用自己的目录整条写进配置。
 *
 * 取最长的已授权前缀，其余部分算子目录：授权目录之间可能互相嵌套
 * （/vol1/1000 与 /vol1/1000/backup 同时被授权），按最短前缀拆会把这段路径拆错。
 * 完全不在清单里时（授权被撤销）整段当作基础目录显示，用户能一眼看出问题在哪。
 */
function splitPlanDir(dir: string, dirs: string[]) {
  const clean = (dir || '').replace(/\/+$/, '')
  const own = (shareDir.value || '').replace(/\/+$/, '')
  if (!clean || (own && clean === own)) {
    planBaseDir.value = OWN_DIR
    planSubDir.value = ''
    return
  }
  let best = ''
  for (const d of dirs) {
    const base = d.replace(/\/+$/, '')
    if (base && (clean === base || clean.startsWith(base + '/')) && base.length > best.length) {
      best = base
    }
  }
  planBaseDir.value = best || clean
  planSubDir.value = best ? clean.slice(best.length).replace(/^\/+/, '') : ''
}

// ---------------------------------------------------------------- 加载

/**
 * 取列表与计划状态。
 *
 * 两个请求一起发：它们合成同一个列表，一份先到就单独显示会让人以为「备份少了」。
 * 计划状态取不到（例如卡在授权上）不影响备份列表 —— 那两件事要分开说：
 * 合成一次请求「一起失败」的话，一个权限问题会让整个页面看起来全坏了。
 */
async function loadAll() {
  if (!can.value) return
  loading.value = true
  try {
    const [list, st] = await Promise.allSettled([
      api.get<{ items: BackupRecord[]; share_dir: string }>('/backups'),
      api.get<BackupPlanStatus>('/backup-plan'),
    ])
    if (list.status === 'fulfilled') {
      localRows.value = list.value.items || []
      shareDir.value = list.value.share_dir || ''
    } else {
      fail('读取备份列表失败', list.reason)
    }
    if (st.status === 'fulfilled') {
      planStatus.value = st.value
      Object.assign(plan, st.value.plan)
      splitPlanDir(st.value.plan.dir, st.value.authorized_dirs || [])
    }
  } finally {
    loading.value = false
  }
}

// ---------------------------------------------------------------- 立即备份

const createDialog = ref(false)
const note = ref('')
const targetDir = ref('')
const creating = ref(false)

function openCreate() {
  note.value = ''
  // 默认留空 = 只写进应用自己的备份目录（与以前一样）；
  // 想顺手在共享文件夹里留一份时再从授权目录里选。
  targetDir.value = ''
  createDialog.value = true
}

async function submitCreate() {
  creating.value = true
  try {
    const res = await api.post<{ copied_to?: string; copy_error?: string }>('/backups', {
      note: note.value,
      dir: targetDir.value,
    })
    if (res?.copy_error) {
      // 本地那份已经成功，只是另存失败：分开说，否则用户会以为没备份。
      // 但这仍然是失败而不是成功 —— 另存正是为了防「同一块盘一起坏」，没写成必须有下文。
      fail('备份已完成，但另存到共享文件夹失败', new Error(res.copy_error))
      ElMessage.warning('备份已完成（本机）；另存到共享文件夹没成功，详见页面顶部')
    } else if (res?.copied_to) {
      ElMessage.success(`备份已完成，并另存到 ${res.copied_to}`)
    } else {
      ElMessage.success('备份已完成')
    }
    createDialog.value = false
    await loadAll()
  } catch (e) {
    fail('备份失败', e)
  } finally {
    creating.value = false
  }
}

// ---------------------------------------------------------------- 还原 / 下载 / 删除

async function restore(row: Row) {
  try {
    await ElMessageBox.confirm(
      `还原将用备份「${row.name}」覆盖当前的全部连接、设备、系统设置与账号（含管理员密码），现有配置会被替换。确认继续？`,
      '还原备份',
      { type: 'warning' },
    )
    const req =
      row.source === 'local'
        ? api.post<{ restored_interfaces: number }>(`/backups/${row.id}/restore`)
        : api.post<{ restored_interfaces: number }>('/backup-plan/restore', { name: row.name })
    const res = await req
    problem.value = null
    ElMessage.success(`已还原 ${res.restored_interfaces} 条连接`)
    await loadAll()
  } catch (e) {
    if (e === 'cancel') return
    fail(`还原「${row.name}」失败`, e)
  }
}

async function downloadRow(row: Row) {
  const url =
    row.source === 'local'
      ? `/backups/${row.id}/download`
      : `/backup-plan/download?name=${encodeURIComponent(row.name)}`
  try {
    // 先取回来再落地（而不是直接把地址丢给浏览器）：
    // 直接下载时，失败响应会被浏览器当成一个文件存下来 —— 用户得到一个内容是错误信息的
    // .json，还以为备份有救了。取回来就能在失败时把服务端那句话显示出来。
    // 备份体积在几 MB 量级，走一趟内存没有负担。
    await downloadText(url, row.name)
    problem.value = null
  } catch (e) {
    fail(`下载「${row.name}」失败`, e)
  }
}

async function removeRow(row: Row) {
  try {
    await ElMessageBox.confirm(`确认删除备份「${row.name}」？删除后这份备份就不能再还原了。`, '删除备份', {
      type: 'warning',
    })
    await api.del(`/backups/${row.id}`)
    problem.value = null
    await loadAll()
  } catch (e) {
    if (e === 'cancel') return
    fail(`删除「${row.name}」失败`, e)
  }
}

// ---------------------------------------------------------------- 导入

const fileInput = ref<HTMLInputElement | null>(null)

function openImportBackup() {
  fileInput.value?.click()
}

async function onImportFile(e: Event) {
  const input = e.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  try {
    const text = await file.text()
    await postRaw(`/backups/import?filename=${encodeURIComponent(file.name)}`, text)
    problem.value = null
    ElMessage.success('备份已导入，可在列表中选择「还原」')
    await loadAll()
  } catch (err) {
    fail(`导入「${file.name}」失败`, err)
  }
}

// ---------------------------------------------------------------- 计划备份

async function savePlan() {
  savingPlan.value = true
  try {
    const payload: BackupPlan = { ...plan, dir: planDirForSave.value }
    const st = await api.put<BackupPlanStatus>('/backup-plan', payload)
    problem.value = null
    planStatus.value = st
    Object.assign(plan, st.plan)
    splitPlanDir(st.plan.dir, st.authorized_dirs || [])
    ElMessage.success('计划备份已保存')
  } catch (e) {
    fail('保存计划备份失败', e)
  } finally {
    savingPlan.value = false
  }
}

async function runPlanNow() {
  runningPlan.value = true
  try {
    // 失败原因用接口返回的原文：它已经写成了一句能直接读的话
    const state = await api.post<{ ok: boolean; file?: string; error?: string }>('/backup-plan/run')
    if (state.ok) {
      problem.value = null
      ElMessage.success(`已写入 ${state.file}`)
    } else {
      fail('立即执行一次失败', new Error(state.error || '未知原因'))
    }
    await loadAll()
  } catch (e) {
    fail('立即执行一次失败', e)
  } finally {
    runningPlan.value = false
  }
}

onMounted(loadAll)
</script>

<style scoped>
/* 顶部失败提示：原因一行，处置一行 —— 处置用主色，让人先看到「我该做什么」 */
.fnwg-problem-msg {
  margin-bottom: 2px;
}

.fnwg-problem-advice {
  color: var(--el-color-primary);
}

/* 计划备份卡片的标题行：整行可点，收起时也能看到状态摘要 */
.fnwg-plan-head {
  display: flex;
  align-items: center;
  gap: 6px;
  cursor: pointer;
  user-select: none;
}

.fnwg-plan-caret {
  transition: transform 0.2s;
  color: var(--el-text-color-secondary);
}

.fnwg-plan-caret-open {
  transform: rotate(90deg);
}

/* 表单标签里的问号：标签本身不换行，问号跟着文字走 */
.fnwg-label-with-help {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

/* 文件已经不在的记录：名字压暗，一眼能看出这一行不可用 */
.fnwg-missing-name {
  color: var(--el-text-color-placeholder);
  text-decoration: line-through;
}
</style>
