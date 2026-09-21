<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div class="fnwg-card">
    <div class="fnwg-card-head">
      <div>
        <strong>配置漂移巡检</strong>
        <span class="fnwg-card-desc">
          按日程把「实际状态」和你的配置对一遍，写成一份报告。开关开着却没生效、连接悄悄掉线、
          计划备份一直失败 —— 这类问题都不会自己报错，靠它定期说出来。
        </span>
      </div>
      <el-tag v-if="status?.last" size="small" :type="lastTagType" effect="plain">{{ lastTagText }}</el-tag>
      <el-button
        v-if="canWrite"
        :icon="Search"
        :loading="running"
        @click="runNow"
      >
        立即巡检一次
      </el-button>
    </div>

    <!-- 计划：开关 + 日程 + 保留份数。说明一律走问号气泡（见 FieldLabel）。 -->
    <el-form v-if="canWrite" label-width="130px" class="fnwg-inspect-form">
      <el-form-item>
        <template #label>
          <span class="fnwg-label-with-help">启用 <FieldLabel :meta="S.inspect_enabled" icon-only /></span>
        </template>
        <el-switch v-model="form.enabled" />
        <span v-if="status?.next_at" class="fnwg-hint" style="margin-left: 12px">
          下一次：{{ formatTime(status.next_at) }}
        </span>
      </el-form-item>

      <el-form-item>
        <template #label>
          <span class="fnwg-label-with-help">巡检频率 <FieldLabel :meta="S.inspect_schedule" icon-only /></span>
        </template>
        <el-radio-group v-model="form.freq">
          <el-radio value="daily">每天</el-radio>
          <el-radio value="weekly">每周</el-radio>
        </el-radio-group>
        <el-select v-if="form.freq === 'weekly'" v-model="form.weekday" style="width: 100px; margin-left: 8px">
          <el-option v-for="(label, i) in weekdays" :key="label" :label="`周${label}`" :value="i + 1" />
        </el-select>
        <el-time-picker
          v-model="form.at"
          format="HH:mm"
          value-format="HH:mm"
          placeholder="06:30"
          style="width: 120px; margin-left: 8px"
        />
      </el-form-item>

      <el-form-item>
        <template #label>
          <span class="fnwg-label-with-help">保留报告份数 <FieldLabel :meta="S.inspect_keep" icon-only /></span>
        </template>
        <el-input-number v-model="form.keep" :min="1" :max="60" controls-position="right" />
        <el-button type="primary" :loading="saving" style="margin-left: 12px" @click="save">保存</el-button>
      </el-form-item>
    </el-form>
    <div v-else class="fnwg-hint">当前账号没有修改权限，只能查看巡检报告。</div>

    <!-- 报告详情：默认最近一次；点历史里的一条可以切换过去看 -->
    <div v-if="selected" class="fnwg-inspect-report">
      <div class="fnwg-card-head">
        <div>
          <strong>{{ isLatest ? '最近一次报告' : '历史报告' }}</strong>
          <span class="fnwg-card-desc">
            {{ formatTime(selected.at) }}<template v-if="selected.manual">（手动触发）</template>
            · 检查 {{ selected.items.length }} 项：{{ selected.passed }} 项正常、
            {{ selected.errors }} 项异常、{{ selected.warnings }} 项待确认
          </span>
        </div>
        <el-button v-if="!isLatest" size="small" @click="selected = status?.last || null">回到最近一次</el-button>
      </div>

      <div v-if="!selected.errors && !selected.warnings" class="fnwg-maint-ok">
        这次巡检全部通过：报告里没有需要处理或待确认的项。
      </div>

      <div v-for="it in problemItems(selected)" :key="it.key" class="fnwg-issue" :class="it.level">
        <el-tag size="small" :type="it.level === 'error' ? 'danger' : 'warning'" effect="plain">
          {{ it.level === 'error' ? '异常' : '待确认' }}
        </el-tag>
        <div class="fnwg-issue-body">
          <strong>{{ it.title }}</strong>
          <div class="fnwg-issue-detail">{{ it.detail }}</div>
          <div v-if="it.fix" class="fnwg-issue-fix">处理建议：{{ it.fix }}</div>
        </div>
        <div class="fnwg-issue-actions">
          <el-button v-if="it.to === 'maintenance'" size="small" @click="goMaintenance(it)">去处理</el-button>
          <el-button v-else-if="it.to" size="small" @click="go(it.to)">去处理</el-button>
        </div>
      </div>

      <el-collapse v-if="okItems(selected).length" style="margin-top: 8px">
        <el-collapse-item :title="`通过项（${okItems(selected).length} 项）`">
          <div v-for="it in okItems(selected)" :key="it.key" class="fnwg-inspect-ok">
            <el-tag size="small" type="success" effect="plain">正常</el-tag>
            <div class="fnwg-issue-body">
              <strong>{{ it.title }}</strong>
              <div class="fnwg-issue-detail">{{ it.detail }}</div>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </div>
    <div v-else class="fnwg-hint" style="margin-top: 8px">
      还没有报告：打开上面的开关按日程巡检，或点「立即巡检一次」立刻查一遍。
    </div>

    <!-- 历史报告：便于回看「什么时候开始不对劲的」 -->
    <el-collapse v-if="history.length" style="margin-top: 12px">
      <el-collapse-item :title="`历史报告（${history.length} 份）`">
        <div
          v-for="(rep, i) in history"
          :key="i"
          class="fnwg-inspect-hist"
          :class="{ active: selected && selected.at === rep.at }"
          @click="selected = rep"
        >
          <span class="fnwg-inspect-hist-time">{{ formatTime(rep.at) }}</span>
          <el-tag size="small" :type="tagTypeOf(rep)" effect="plain">{{ tagTextOf(rep) }}</el-tag>
          <span class="fnwg-hint">
            检查 {{ rep.items.length }} 项<template v-if="rep.manual"> · 手动触发</template>
          </span>
        </div>
      </el-collapse-item>
    </el-collapse>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Search } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import type { InspectItem, InspectPlan, InspectReport, InspectStatus } from '@/api/types'
import FieldLabel from '@/components/FieldLabel.vue'
import { inspectFields as S } from '@/constants/fields'
import { refreshSystemHealth } from '@/composables/useSystemHealth'
import { useSession } from '@/stores/session'
import { formatTime } from '@/utils/format'

const router = useRouter()
const session = useSession()
const canWrite = computed(() => session.can('iface.write'))

const weekdays = ['一', '二', '三', '四', '五', '六', '日']

const status = ref<InspectStatus | null>(null)
const selected = ref<InspectReport | null>(null)
const saving = ref(false)
const running = ref(false)

// 表单与 status.plan 分开存：用户改到一半时不能被后台刷新覆盖掉。
const form = reactive<InspectPlan>({ enabled: false, freq: 'daily', at: '06:30', weekday: 1, keep: 14 })

/** 历史列表：含最近一次（点它等于回到最近一次，与上面的按钮同效）。 */
const history = computed(() => status.value?.reports || [])

const isLatest = computed(() => !!selected.value && selected.value.at === status.value?.last?.at)

function problemItems(rep: InspectReport | null): InspectItem[] {
  return (rep?.items || []).filter((it) => it.level !== 'ok')
}

function okItems(rep: InspectReport | null): InspectItem[] {
  return (rep?.items || []).filter((it) => it.level === 'ok')
}

function tagTypeOf(rep: InspectReport): 'danger' | 'warning' | 'success' {
  if (rep.errors) return 'danger'
  if (rep.warnings) return 'warning'
  return 'success'
}

function tagTextOf(rep: InspectReport): string {
  if (rep.errors) return `${rep.errors} 项异常`
  if (rep.warnings) return `${rep.warnings} 项待确认`
  return '全部通过'
}

const lastTagType = computed(() => (status.value?.last ? tagTypeOf(status.value.last) : 'info'))
const lastTagText = computed(() => {
  const last = status.value?.last
  if (!last) return ''
  return last.manual ? `${tagTextOf(last)}（手动）` : tagTextOf(last)
})

/**
 * 需要在本页（系统维护）处理的项：切到对应的页签。
 *
 * 报告在「巡检报告」页签里，而事实与修复按钮在别的页签 —— 只弹一句提示等于让用户自己去翻。
 * 落点按 key 判断：桌面入口那一条在「系统网络」，其余需要修复/说明的在「待处理」
 * （那里是异常的唯一出口，一键修复也在那里）。
 */
function goMaintenance(it: InspectItem): void {
  const tab = it.key === 'gateway' ? 'network' : 'issues'
  void router.push({ name: 'maintenance', query: { tab } })
  ElMessage.info(
    tab === 'network'
      ? '已切到「系统网络」页签：那里能看到桌面入口的状态与处置办法。'
      : '已切到「待处理」页签：在那里点「立即修复」。',
  )
}

function go(name?: string): void {
  if (name) void router.push({ name })
}

async function load(): Promise<void> {
  try {
    const st = await api.get<InspectStatus>('/system/inspect')
    status.value = st
    Object.assign(form, st.plan)
    // 默认看最近一次报告；用户切到历史某一条后不再覆盖他的选择。
    if (!selected.value || selected.value.at === st.last?.at) {
      selected.value = st.last || (st.reports.length ? st.reports[0] : null)
    }
  } catch {
    // 读不到就保持空态：本面板是只读展示，报错交给页面的统一错误提示即可。
  }
}

async function save(): Promise<void> {
  saving.value = true
  try {
    const st = await api.put<InspectStatus>('/system/inspect', { ...form })
    status.value = st
    Object.assign(form, st.plan)
    selected.value = st.last || selected.value
    ElMessage.success('巡检计划已保存')
  } catch (e) {
    ElMessage.error((e as Error)?.message || '保存巡检计划失败')
  } finally {
    saving.value = false
  }
}

async function runNow(): Promise<void> {
  running.value = true
  try {
    const st = await api.post<InspectStatus>('/system/inspect/run')
    status.value = st
    selected.value = st.last || null
    const last = st.last
    if (!last) {
      ElMessage.warning('巡检已完成，但没能读到报告')
    } else if (last.errors) {
      ElMessage.warning(`巡检发现 ${last.errors} 项需要处理，详见下方报告`)
    } else if (last.warnings) {
      ElMessage.success(`巡检完成：${last.warnings} 项待确认，详见下方报告`)
    } else {
      ElMessage.success(`巡检完成：检查 ${last.items.length} 项，全部正常`)
    }
    // 顶栏与各页的异常清单来自同一份判定，手动巡检后让它们立刻同步。
    void refreshSystemHealth()
  } catch (e) {
    ElMessage.error((e as Error)?.message || '立即巡检失败')
  } finally {
    running.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.fnwg-label-with-help {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.fnwg-inspect-form {
  margin-top: 4px;
}

.fnwg-inspect-report {
  margin-top: 12px;
  border-top: 1px solid var(--el-border-color-lighter);
}

.fnwg-maint-ok {
  font-size: 13px;
  line-height: 1.9;
  color: var(--el-text-color-regular);
}

.fnwg-issue {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 10px 0;
  border-top: 1px solid var(--el-border-color-lighter);
}

.fnwg-issue:first-of-type {
  border-top: none;
}

.fnwg-issue-body {
  flex: 1;
  min-width: 0;
  font-size: 12.5px;
  line-height: 1.8;
}

.fnwg-issue-detail {
  color: var(--el-text-color-regular);
  word-break: break-word;
}

.fnwg-issue-fix {
  color: var(--el-color-danger);
}

.fnwg-issue.warning .fnwg-issue-fix {
  color: var(--el-color-warning);
}

.fnwg-issue-actions {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.fnwg-inspect-ok {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 6px 0;
}

.fnwg-inspect-hist {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 6px 4px;
  border-radius: 4px;
  cursor: pointer;
}

.fnwg-inspect-hist:hover {
  background: var(--el-fill-color-light);
}

.fnwg-inspect-hist.active {
  background: var(--el-fill-color);
}

.fnwg-inspect-hist-time {
  font-size: 12.5px;
  min-width: 150px;
}
</style>
