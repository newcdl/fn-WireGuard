<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 newcdl <newcdl@163.com> -->

<template>
  <div>
    <!-- 总体状态：任意页面看到的红/黄/绿与这里完全同源（useSystemHealth） -->
    <div class="fnwg-card fnwg-maint-head">
      <span :class="['fnwg-dot', tone]" />
      <div class="fnwg-maint-head-main">
        <strong>{{ toneLabel }}</strong>
        <div class="fnwg-hint">
          上次检查：{{ checkedAt || '尚未检查' }}　·　每 60 秒自动复查一次
          <template v-if="failedReason">　·　<span class="fnwg-maint-err">自检读取失败：{{ failedReason }}</span></template>
        </div>
      </div>
      <el-button :icon="Search" :loading="loading" @click="refresh">立即体检</el-button>
      <el-button v-if="session.can('iface.write')" :icon="Refresh" :loading="reconciling" @click="forceReconcile">
        重新应用全部配置
      </el-button>
    </div>

    <!-- 待处理事项：所有异常的唯一出口，避免用户在多个页面之间找按钮 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>待处理事项</strong>
          <span class="fnwg-card-desc">按重要性排序；「异常」表示相关功能当前没有在工作</span>
        </div>
        <el-tag v-if="!issues.length" size="small" type="success" effect="plain">全部通过</el-tag>
        <el-tag v-else size="small" :type="errors.length ? 'danger' : 'warning'" effect="plain">
          {{ errors.length }} 项异常 · {{ warnings.length }} 项待确认
        </el-tag>
      </div>

      <div v-if="!issues.length" class="fnwg-maint-ok">
        未发现需要处理的问题：系统上网路线、连接状态、内网访问与转发规则都已就绪。
      </div>

      <div v-for="it in issues" :key="it.key" class="fnwg-issue" :class="it.level">
        <el-tag size="small" :type="it.level === 'error' ? 'danger' : 'warning'" effect="plain">
          {{ it.level === 'error' ? '异常' : '待确认' }}
        </el-tag>
        <div class="fnwg-issue-body">
          <strong>{{ it.title }}</strong>
          <div class="fnwg-issue-detail">{{ it.detail }}</div>
          <div v-if="it.fix" class="fnwg-issue-fix">处理建议：{{ it.fix }}</div>
        </div>
        <div class="fnwg-issue-actions">
          <el-button
            v-if="it.repairable && session.can('iface.write')"
            type="danger"
            size="small"
            :loading="repairing"
            @click="repairNetwork"
          >
            立即修复
          </el-button>
          <el-button v-if="it.to && it.to !== 'maintenance'" size="small" @click="go(it.to)">去处理</el-button>
        </div>
      </div>
    </div>

    <!-- 分组一：NAS 系统网络 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>NAS 系统网络</strong>
          <span class="fnwg-card-desc">
            确认本应用没有影响 NAS 自身的上网路线。FN Connect、Docker、应用市场与系统更新都依赖它。
            本应用只会清理自己造成的残留，绝不修改系统设置。
          </span>
        </div>
        <el-button v-if="net && !net.healthy && session.can('iface.write')" type="danger" :icon="Refresh" :loading="repairing" @click="repairNetwork">
          立即修复
        </el-button>
      </div>

      <el-alert
        v-if="net"
        :type="netAlert.type"
        :closable="false"
        show-icon
        :title="netAlert.title"
        style="margin-top: 4px"
      />
      <ul v-if="net?.messages?.length" class="fnwg-net-list">
        <li v-for="(m, i) in net.messages" :key="i">{{ m }}</li>
      </ul>

      <el-descriptions v-if="net" :column="isMobile ? 1 : 2" border size="small" style="margin-top: 12px">
        <el-descriptions-item label="本应用的连接">{{ net.managed_interfaces?.join('、') || '无' }}</el-descriptions-item>
        <el-descriptions-item label="系统转发策略">
          {{ net.forward_policy_drop ? '丢弃（已为隧道网段单独放行）' : '放行' }}
        </el-descriptions-item>
        <el-descriptions-item label="系统默认路由" :span="2">
          <span v-if="!net.system_defaults?.length" class="fnwg-maint-err">没有读到默认路由</span>
          <span v-else class="fnwg-mono">
            {{ net.system_defaults.map((d) => `${d.dev || '-'} via ${d.gw || '-'} metric ${d.metric}`).join('　|　') }}
          </span>
        </el-descriptions-item>
      </el-descriptions>
    </div>

    <!-- 分组一之二：飞牛桌面入口
         「端口能打开、从飞牛桌面点图标却 502」时，差别只有这个 socket 文件，
         而端口侧的任何检查都看不出这件事。这一组就是为了让那种故障有地方说话。 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>飞牛桌面入口</strong>
          <span class="fnwg-card-desc">
            从飞牛桌面点本应用的图标，走的是应用目录下的一个 socket 文件。它没建立起来时，
            桌面图标会显示 502，而 IP:端口 仍然完全正常 —— 只看端口是查不出这件事的。
          </span>
        </div>
        <el-tag
          v-if="net?.gateway"
          size="small"
          :type="net.gateway.ready ? 'success' : net.gateway.configured ? 'danger' : 'info'"
          effect="plain"
        >
          {{ net.gateway.ready ? '正常' : net.gateway.configured ? '未就绪' : '未配置' }}
        </el-tag>
      </div>

      <div v-if="!net" class="fnwg-hint">暂无数据，点击上方「立即体检」。</div>
      <template v-else>
        <div class="fnwg-hint">
          socket 路径：<span class="fnwg-mono">{{ net.gateway?.path || '未知' }}</span>
        </div>
        <div v-if="net.gateway?.ready" class="fnwg-hint">
          入口正常：从飞牛桌面点图标可以打开本应用（进去后照常要用本应用账号登录）。
        </div>
        <div v-else class="fnwg-nat-check">
          <el-tag size="small" :type="net.gateway?.configured ? 'danger' : 'info'" effect="plain">
            {{ net.gateway?.configured ? '未就绪' : '未配置' }}
          </el-tag>
          <div class="fnwg-nat-check-body">
            <strong>
              {{ net.gateway?.configured ? '从飞牛桌面点图标会显示 502' : '本机未建立飞牛桌面入口' }}
            </strong>
            <div class="fnwg-nat-check-detail">{{ net.gateway?.detail }}</div>
            <div v-if="net.gateway?.fix" class="fnwg-issue-fix">处理建议：{{ net.gateway.fix }}</div>
          </div>
        </div>
      </template>
    </div>

    <!-- 分组二：内网访问链路逐层诊断 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>内网访问诊断</strong>
          <span class="fnwg-card-desc">「设备连上了但访问不了家里其它设备」时，看哪一层没过</span>
        </div>
        <el-tag v-if="natFailed.length" size="small" type="danger" effect="plain">{{ natFailed.length }} 项未通过</el-tag>
        <el-tag v-else-if="net" size="small" type="success" effect="plain">全部通过</el-tag>
      </div>

      <div v-if="!net?.nat?.checks?.length" class="fnwg-hint">暂无数据，点击上方「立即体检」。</div>
      <div v-for="c in net?.nat?.checks || []" :key="c.key" class="fnwg-nat-check">
        <el-tag size="small" :type="c.ok ? 'success' : 'danger'" effect="plain">{{ c.ok ? '通过' : '未通过' }}</el-tag>
        <div class="fnwg-nat-check-body">
          <strong>{{ c.label }}</strong>
          <div class="fnwg-nat-check-detail">{{ c.detail }}</div>
          <div v-if="!c.ok && c.fix" class="fnwg-issue-fix">处理建议：{{ c.fix }}</div>
        </div>
      </div>
    </div>

    <!-- 分组二之二：访问控制配置检查
         「设备通行范围」「内网访问」「设备之间隔离」单独看都没错，
         组合起来却可能互相抵消，现象只是一个模糊的「配了却访问不了」。 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>访问控制配置检查</strong>
          <span class="fnwg-card-desc">范围、开关、隔离三项设置之间是否互相矛盾</span>
        </div>
        <el-tag v-if="accessIssues.length" size="small" type="warning" effect="plain">
          {{ accessIssues.length }} 项需要确认
        </el-tag>
        <el-tag v-else-if="net" size="small" type="success" effect="plain">未发现矛盾</el-tag>
      </div>

      <div v-if="!net" class="fnwg-hint">暂无数据，点击上方「立即体检」。</div>
      <div v-else-if="!accessIssues.length" class="fnwg-hint">
        未发现互相矛盾的配置。这里会检查：设备允许的范围是否被某个开关挡住、范围是否指向了另一条连接等。
      </div>
      <div v-for="a in accessIssues" :key="a.key + (a.interface_id || 0)" class="fnwg-nat-check">
        <el-tag size="small" type="warning" effect="plain">需确认</el-tag>
        <div class="fnwg-nat-check-body">
          <strong>{{ a.title }}</strong>
          <div class="fnwg-nat-check-detail">{{ a.detail }}</div>
          <div v-if="a.fix" class="fnwg-issue-fix">处理建议：{{ a.fix }}</div>
        </div>
      </div>
    </div>

    <!-- 分组三：疑似残留网卡 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>疑似残留网卡</strong>
          <span class="fnwg-card-desc">
            内核里有、但不是本应用创建的 WireGuard 网卡。它们会一直占用监听端口，导致新连接无法使用这些端口。
          </span>
        </div>
        <el-tag v-if="net?.foreign_interfaces?.length" size="small" type="warning" effect="plain">
          {{ net.foreign_interfaces.length }} 个
        </el-tag>
      </div>

      <div v-if="!net?.foreign_interfaces?.length" class="fnwg-hint">未发现疑似残留网卡。</div>
      <div v-for="fi in net?.foreign_interfaces || []" :key="fi.name" class="fnwg-foreign-item">
        <div class="fnwg-foreign-main">
          <el-tag size="small" effect="plain" :type="fi.up ? 'warning' : 'info'">{{ fi.up ? '运行中' : '已停止' }}</el-tag>
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
      <div v-if="net?.foreign_interfaces?.length" class="fnwg-hint" style="margin-top: 8px">
        它们可能是早期版本卸载时没清理干净的残留，也可能是你用 wg-quick 等工具手工建的。
        <b>无法确认来源时请不要清理</b> —— 清理会中断该网卡上正在进行的连接。
      </div>
    </div>

    <!-- 分组四：运行环境 -->
    <div class="fnwg-card">
      <div class="fnwg-card-head">
        <div>
          <strong>运行环境</strong>
          <span class="fnwg-card-desc">后台组件与系统能力，任何一项不可用都会直接说明影响</span>
        </div>
      </div>
      <el-descriptions :column="isMobile ? 1 : 2" border size="small">
        <el-descriptions-item label="后台服务">
          <el-tag size="small" :type="health?.agent_up ? 'success' : 'danger'" effect="plain">
            {{ health?.agent_up ? '运行中' : '未运行' }}
          </el-tag>
        </el-descriptions-item>
        <el-descriptions-item label="工作模式">{{ backendLabel }}</el-descriptions-item>
        <el-descriptions-item label="加密网络支持">
          <el-tag size="small" :type="kernelTagType" effect="plain">
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
        <div><strong>加密网络支持</strong>：标准模式，速度最快、资源占用最低。显示「未开启」时若兼容模式可用，会自动改用兼容模式。</div>
        <div><strong>兼容模式支持</strong>：内核不支持标准模式时的备选方案，功能完整、速度与资源占用略逊；两项都不可用时新建的连接无法工作。</div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { Refresh, Search } from '@element-plus/icons-vue'
import { api } from '@/api/client'
import type { ForeignInterface } from '@/api/types'
import { refreshSystemHealth, useSystemHealth } from '@/composables/useSystemHealth'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'

const router = useRouter()
const session = useSession()
const { isMobile } = useBreakpoint()

const { loading, checkedAt, failedReason, net, health, issues, errors, warnings, tone, toneLabel, refresh } =
  useSystemHealth()

const repairing = ref(false)
const reconciling = ref(false)
const removingForeign = ref('')

const natFailed = computed(() => (net.value?.nat?.checks || []).filter((c) => !c.ok))
const accessIssues = computed(() => net.value?.access_issues || [])

/**
 * 自检结论：疑似残留不算「异常」（它也可能真的在被别的工具使用），
 * 因此只给中性提醒，不把整块标成红色。
 */
const netAlert = computed<{ type: 'success' | 'warning' | 'error'; title: string }>(() => {
  const r = net.value
  if (!r) return { type: 'warning', title: '尚未完成检查' }
  if (!r.healthy) return { type: 'error', title: '发现异常，建议立即修复' }
  if (r.foreign_interfaces?.length) return { type: 'warning', title: '未发现路由异常，但有疑似残留网卡待你确认' }
  return { type: 'success', title: '未发现影响 NAS 系统网络的问题' }
})

const backendLabel = computed(() => {
  const b = health.value?.backend
  return ({ kernel: '标准模式', userspace: '兼容模式', mock: '演示模式' } as Record<string, string>)[b || ''] || b || '-'
})

// 内核模块没开不等于「不可用」：兼容模式能顶上时是警告级，只有两条路都断了才是红色。
const kernelTagType = computed(() => {
  if (health.value?.kernel_module) return 'success'
  return health.value?.tun_device ? 'warning' : 'danger'
})

const uptime = computed(() => {
  const s = health.value?.uptime_sec || 0
  const h = Math.floor(s / 3600)
  const m = Math.floor((s % 3600) / 60)
  return h > 0 ? `${h} 小时 ${m} 分钟` : `${m} 分钟`
})

function go(name?: string) {
  if (name) router.push({ name })
}

async function repairNetwork() {
  repairing.value = true
  try {
    const res = await api.post<{ actions: string[] }>('/system/network/repair')
    ElMessage.success(res.actions?.length ? `已修复 ${res.actions.length} 项` : '没有需要修复的内容')
    await refreshSystemHealth()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    repairing.value = false
  }
}

async function forceReconcile() {
  reconciling.value = true
  try {
    const res = await api.post<{ actions: string[] }>('/system/reconcile')
    ElMessage.success(res.actions?.length ? `已重新应用 ${res.actions.length} 项设置` : '当前状态与配置一致，无需变更')
    await refreshSystemHealth()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    reconciling.value = false
  }
}

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
    await refreshSystemHealth()
  } catch (e) {
    if (e !== 'cancel' && e !== 'close') ElMessage.error((e as Error).message)
  } finally {
    removingForeign.value = ''
  }
}

onMounted(() => {
  void refresh()
})
</script>

<style scoped>
.fnwg-maint-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 12px;
  flex-wrap: wrap;
}

.fnwg-maint-head-main {
  flex: 1;
  min-width: 200px;
}

.fnwg-maint-ok {
  font-size: 13px;
  line-height: 1.9;
  color: var(--el-text-color-regular);
}

.fnwg-maint-err {
  color: var(--el-color-danger);
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

.fnwg-net-list {
  margin: 10px 0 0;
  padding-left: 18px;
  font-size: 12.5px;
  line-height: 1.9;
  color: var(--el-text-color-regular);
}

.fnwg-explain {
  margin-top: 12px;
  font-size: 12.5px;
  color: var(--el-text-color-secondary);
  line-height: 1.9;
}

.fnwg-foreign-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 10px;
  padding: 8px 0;
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

.fnwg-nat-check {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  padding: 8px 0;
  border-top: 1px solid var(--el-border-color-lighter);
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
</style>
