<template>
  <div class="fnwg-layout">
    <!-- 桌面端侧边导航 -->
    <aside v-if="!isMobile" class="fnwg-sidebar">
      <div class="fnwg-brand">
        <el-icon :size="18"><Connection /></el-icon>
        <span>WireGuard 管理工具</span>
      </div>

      <!--
        铁律：el-menu 内的 el-menu-item 只能放「真实路由」。
        el-menu 一旦开启 router，点击时执行 `router.push(item.route || index)`，
        非路由项（如"配置说明"）会被当成路径推入，导致无匹配路由而白屏。
        此类动作入口一律放在菜单外面。
      -->
      <el-menu :default-active="route.name as string" class="fnwg-menu" @select="onMenuSelect">
        <el-menu-item v-for="n in navs" :key="n.name" :index="n.name">
          <el-icon><component :is="n.icon" /></el-icon><span>{{ n.label }}</span>
        </el-menu-item>
      </el-menu>

      <div class="fnwg-sidebar-actions">
        <button type="button" class="fnwg-sidebar-action" @click="helpVisible = true">
          <el-icon><Reading /></el-icon><span>配置说明大全</span>
        </button>
      </div>

      <div style="flex: 1"></div>
      <div style="padding: 12px 16px; font-size: 12px; opacity: 0.6">v{{ session.version || '0.3.0' }}</div>
    </aside>

    <div class="fnwg-main">
      <header class="fnwg-header">
        <div style="display: flex; align-items: center; gap: 8px; min-width: 0">
          <el-button v-if="isMobile" link :icon="Menu" @click="navVisible = true" />
          <span class="fnwg-header-title">{{ title }}</span>
        </div>

        <div class="fnwg-header-actions">
          <!-- 全局搜索：一个入口搜连接与设备，选中后跳到对应页面并打开详情 -->
          <GlobalSearch v-if="!isMobile" ref="searchRef" />
          <el-button v-else link :icon="Search" @click="mobileSearchVisible = true" />

          <!-- 系统状态栏：任意页面都能看到当前是否正常，点击直达处理入口 -->
          <el-tooltip :content="toneLabel" placement="bottom">
            <button type="button" class="fnwg-health-chip" :class="tone" @click="goMaintenance">
              <span :class="['fnwg-dot', tone]" />
              <span v-if="!isMobile">{{ chipText }}</span>
            </button>
          </el-tooltip>

          <el-tooltip :content="syncTip" placement="bottom">
            <el-tag size="small" :type="realtime.connected ? 'success' : 'info'" effect="plain">
              <span :class="['fnwg-dot', realtime.connected ? 'ok' : 'off']" style="margin-right: 4px" />
              {{ realtime.connected ? '状态同步中' : '状态未同步' }}
            </el-tag>
          </el-tooltip>
          <el-tag v-if="!isMobile && backendLabel" size="small" type="info" effect="plain">
            {{ backendLabel }}
          </el-tag>

          <el-tooltip content="配置说明大全" placement="bottom">
            <el-button link :icon="Reading" @click="helpVisible = true" />
          </el-tooltip>

          <el-dropdown @command="onCommand">
            <span style="cursor: pointer; display: flex; align-items: center; gap: 6px">
              <el-icon><Avatar /></el-icon>
              <span v-if="!isMobile">{{ session.user?.username }}</span>
              <el-icon v-if="isMobile"><ArrowDown /></el-icon>
            </span>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item disabled>{{ session.user?.username }}（{{ roleLabel }}）</el-dropdown-item>
                <el-dropdown-item command="help" divided>配置说明大全</el-dropdown-item>
                <el-dropdown-item command="password">修改密码</el-dropdown-item>
                <el-dropdown-item command="logout" divided>退出登录</el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
        </div>
      </header>

      <!--
        全局异常横幅：只要存在「功能确实没在工作」的问题就出现（warning 不打扰，只进状态栏）。
        放在内容区之外，因此在任何页面、任何滚动位置都能第一时间看到。
      -->
      <div v-if="errors.length" class="fnwg-banner down">
        <el-icon class="fnwg-banner-icon"><WarningFilled /></el-icon>
        <div class="fnwg-banner-body">
          <strong>{{ bannerTitle }}</strong>
          <span class="fnwg-banner-detail">{{ bannerDetail }}</span>
        </div>
        <div class="fnwg-banner-actions">
          <el-button v-if="canRepair" size="small" type="danger" :loading="repairing" @click="quickRepair">
            立即修复
          </el-button>
          <el-button size="small" @click="goMaintenance">去处理</el-button>
        </div>
      </div>

      <main class="fnwg-content">
        <router-view v-slot="{ Component }">
          <component :is="Component" />
        </router-view>
      </main>

      <!-- 移动端底部导航 -->
      <nav v-if="isMobile" class="fnwg-bottom-nav">
        <button
          v-for="n in navs"
          :key="n.name"
          class="fnwg-bottom-nav-item"
          :class="{ active: route.name === n.name }"
          @click="router.push({ name: n.name })"
        >
          <el-icon><component :is="n.icon" /></el-icon>
          <span>{{ n.short }}</span>
        </button>
      </nav>
    </div>

    <!-- 移动端抽屉导航 -->
    <el-drawer v-model="navVisible" direction="ltr" size="240px" :with-header="false">
      <div class="fnwg-brand" style="border: none">
        <el-icon :size="18"><Connection /></el-icon>
        <span>WireGuard 管理工具</span>
      </div>
      <el-menu :default-active="route.name as string" class="fnwg-menu" @select="onMenuSelect">
        <el-menu-item v-for="n in navs" :key="n.name" :index="n.name">
          <el-icon><component :is="n.icon" /></el-icon><span>{{ n.label }}</span>
        </el-menu-item>
      </el-menu>
      <div class="fnwg-sidebar-actions">
        <button type="button" class="fnwg-sidebar-action" @click="openHelp">
          <el-icon><Reading /></el-icon><span>配置说明大全</span>
        </button>
      </div>
    </el-drawer>

    <ConfigHelpDrawer v-model="helpVisible" :groups="helpGroups" />

    <el-dialog v-model="mobileSearchVisible" title="搜索连接与设备" :width="dialogWidth || '92%'" top="8vh">
      <GlobalSearch mobile />
    </el-dialog>

    <el-dialog v-model="pwVisible" title="修改密码" :width="dialogWidth || '420px'">
      <el-form class="fnwg-form" :label-position="isMobile ? 'top' : 'right'" label-width="90px">
        <el-form-item label="原密码">
          <el-input v-model="pw.old" type="password" show-password />
        </el-form-item>
        <el-form-item label="新密码">
          <el-input v-model="pw.next" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwVisible = false">取消</el-button>
        <el-button type="primary" @click="submitPassword">确定</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Odometer,
  Link,
  User,
  Document,
  Setting,
  Tools,
  Avatar,
  ArrowDown,
  Menu,
  Reading,
  Connection,
  WarningFilled,
  Search,
} from '@element-plus/icons-vue'
import { api } from '@/api/client'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import GlobalSearch from '@/components/GlobalSearch.vue'
import { allHelpGroups } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { refreshSystemHealth, useSystemHealth } from '@/composables/useSystemHealth'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'

const route = useRoute()
const router = useRouter()
const session = useSession()
const realtime = useRealtime()
const { isMobile, dialogWidth } = useBreakpoint()

const { errors, warnings, tone, toneLabel, start: startHealth, stop: stopHealth } = useSystemHealth()

const navs = [
  { name: 'dashboard', label: '总览', short: '总览', icon: Odometer },
  { name: 'interfaces', label: '我的连接', short: '连接', icon: Link },
  { name: 'peers', label: '我的设备', short: '设备', icon: User },
  { name: 'logs', label: '运行记录', short: '记录', icon: Document },
  { name: 'maintenance', label: '系统维护', short: '维护', icon: Tools },
  { name: 'settings', label: '系统设置', short: '设置', icon: Setting },
]

const titles: Record<string, string> = {
  dashboard: '总览',
  interfaces: '我的连接',
  peers: '我的设备',
  logs: '运行记录',
  maintenance: '系统维护',
  settings: '系统设置',
}

const repairing = ref(false)

/** 顶栏状态栏文字：异常数量最优先，其次待确认，全部通过时给正向反馈 */
const chipText = computed(() => {
  if (errors.value.length) return `${errors.value.length} 项异常`
  if (warnings.value.length) return `${warnings.value.length} 项待确认`
  return '系统正常'
})

const bannerTitle = computed(() => `${errors.value.length} 项异常需要处理`)

/** 横幅只放第一条的详情 + 剩余条数，保证在手机上也不会撑成一大块 */
const bannerDetail = computed(() => {
  const first = errors.value[0]
  if (!first) return ''
  const rest = errors.value.length > 1 ? `（另有 ${errors.value.length - 1} 项，点「去处理」查看全部）` : ''
  return `${first.title}：${first.detail}${rest}`
})

const canRepair = computed(() => errors.value.some((i) => i.repairable) && session.can('iface.write'))

function goMaintenance() {
  router.push({ name: 'maintenance' })
}

/** 横幅上的「立即修复」：与维护页同一个接口，避免用户为了修一个问题先跳页面 */
async function quickRepair() {
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
const title = computed(() => titles[route.name as string] || 'WireGuard 管理工具')
const roleLabel = computed(
  () => ({ admin: '管理员', operator: '运维', viewer: '只读' })[session.user?.role || 'viewer'],
)
const backendLabel = computed(() => {
  const b = realtime.status?.backend
  return ({ kernel: '标准模式', userspace: '兼容模式', mock: '演示模式' } as Record<string, string>)[b || ''] || ''
})
const syncTip = computed(() =>
  realtime.connected
    ? '正在实时显示连接与流量情况'
    : '与后台的实时通道断开，数据可能不是最新的（会自动重连）',
)

const helpGroups = allHelpGroups

const navVisible = ref(false)
const searchRef = ref()
const mobileSearchVisible = ref(false)
const helpVisible = ref(false)
const pwVisible = ref(false)
const pw = ref({ old: '', next: '' })

/** 菜单只处理真实路由，未知 index 一律忽略（防止误导航导致白屏） */
function onMenuSelect(index: string) {
  navVisible.value = false
  if (!navs.some((n) => n.name === index)) return
  router.push({ name: index })
}

function openHelp() {
  navVisible.value = false
  helpVisible.value = true
}

/** Ctrl/⌘ + K 聚焦搜索：搜索是高频动作，值得给一个快捷键 */
function onHotkey(e: KeyboardEvent) {
  if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    if (isMobile.value) mobileSearchVisible.value = true
    else searchRef.value?.focus?.()
  }
}

onMounted(() => {
  realtime.connect()
  // 全局体检：顶栏状态栏与异常横幅都读它，任意页面都能即时感知
  startHealth()
  window.addEventListener('keydown', onHotkey)
})

onUnmounted(() => {
  stopHealth()
  window.removeEventListener('keydown', onHotkey)
})

async function onCommand(cmd: string) {
  if (cmd === 'help') {
    helpVisible.value = true
    return
  }
  if (cmd === 'password') {
    pw.value = { old: '', next: '' }
    pwVisible.value = true
    return
  }
  if (cmd === 'logout') {
    await ElMessageBox.confirm('确认退出登录？', '提示', { type: 'warning' })
    await session.logout()
    router.replace({ name: 'login' })
  }
}

async function submitPassword() {
  try {
    await api.post('/auth/password', { old_password: pw.value.old, new_password: pw.value.next })
    ElMessage.success('密码已修改')
    pwVisible.value = false
  } catch (e) {
    ElMessage.error((e as Error).message)
  }
}
</script>

<style scoped>
.fnwg-menu {
  border-right: none;
  padding-top: 6px;
}

.fnwg-header-title {
  font-weight: 600;
  font-size: 15px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}

.fnwg-sidebar-actions {
  padding: 8px 12px;
  border-top: 1px solid var(--fnwg-border);
  margin-top: 6px;
}

.fnwg-sidebar-action {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 10px;
  border: 1px solid var(--fnwg-border);
  border-radius: 8px;
  background: transparent;
  color: var(--el-text-color-regular);
  font-family: inherit;
  font-size: 13px;
  cursor: pointer;
  transition: all 0.15s;
}

.fnwg-sidebar-action:hover {
  color: var(--el-color-primary);
  border-color: var(--el-color-primary-light-5);
  background: var(--el-color-primary-light-9);
}

/* 顶栏右侧动作区：允许整体压缩，但内部状态项不压缩（压缩交给搜索框）。
   空格不足时若让状态文字被压，中文的最小宽度只有一个字，会变成一字一行的竖排。 */
.fnwg-header-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  flex: 0 1 auto;
  min-width: 0;
}

/* 状态标签、按钮与账号菜单一律不参与压缩、不换行。
   中文的最小宽度只有一个字，被压缩时就会变成一字一行的竖排。 */
.fnwg-header-actions :deep(.el-tag),
.fnwg-header-actions :deep(.el-dropdown),
.fnwg-header-actions :deep(.el-button) {
  flex-shrink: 0;
  white-space: nowrap;
}

/* 顶栏系统状态栏：颜色跟随总体状态，点击直达系统维护 */
.fnwg-health-chip {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  height: 26px;
  padding: 0 10px;
  border-radius: 13px;
  border: 1px solid var(--fnwg-border);
  background: transparent;
  color: var(--el-text-color-regular);
  font-family: inherit;
  font-size: 12px;
  cursor: pointer;
  transition: all 0.15s;
  /* 不换行 + 不压缩：否则「系统正常 / N 项异常」会被挤成竖排 */
  white-space: nowrap;
  flex-shrink: 0;
}

.fnwg-health-chip .fnwg-dot {
  margin-right: 0;
}

.fnwg-health-chip:hover {
  border-color: var(--el-color-primary-light-5);
  color: var(--el-color-primary);
}

.fnwg-health-chip.ok {
  border-color: var(--el-color-success-light-5);
  color: var(--el-color-success);
}

.fnwg-health-chip.warn {
  border-color: var(--el-color-warning-light-5);
  color: var(--el-color-warning);
}

.fnwg-health-chip.down {
  border-color: var(--el-color-danger-light-5);
  color: var(--el-color-danger);
}

/* 全局异常横幅：只在「功能确实没在工作」时出现，位于内容区之外，任何页面都能看到 */
.fnwg-banner {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 16px;
  flex: 0 0 auto;
  border-bottom: 1px solid var(--el-color-danger-light-7);
  background: var(--el-color-danger-light-9);
  color: var(--el-color-danger);
  font-size: 12.5px;
}

.fnwg-banner-icon {
  font-size: 16px;
  flex: 0 0 auto;
}

.fnwg-banner-body {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  line-height: 1.6;
}

.fnwg-banner-body strong {
  font-size: 13px;
}

.fnwg-banner-detail {
  color: var(--el-text-color-regular);
  word-break: break-word;
}

.fnwg-banner-actions {
  display: flex;
  gap: 8px;
  flex: 0 0 auto;
}

@media (max-width: 767px) {
  .fnwg-header-title {
    font-size: 14px;
  }

  .fnwg-banner {
    flex-wrap: wrap;
    padding: 8px 12px;
  }

  .fnwg-banner-actions {
    width: 100%;
    justify-content: flex-end;
  }
}
</style>
