<template>
  <div class="fnwg-layout">
    <!-- 桌面端侧边导航 -->
    <aside v-if="!isMobile" class="fnwg-sidebar">
      <div class="fnwg-brand">
        <el-icon :size="18"><Connection /></el-icon>
        <span>WireGuard 管理</span>
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

        <div style="display: flex; align-items: center; gap: 8px">
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
        <span>WireGuard 管理</span>
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
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  Odometer,
  Link,
  User,
  Document,
  Setting,
  Avatar,
  ArrowDown,
  Menu,
  Reading,
  Connection,
} from '@element-plus/icons-vue'
import { api } from '@/api/client'
import ConfigHelpDrawer from '@/components/ConfigHelpDrawer.vue'
import { allHelpGroups } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'

const route = useRoute()
const router = useRouter()
const session = useSession()
const realtime = useRealtime()
const { isMobile, dialogWidth } = useBreakpoint()

const navs = [
  { name: 'dashboard', label: '总览', short: '总览', icon: Odometer },
  { name: 'interfaces', label: '我的连接', short: '连接', icon: Link },
  { name: 'peers', label: '我的设备', short: '设备', icon: User },
  { name: 'logs', label: '运行记录', short: '记录', icon: Document },
  { name: 'settings', label: '系统设置', short: '设置', icon: Setting },
]

const titles: Record<string, string> = {
  dashboard: '总览',
  interfaces: '我的连接',
  peers: '我的设备',
  logs: '运行记录',
  settings: '系统设置',
}
const title = computed(() => titles[route.name as string] || 'WireGuard 管理')
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

onMounted(() => {
  realtime.connect()
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

@media (max-width: 767px) {
  .fnwg-header-title {
    font-size: 14px;
  }
}
</style>
