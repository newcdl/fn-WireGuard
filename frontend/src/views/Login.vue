<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div class="login-page">
    <!-- 背景装饰：两团柔光 + 细网格，浅色深色各自一套（很淡，只为打破大片纯色的呆板） -->
    <div class="login-bg" aria-hidden="true">
      <div class="login-glow login-glow-a" />
      <div class="login-glow login-glow-b" />
    </div>

    <div class="login-shell">
      <!-- ============ 左：品牌栏（仅桌面显示） ============ -->
      <!-- 品牌区用固定的深色渐变，不随明暗主题变：它是「这个产品的颜色」，跟着主题换会失去辨识度 -->
      <aside class="login-brand">
        <div class="login-brand-head">
          <img :src="logoUrl" alt="WireGuard 管理工具" class="login-logo" />
          <div class="login-brand-name">WireGuard 管理工具</div>
        </div>

        <div class="login-brand-slogan">自家 NAS 上的私有网络，一块屏幕看全、一次点击管好</div>

        <ul class="login-brand-points">
          <li>
            <span class="login-point-icon"><el-icon><Link /></el-icon></span>
            <div>
              <div class="login-point-title">连接与设备，一目了然</div>
              <div class="login-point-desc">隧道状态、在线设备、内网资产，都收在一页里</div>
            </div>
          </li>
          <li>
            <span class="login-point-icon"><el-icon><Histogram /></el-icon></span>
            <div>
              <div class="login-point-title">流量心里有数</div>
              <div class="login-point-desc">按设备、按天的报表与配额提醒，谁在跑流量随时可查</div>
            </div>
          </li>
          <li>
            <span class="login-point-icon"><el-icon><Lock /></el-icon></span>
            <div>
              <div class="login-point-title">安全底线扎实</div>
              <div class="login-point-desc">二次验证、应急安全码、配置快照，出事也有退路</div>
            </div>
          </li>
        </ul>

        <div class="login-brand-foot">运行在你自己的 NAS 上 · 数据不出家门</div>
      </aside>

      <!-- ============ 右：表单区 ============ -->
      <main class="login-main">
        <!-- 移动端品牌头（桌面端由左侧品牌栏承担，这里隐藏） -->
        <div class="login-mobile-head">
          <img :src="logoUrl" alt="" class="login-logo-sm" />
          <div>
            <div class="login-mobile-name">WireGuard 管理工具</div>
            <div class="login-mobile-sub">私有网络控制台</div>
          </div>
        </div>

        <!--
          从飞牛桌面点开时，这里通常根本不会出现：网关通道已按飞牛身份免密进入。
          会看到这个表单，说明「这次请求没带上可用的飞牛身份」—— 两种情形的处理办法完全不同，
          所以页面直接把观察到的事实说出来，而不是让人猜是功能没做还是坏了（这个坑 0.8.9 踩过一次）。
        -->
        <div v-if="session.gatewayBlocked" class="login-note warn">
          已识别到飞牛账号，但没能进入：{{ session.gatewayBlocked }}
        </div>
        <div v-else-if="session.channel === 'socket'" class="login-note">
          这次请求虽然来自飞牛桌面入口，但没有带上飞牛身份（刷新过页面、或链接被复制到别处打开都会这样）。
          回飞牛桌面重新点一次图标即可免密进入；也可以继续用账号密码登录。
        </div>

        <!-- —— 第一步：账号密码 —— -->
        <el-form
          v-if="step === 'password'"
          class="login-form"
          :model="form"
          label-position="top"
          @submit.prevent="submit"
        >
          <div class="login-title">欢迎回来</div>
          <div class="login-sub">登录以管理你的连接与设备</div>

          <el-form-item label="登录账号">
            <el-input
              v-model="form.username"
              size="large"
              placeholder="请输入登录账号"
              :prefix-icon="User"
              autofocus
            />
          </el-form-item>
          <el-form-item label="登录密码">
            <el-input
              v-model="form.password"
              size="large"
              type="password"
              show-password
              placeholder="请输入登录密码"
              :prefix-icon="Lock"
              @keyup.enter="submit"
            />
          </el-form-item>
          <el-button type="primary" size="large" class="login-submit" :loading="loading" @click="submit">
            登 录
          </el-button>

          <!-- 端口入口没有飞牛身份可用 —— 那不是缺陷，只是入口不同。小声说一句就够，
               不必弹提示打断；但也不能不说，否则用户会以为免密登录坏了。 -->
          <div v-if="session.channel !== 'socket'" class="login-entry-hint">
            从飞牛桌面点开本应用可免密进入；当前是端口入口，请用账号密码登录。
          </div>

          <el-button link class="login-link-btn" @click="step = 'emergency'">
            密码和验证码都用不了？用安全码应急登录
          </el-button>
        </el-form>

        <!--
          飞牛账号：与账号密码并列的第二种进入方式，按「第三方登录」的样式放在表单下方。
          只有本次请求确实带着可核验的飞牛身份时才出现（从飞牛桌面打开时）；端口入口没有它。
        -->
        <div v-if="step === 'password' && session.gatewayUser" class="login-alt">
          <div class="login-divider"><span>或</span></div>
          <el-button size="large" class="login-third" :loading="gatewayLoading" @click="loginWithGateway">
            <el-icon><Monitor /></el-icon>
            <span class="login-third-text">飞牛账号 {{ session.gatewayUser.username }}</span>
          </el-button>
        </div>

        <!-- —— 第二步：二次验证。口令已通过，但服务端此时还没下发会话 —— -->
        <el-form
          v-if="step === 'totp'"
          class="login-form"
          label-position="top"
          @submit.prevent="submitTOTP"
        >
          <div class="login-title">两步验证</div>
          <div class="login-sub">账号「{{ form.username }}」已开启二次验证</div>

          <div class="login-note">请输入验证器 App 里当前显示的 6 位数字；如果手机不在身边，可以改用一枚恢复码。</div>

          <el-form-item label="验证码">
            <el-input
              v-model="code"
              size="large"
              placeholder="6 位动态口令，或一枚恢复码"
              :prefix-icon="Key"
              autofocus
              @keyup.enter="submitTOTP"
            />
          </el-form-item>

          <el-checkbox v-model="trustDevice" class="login-trust">信任本设备，30 天内不再验证</el-checkbox>
          <div class="login-hint">
            仅在个人设备上勾选。公共电脑请勿勾选，事后可在「用户菜单 → 二次验证」里撤销。
          </div>

          <el-button type="primary" size="large" class="login-submit" :loading="loading" @click="submitTOTP">
            验证并登录
          </el-button>
          <el-button link class="login-link-btn" @click="backToPassword">返回重新输入账号密码</el-button>
        </el-form>

        <!-- —— 应急登录：用初始化时保存的安全码 —— -->
        <el-form
          v-if="step === 'emergency'"
          class="login-form"
          label-position="top"
          @submit.prevent="submitEmergency"
        >
          <div class="login-title">应急登录</div>
          <div class="login-sub">密码和验证码都用不了时最后的选择</div>

          <div class="login-note warn">
            用于「忘记密码、手机丢失且恢复码也遗失」这类情况，请输入初始化时保存的应急安全码。
          </div>

          <el-form-item label="应急安全码">
            <el-input
              v-model="emCode"
              type="textarea"
              :rows="3"
              placeholder="52 位字母数字；带分组连字符、空格或大小写不同都可以"
            />
          </el-form-item>
          <el-form-item label="新的登录密码（可留空）">
            <el-input
              v-model="emPassword"
              size="large"
              type="password"
              show-password
              placeholder="填写则同时重置管理员密码，至少 8 位"
            />
          </el-form-item>
          <el-button type="danger" size="large" class="login-submit" :loading="loading" @click="submitEmergency">
            应急登录
          </el-button>
          <el-button link class="login-link-btn" @click="backToPassword">返回登录</el-button>
        </el-form>

        <!-- —— 应急登录成功：旧码已被消耗，必须保存新码才放行 —— -->
        <div v-if="step === 'newcode'" class="login-form">
          <div class="login-title">应急登录成功</div>
          <div class="login-sub">旧的安全码已作废，这是新的一枚</div>
          <SecurityCodeBlock :code="newCode" />
          <div class="login-hint" style="margin-top: 10px">
            请立即保存。它同样只能使用一次，用掉后系统会再下发新的一码；系统不留明文，我们也无法找回。
          </div>
          <el-checkbox v-model="savedNew" class="login-trust">我已妥善保存这枚新安全码</el-checkbox>
          <el-button type="primary" size="large" class="login-submit" :disabled="!savedNew" @click="enter">
            进入控制台
          </el-button>
        </div>
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { Histogram, Key, Link, Lock, Monitor, User } from '@element-plus/icons-vue'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import SecurityCodeBlock from '@/components/SecurityCodeBlock.vue'
import logoUrl from '@/assets/app-icon.png'

const router = useRouter()
const route = useRoute()
const session = useSession()

/** 「以飞牛账号登录」的进行状态：这个按钮会换发一份普通会话，值得给个加载态。 */
const gatewayLoading = ref(false)

async function loginWithGateway(): Promise<void> {
  gatewayLoading.value = true
  try {
    await session.gatewayLogin()
    router.replace('/')
  } catch (e) {
    // 例如管理员在本应用里停用了这个飞牛账号：把原因原样显示，别让人猜
    ElMessage.error((e as Error).message || '飞牛账号登录失败')
  } finally {
    gatewayLoading.value = false
  }
}
const realtime = useRealtime()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

/** 当前界面：password（账号口令）→ totp（二次验证）/ emergency（安全码）→ newcode（保存新安全码）。 */
const step = ref<'password' | 'totp' | 'emergency' | 'newcode'>('password')
const challenge = ref('')
const code = ref('')
const trustDevice = ref(false)

const emCode = ref('')
const emPassword = ref('')
const newCode = ref('')
const savedNew = ref(false)

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请填写用户名与密码')
    return
  }
  loading.value = true
  try {
    const out = await session.login(form.username, form.password)
    if (out.totpRequired) {
      // 口令正确，但服务端故意没有下发会话：必须再过一次动态口令才算登录
      challenge.value = out.challenge
      code.value = ''
      step.value = 'totp'
      return
    }
    enter()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

async function submitTOTP() {
  if (!code.value.trim()) {
    ElMessage.warning('请输入验证码')
    return
  }
  loading.value = true
  try {
    await session.loginTOTP(challenge.value, code.value.trim(), trustDevice.value)
    enter()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

async function submitEmergency() {
  if (!emCode.value.trim()) {
    ElMessage.warning('请输入应急安全码')
    return
  }
  loading.value = true
  try {
    newCode.value = await session.emergencyLogin(emCode.value.trim(), emPassword.value)
    emCode.value = ''
    emPassword.value = ''
    if (newCode.value) {
      step.value = 'newcode'
      return
    }
    // 理论上不会发生：服务端每次应急登录都会下发新码。真出现就直接放行，不把人卡住。
    enter()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

function backToPassword() {
  step.value = 'password'
  challenge.value = ''
  code.value = ''
  trustDevice.value = false
  emCode.value = ''
  emPassword.value = ''
  form.password = ''
}

function enter() {
  realtime.connect()
  const redirect = (route.query.redirect as string) || '/dashboard'
  router.replace(redirect)
}
</script>

<style scoped>
/* ============ 页面与背景 ============ */
.login-page {
  position: relative;
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 24px;
  overflow: hidden;
  background: var(--fnwg-bg);
}

/* 两团柔光：打破大片纯色的呆板。透明度刻意压得很低 —— 登录页的第一要务是让人看清表单 */
.login-glow {
  position: absolute;
  width: 560px;
  height: 560px;
  border-radius: 50%;
  filter: blur(90px);
  opacity: 0.5;
  pointer-events: none;
}
.login-glow-a {
  top: -180px;
  right: -120px;
  background: rgba(64, 158, 255, 0.22);
}
.login-glow-b {
  bottom: -200px;
  left: -140px;
  background: rgba(103, 194, 58, 0.14);
}
html.dark .login-glow-a {
  opacity: 0.3;
}
html.dark .login-glow-b {
  opacity: 0.2;
}

/* ============ 主体：桌面双栏 / 窄屏单栏 ============ */
.login-shell {
  position: relative;
  display: flex;
  width: min(920px, 100%);
  min-height: 560px;
  border-radius: 18px;
  background: var(--fnwg-card);
  border: 1px solid var(--fnwg-border);
  box-shadow:
    0 20px 60px rgba(0, 0, 0, 0.12),
    0 4px 16px rgba(0, 0, 0, 0.06);
  overflow: hidden;
}

/* ============ 左：品牌栏 ============ */
.login-brand {
  flex: 0 0 42%;
  display: flex;
  flex-direction: column;
  padding: 44px 38px;
  color: #e8edf6;
  background:
    radial-gradient(900px 480px at -10% -20%, rgba(64, 158, 255, 0.28), transparent 60%),
    radial-gradient(700px 420px at 120% 115%, rgba(103, 194, 58, 0.14), transparent 55%),
    linear-gradient(160deg, #17233c 0%, #101a2e 55%, #0c1526 100%);
}

.login-brand-head {
  display: flex;
  align-items: center;
  gap: 12px;
}
.login-logo {
  width: 44px;
  height: 44px;
  border-radius: 11px;
  /* 白衬底：图标本身是彩色的，直接贴在深色上会糊成一团 */
  background: #fff;
  padding: 5px;
  box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
}
.login-brand-name {
  font-size: 20px;
  font-weight: 700;
  letter-spacing: 0.4px;
}

.login-brand-slogan {
  margin: 18px 0 30px;
  font-size: 15px;
  line-height: 1.7;
  color: rgba(232, 237, 246, 0.78);
}

.login-brand-points {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: 22px;
}
.login-brand-points li {
  display: flex;
  gap: 14px;
  align-items: flex-start;
}
.login-point-icon {
  flex: 0 0 36px;
  height: 36px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 10px;
  font-size: 17px;
  color: #7ab5ff;
  background: rgba(122, 181, 255, 0.12);
  border: 1px solid rgba(122, 181, 255, 0.22);
}
.login-point-title {
  font-size: 14px;
  font-weight: 600;
}
.login-point-desc {
  margin-top: 3px;
  font-size: 12.5px;
  line-height: 1.6;
  color: rgba(232, 237, 246, 0.62);
}

.login-brand-foot {
  margin-top: auto;
  padding-top: 28px;
  font-size: 12px;
  color: rgba(232, 237, 246, 0.5);
}

/* ============ 右：表单区 ============ */
.login-main {
  flex: 1;
  display: flex;
  flex-direction: column;
  justify-content: center;
  padding: 40px 44px;
}

.login-form {
  width: 100%;
  max-width: 340px;
  margin: 0 auto;
}

.login-title {
  font-size: 22px;
  font-weight: 700;
  color: var(--el-text-color-primary);
}
.login-sub {
  margin: 6px 0 22px;
  font-size: 13.5px;
  color: var(--el-text-color-secondary);
}

/* 通道提示：比 el-alert 轻，登录页不需要那么重的色块 */
.login-note {
  margin-bottom: 16px;
  padding: 9px 12px;
  border-radius: 8px;
  font-size: 12.5px;
  line-height: 1.65;
  color: var(--el-text-color-regular);
  background: var(--el-fill-color-light);
  border: 1px solid var(--el-border-color-lighter);
}
.login-note.warn {
  color: var(--el-color-warning-dark-2, #b88230);
  background: var(--el-color-warning-light-9, #fdf6ec);
  border-color: var(--el-color-warning-light-7, #faecd8);
}
html.dark .login-note.warn {
  color: #e6a23c;
}

.login-entry-hint {
  margin-top: 12px;
  font-size: 12px;
  line-height: 1.6;
  text-align: center;
  color: var(--el-text-color-secondary);
  opacity: 0.75;
}

.login-submit {
  width: 100%;
  margin-top: 4px;
  font-size: 15px;
  letter-spacing: 4px;
}

.login-link-btn {
  width: 100%;
  margin: 12px 0 0;
  height: auto;
  padding: 6px 0;
  font-size: 12.5px;
}

.login-trust {
  margin-bottom: 6px;
}

.login-hint {
  font-size: 12px;
  line-height: 1.6;
  opacity: 0.6;
  margin-bottom: 14px;
}

/* ============ 飞牛账号（第三方登录） ============ */
.login-alt {
  width: 100%;
  max-width: 340px;
  margin: 4px auto 0;
}
.login-divider {
  position: relative;
  margin: 18px 0 14px;
  text-align: center;
  border-top: 1px solid var(--fnwg-border);
}
.login-divider span {
  position: relative;
  top: -10px;
  padding: 0 14px;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  background: var(--fnwg-card);
}
.login-third {
  width: 100%;
  font-weight: 500;
}
.login-third-text {
  margin-left: 6px;
}

/* ============ 移动端品牌头（桌面隐藏） ============ */
.login-mobile-head {
  display: none;
}

/* ============ 窄屏（单栏） ============ */
@media (max-width: 879px) {
  .login-page {
    padding: 14px;
    align-items: flex-start;
    padding-top: max(20px, env(safe-area-inset-top));
  }
  .login-shell {
    flex-direction: column;
    min-height: 0;
    margin-top: 4vh;
  }
  .login-brand {
    display: none;
  }
  .login-mobile-head {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 26px;
  }
  .login-logo-sm {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    background: #fff;
    padding: 4px;
    box-shadow: 0 3px 10px rgba(0, 0, 0, 0.18);
  }
  html.dark .login-logo-sm {
    background: #fff; /* 图标是彩色的，深色主题下也要白衬底，否则糊成一团 */
  }
  .login-mobile-name {
    font-size: 17px;
    font-weight: 700;
    color: var(--el-text-color-primary);
  }
  .login-mobile-sub {
    font-size: 12px;
    color: var(--el-text-color-secondary);
    margin-top: 2px;
  }
  .login-main {
    padding: 30px 22px 34px;
    justify-content: flex-start;
  }
  .login-form {
    max-width: 420px;
  }
  .login-title {
    font-size: 20px;
  }
  /* 手机上键盘会顶起视口，柔光没必要占资源 */
  .login-glow {
    width: 320px;
    height: 320px;
    filter: blur(70px);
  }
}
</style>
