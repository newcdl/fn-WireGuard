<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 newcdl <newcdl@163.com> -->

<template>
  <div class="login-page">
    <el-card class="login-card">
      <div style="text-align: center; margin-bottom: 20px">
        <el-icon :size="36" color="#409eff"><Connection /></el-icon>
        <h2 style="margin: 10px 0 4px">WireGuard 管理工具</h2>
        <div style="font-size: 13px; opacity: 0.65">飞牛 NAS 原生 WireGuard 控制台</div>
      </div>

      <!-- 唯一入口：账号与口令。
           从飞牛桌面点图标进来也是这里 —— 图标只负责打开页面，
           本应用不认飞牛账号身份，进去必须先登录。 -->
      <el-form v-if="step === 'password'" :model="form" label-position="top" @submit.prevent="submit">
        <el-form-item label="登录账号">
          <el-input v-model="form.username" placeholder="请输入登录账号" autofocus />
        </el-form-item>
        <el-form-item label="登录密码">
          <el-input
            v-model="form.password"
            type="password"
            show-password
            placeholder="请输入登录密码"
            @keyup.enter="submit"
          />
        </el-form-item>
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="submit">
          登录
        </el-button>
        <el-button link style="width: 100%; margin: 10px 0 0" @click="step = 'emergency'">
          密码和验证码都用不了？用安全码应急登录
        </el-button>
      </el-form>

      <!-- 第二步：二次验证。口令已通过，但服务端此时还没下发会话 -->
      <el-form v-else-if="step === 'totp'" label-position="top" @submit.prevent="submitTOTP">
        <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            账号「{{ form.username }}」已开启二次验证。请输入验证器 App 里当前显示的 6 位数字；
            如果手机不在身边，可以改用一枚恢复码。
          </template>
        </el-alert>
        <el-form-item label="验证码">
          <el-input
            v-model="code"
            placeholder="6 位动态口令，或一枚恢复码"
            autofocus
            @keyup.enter="submitTOTP"
          />
        </el-form-item>
        <el-checkbox v-model="trustDevice" style="margin-bottom: 10px">
          信任本设备，30 天内不再验证
        </el-checkbox>
        <div class="login-hint">
          仅在个人设备上勾选。公共电脑请勿勾选，事后可在「用户菜单 → 二次验证」里撤销。
        </div>
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="submitTOTP">
          验证并登录
        </el-button>
        <el-button link style="width: 100%; margin: 8px 0 0" @click="backToPassword">
          返回重新输入账号密码
        </el-button>
      </el-form>

      <!-- 应急登录：用初始化时保存的安全码 -->
      <el-form v-else-if="step === 'emergency'" label-position="top" @submit.prevent="submitEmergency">
        <el-alert type="warning" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>
            应急登录用于「密码和验证码都用不了」的情况，例如忘记密码、手机丢失且恢复码也遗失。
            请输入初始化时保存的应急安全码。
          </template>
        </el-alert>
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
            type="password"
            show-password
            placeholder="填写则同时重置管理员密码，至少 8 位"
          />
        </el-form-item>
        <el-button type="danger" size="large" style="width: 100%" :loading="loading" @click="submitEmergency">
          应急登录
        </el-button>
        <el-button link style="width: 100%; margin: 8px 0 0" @click="backToPassword">返回登录</el-button>
      </el-form>

      <!-- 应急登录成功：旧码已被消耗，必须保存新码才放行 -->
      <template v-else>
        <div style="text-align: center; margin-bottom: 14px">
          <h3 style="margin: 0 0 4px">应急登录成功</h3>
          <div style="font-size: 13px; opacity: 0.65">旧的安全码已作废，这是新的一枚</div>
        </div>
        <SecurityCodeBlock :code="newCode" />
        <div class="login-hint" style="margin-top: 10px">
          请立即保存。它同样只能使用一次，用掉后系统会再下发新的一码；系统不留明文，我们也无法找回。
        </div>
        <el-checkbox v-model="savedNew" style="margin-bottom: 12px">我已妥善保存这枚新安全码</el-checkbox>
        <el-button type="primary" size="large" style="width: 100%" :disabled="!savedNew" @click="enter">
          进入控制台
        </el-button>
      </template>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import SecurityCodeBlock from '@/components/SecurityCodeBlock.vue'

const router = useRouter()
const route = useRoute()
const session = useSession()
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
.login-page {
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  background: var(--fnwg-bg);
}
.login-card {
  width: min(400px, 100%);
  border-radius: 14px;
}
.login-hint {
  font-size: 12px;
  line-height: 1.6;
  opacity: 0.6;
  margin-bottom: 14px;
}
</style>
