<template>
  <div class="login-page">
    <el-card class="login-card">
      <div style="text-align: center; margin-bottom: 20px">
        <el-icon :size="36" color="#409eff"><Connection /></el-icon>
        <h2 style="margin: 10px 0 4px">WireGuard 管理工具</h2>
        <div style="font-size: 13px; opacity: 0.65">飞牛 NAS 原生 WireGuard 控制台</div>
      </div>

      <!-- 第一步：账号与口令 -->
      <el-form v-if="!totpRequired" :model="form" label-position="top" @submit.prevent="submit">
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
      </el-form>

      <!-- 第二步：二次验证。口令已通过，但服务端此时还没下发会话 -->
      <el-form v-else label-position="top" @submit.prevent="submitTOTP">
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
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="submitTOTP">
          验证并登录
        </el-button>
        <el-button link style="width: 100%; margin: 8px 0 0" @click="backToPassword">
          返回重新输入账号密码
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'

const router = useRouter()
const route = useRoute()
const session = useSession()
const realtime = useRealtime()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

const totpRequired = ref(false)
const challenge = ref('')
const code = ref('')

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
      totpRequired.value = true
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
    await session.loginTOTP(challenge.value, code.value.trim())
    enter()
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
}

function backToPassword() {
  totpRequired.value = false
  challenge.value = ''
  code.value = ''
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
  width: min(380px, 100%);
  border-radius: 14px;
}
</style>
