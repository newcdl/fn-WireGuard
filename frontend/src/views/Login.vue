<template>
  <div class="login-page">
    <el-card class="login-card">
      <div style="text-align: center; margin-bottom: 20px">
        <el-icon :size="36" color="#409eff"><Connection /></el-icon>
        <h2 style="margin: 10px 0 4px">WireGuard 管理</h2>
        <div style="font-size: 13px; opacity: 0.65">飞牛 NAS 原生 WireGuard 控制台</div>
      </div>
      <el-form :model="form" label-position="top" @submit.prevent="submit">
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

async function submit() {
  if (!form.username || !form.password) {
    ElMessage.warning('请填写用户名与密码')
    return
  }
  loading.value = true
  try {
    await session.login(form.username, form.password)
    realtime.connect()
    const redirect = (route.query.redirect as string) || '/dashboard'
    router.replace(redirect)
  } catch (e) {
    ElMessage.error((e as Error).message)
  } finally {
    loading.value = false
  }
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
