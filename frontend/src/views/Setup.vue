<template>
  <div class="setup-page">
    <el-card class="setup-card">
      <div style="text-align: center; margin-bottom: 20px">
        <el-icon :size="36" color="#409eff"><Connection /></el-icon>
        <h2 style="margin: 10px 0 4px">初始化管理员</h2>
        <div style="font-size: 13px; opacity: 0.65">首次使用，请创建管理员账号</div>
      </div>
      <el-form :model="form" label-position="top">
        <el-form-item label="登录账号">
          <el-input v-model="form.username" placeholder="例如 admin" />
        </el-form-item>
        <el-form-item label="登录密码">
          <el-input v-model="form.password" type="password" show-password placeholder="至少 8 位" />
        </el-form-item>
        <el-form-item label="再输入一次密码">
          <el-input v-model="form.confirm" type="password" show-password placeholder="再次输入密码" />
        </el-form-item>
        <el-alert
          v-if="error"
          :title="error"
          type="error"
          :closable="false"
          style="margin-bottom: 12px"
        />
        <el-button type="primary" size="large" style="width: 100%" :loading="loading" @click="submit">
          创建并进入
        </el-button>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'

const router = useRouter()
const session = useSession()
const realtime = useRealtime()
const loading = ref(false)
const error = ref('')
const form = reactive({ username: '', password: '', confirm: '' })

async function submit() {
  error.value = ''
  if (!form.username || !form.password) {
    error.value = '请填写用户名与密码'
    return
  }
  if (form.password !== form.confirm) {
    error.value = '两次输入的密码不一致'
    return
  }
  loading.value = true
  try {
    await session.setup(form.username, form.password)
    realtime.connect()
    router.replace('/dashboard')
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.setup-page {
  min-height: 100vh;
  min-height: 100dvh;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: 16px;
  background: var(--fnwg-bg);
}
.setup-card {
  width: min(400px, 100%);
  border-radius: 14px;
}
</style>
