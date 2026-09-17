<template>
  <div class="setup-page">
    <el-card class="setup-card">
      <!-- 第一步：创建管理员 -->
      <template v-if="!code">
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
      </template>

      <!-- 第二步：把应急安全码交给用户。强制确认保存后才放行 -->
      <template v-else>
        <div style="text-align: center; margin-bottom: 16px">
          <h2 style="margin: 0 0 4px">请保存你的应急安全码</h2>
          <div style="font-size: 13px; opacity: 0.65">这是所有登录方式都失效时的最后入口</div>
        </div>

        <el-alert v-if="codeError" type="warning" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>{{ codeError }}</template>
        </el-alert>

        <SecurityCodeBlock v-if="code" :code="code" />

        <div class="setup-hint">
          它能做什么：管理员忘记密码、手机丢失且恢复码也遗失、或飞牛网关异常导致界面进不去时，
          在登录页点「应急登录」输入它即可进入，并重置密码或关闭二次验证。
        </div>
        <div class="setup-hint">
          请注意：<strong>只能使用一次</strong>，用过之后系统会立即作废它并下发新的一码；
          系统只保存它的哈希，明文无法再次查看，我们也无法帮你找回。请离线保存（密码管理器或纸质），
          不要截图转发或上传网盘。
        </div>

        <el-checkbox v-if="code" v-model="saved" style="margin: 4px 0 12px">
          我已妥善保存这枚安全码
        </el-checkbox>
        <el-button
          type="primary"
          size="large"
          style="width: 100%"
          :disabled="!!code && !saved"
          @click="enter"
        >
          进入控制台
        </el-button>
      </template>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import SecurityCodeBlock from '@/components/SecurityCodeBlock.vue'

const router = useRouter()
const session = useSession()
const realtime = useRealtime()
const loading = ref(false)
const error = ref('')
const form = reactive({ username: '', password: '', confirm: '' })

/** 初始化成功后拿到的应急安全码；非空即进入第二步。 */
const code = ref('')
const codeError = ref('')
const saved = ref(false)

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
    const res = await session.setup(form.username, form.password)
    code.value = res.securityCode
    codeError.value = res.securityCodeError
    // 安全码生成失败时没有东西可保存，直接放行，不把用户卡在这一步。
    if (!res.securityCode) enter()
  } catch (e) {
    error.value = (e as Error).message
  } finally {
    loading.value = false
  }
}

function enter() {
  realtime.connect()
  router.replace('/dashboard')
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
  width: min(460px, 100%);
  border-radius: 14px;
}
.setup-hint {
  font-size: 12px;
  line-height: 1.7;
  opacity: 0.7;
  margin-top: 10px;
}
</style>
