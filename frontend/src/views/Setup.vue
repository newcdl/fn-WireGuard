<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<template>
  <div class="fnwg-auth-page">
    <div class="fnwg-auth-glow fnwg-auth-glow-a" aria-hidden="true" />
    <div class="fnwg-auth-glow fnwg-auth-glow-b" aria-hidden="true" />

    <div class="fnwg-auth-shell">
      <div class="fnwg-auth-head">
        <img :src="logoUrl" alt="" class="fnwg-auth-logo" />
        <div>
          <div class="fnwg-auth-brand">WireGuard 管理工具</div>
          <div class="fnwg-auth-sub">
            {{ code ? '最后一步：保存应急安全码' : '首次使用，先决定用什么方式进入' }}
          </div>
        </div>
      </div>

      <!-- ============ 第一步：选择进入方式 ============ -->
      <template v-if="!code">
        <!-- 说明必须与下面真正给出的选项一致：端口入口上只有账号密码一种方式，
             却写「两种方式选一种」，用户会以为界面坏了（真机反馈）。 -->
        <div class="fnwg-auth-note">
          <template v-if="gatewayAvailable">
            检测到飞牛账号「<strong>{{ gatewayName }}</strong>」：它可以直接登录本应用，不必再输一遍密码
            —— 飞牛管理员进来是管理员，普通成员进来是只读。
          </template>
          <template v-else>
            当前是「IP:端口」入口，这条通道上没有飞牛身份，因此只能创建账号密码。
            想直接用飞牛账号登录（不必输密码），请改为<strong>从飞牛桌面点开本应用</strong>。
          </template>
        </div>

        <!-- 确实存在第二种方式时才给出选择：只有一个选项时摆两个按钮反而让人以为要选 -->
        <div v-if="gatewayAvailable" class="fnwg-auth-choices">
          <button
            type="button"
            class="fnwg-auth-choice"
            :class="{ 'is-active': method === 'password' }"
            :aria-pressed="method === 'password'"
            @click="method = 'password'"
          >
            <span class="fnwg-auth-choice-icon"><el-icon><Key /></el-icon></span>
            <span>
              <span class="fnwg-auth-choice-title">创建本地账号</span>
              <span class="fnwg-auth-choice-desc">账号密码登录，也可用「IP:端口」直接进入</span>
            </span>
            <el-icon v-if="method === 'password'" class="fnwg-auth-choice-check"><CircleCheck /></el-icon>
          </button>

          <button
            type="button"
            class="fnwg-auth-choice"
            :class="{ 'is-active': method === 'gateway' }"
            :aria-pressed="method === 'gateway'"
            @click="method = 'gateway'"
          >
            <span class="fnwg-auth-choice-icon"><el-icon><Monitor /></el-icon></span>
            <span>
              <span class="fnwg-auth-choice-title">只用飞牛账号登录</span>
              <span class="fnwg-auth-choice-desc">不保存任何口令，从飞牛桌面点开即可进入</span>
            </span>
            <el-icon v-if="method === 'gateway'" class="fnwg-auth-choice-check"><CircleCheck /></el-icon>
          </button>
        </div>

        <!-- 选了本地账号：三个字段 -->
        <el-form v-if="method === 'password'" :model="form" label-position="top">
          <el-form-item label="登录账号">
            <el-input v-model="form.username" size="large" placeholder="例如 admin" autofocus />
          </el-form-item>
          <el-form-item label="登录密码">
            <el-input v-model="form.password" size="large" type="password" show-password placeholder="至少 8 位" />
          </el-form-item>
          <el-form-item label="再输入一次密码">
            <el-input
              v-model="form.confirm"
              size="large"
              type="password"
              show-password
              placeholder="再次输入密码"
              @keyup.enter="submit"
            />
          </el-form-item>
          <div class="fnwg-auth-hint">
            本地账号可以用「IP:端口」直接登录，不依赖飞牛桌面入口；与飞牛账号共用同一套权限。
          </div>
        </el-form>

        <!-- 选了飞牛账号：说清接下来会发生什么 -->
        <template v-else>
          <div class="fnwg-auth-note">
            本应用<strong>不会保存任何口令</strong>，进入方式完全交给飞牛账号
            （「{{ gatewayName || '当前飞牛账号' }}」会成为第一位管理员）。
            留意「IP:端口」入口将没有可用的本地账号，只能走飞牛桌面或应急登录。
          </div>
        </template>

        <el-alert
          v-if="error"
          :title="error"
          type="error"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
        />
        <el-button type="primary" size="large" class="fnwg-auth-submit" :loading="loading" @click="submit">
          {{ method === 'gateway' ? '用飞牛账号完成初始化' : '创建并进入' }}
        </el-button>
      </template>

      <!-- ============ 第二步：把应急安全码交给用户（必须确认保存才放行） ============ -->
      <template v-else>
        <el-alert v-if="codeError" type="warning" :closable="false" show-icon style="margin-bottom: 12px">
          <template #title>{{ codeError }}</template>
        </el-alert>

        <SecurityCodeBlock v-if="code" :code="code" />

        <div class="fnwg-auth-hint">
          它能做什么：{{ method === 'gateway' ? '飞牛入口打不开时' : '管理员忘记密码、手机丢失且恢复码也遗失、或界面根本打不开时' }}，
          在登录页点「应急登录」输入它即可进入，并设置或重置密码、关闭二次验证。
        </div>
        <div class="fnwg-auth-hint">
          请注意：<strong>只能使用一次</strong>，用过之后系统会立即作废它并下发新的一码；
          系统只保存它的哈希，明文无法再次查看，我们也无法帮你找回。请离线保存（密码管理器或纸质），
          不要截图转发或上传网盘。
        </div>

        <el-checkbox v-if="code" v-model="saved" style="margin: 10px 0 12px">
          我已妥善保存这枚安全码
        </el-checkbox>
        <el-button
          type="primary"
          size="large"
          class="fnwg-auth-submit"
          :disabled="!!code && !saved"
          @click="enter"
        >
          进入控制台
        </el-button>
      </template>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { CircleCheck, Key, Monitor } from '@element-plus/icons-vue'
import { useSession } from '@/stores/session'
import { useRealtime } from '@/stores/realtime'
import SecurityCodeBlock from '@/components/SecurityCodeBlock.vue'
import logoUrl from '@/assets/app-icon.png'

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

/**
 * 进入方式：password = 建本地账号（等于保留一条不依赖飞牛入口的退路）；
 * gateway = 不建账号、完全交给飞牛身份。
 * 只有本次请求确实带着可核验的飞牛身份时才让选（否则选了也进不去，见后端 setupGatewayOnly）。
 */
const method = ref<'password' | 'gateway'>('password')
const gatewayAvailable = computed(() => !!session.gatewayUser)
const gatewayName = computed(() => session.gatewayUser?.username || '')

async function submit() {
  error.value = ''
  if (method.value === 'password') {
    if (!form.username || !form.password) {
      error.value = '请填写用户名与密码'
      return
    }
    if (form.password !== form.confirm) {
      error.value = '两次输入的密码不一致'
      return
    }
  }
  loading.value = true
  try {
    const res =
      method.value === 'gateway'
        ? await session.setupWithGateway()
        : await session.setup(form.username, form.password)
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
