<template>
  <router-view />
</template>

<script setup lang="ts">
import { onMounted } from 'vue'
import { useRealtime } from '@/stores/realtime'

const realtime = useRealtime()

onMounted(() => {
  // 建立实时通道；未登录时服务端会拒绝，登录成功后由布局重新连接
  realtime.connect()
})
</script>
