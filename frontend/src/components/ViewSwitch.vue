<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 小柿子 <newxsz@163.com> -->

<!--
  列表视图切换（表格 / 卡片）。
  放在列表所在页面的右上角：两个图标的单选，占位很小，不抢工具栏里那些「动作按钮」的位置。
  偏好由 useViewMode 负责记住，这里只管显示与回传。
-->
<template>
  <el-radio-group
    :model-value="modelValue"
    size="small"
    class="fnwg-view-switch"
    @update:model-value="onChange"
  >
    <el-radio-button value="table" title="表格视图：一行一条，字段对齐好比较">
      <el-icon><Grid /></el-icon>
    </el-radio-button>
    <el-radio-button value="cards" title="卡片视图：一条一块，信息分组更清楚">
      <el-icon><Postcard /></el-icon>
    </el-radio-button>
  </el-radio-group>
</template>

<script setup lang="ts">
import { Grid, Postcard } from '@element-plus/icons-vue'
import type { ListViewMode } from '@/composables/useViewMode'

defineProps<{ modelValue: ListViewMode }>()
const emit = defineEmits<{ (e: 'update:modelValue', v: ListViewMode): void }>()

/** 只认这两种取值：控件传回来的类型宽，这里收窄一次，免得把脏值写进偏好里。 */
function onChange(v: string | number | boolean | undefined): void {
  emit('update:modelValue', v === 'cards' ? 'cards' : 'table')
}
</script>

<style scoped>
.fnwg-view-switch {
  display: flex;
  flex: 0 0 auto;
  /* 两种情况都要落在右上角：放进工具栏（flex 行）时靠 margin-left 顶到最右，
     独立成行时靠自身右对齐 —— 各列表的容器不一样，这两条一起才能统一位置。 */
  justify-content: flex-end;
  margin-left: auto;
}

.fnwg-view-switch :deep(.el-radio-button__inner) {
  padding: 5px 9px;
}
</style>
