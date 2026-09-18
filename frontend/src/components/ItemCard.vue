<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 newcdl <newcdl@163.com> -->

<template>
  <div class="fnwg-item-card" :class="{ selectable, selected }">
    <div v-if="selectable" class="fnwg-item-check" @click.stop="emit('toggle')">
      <el-checkbox :model-value="selected" @change="emit('toggle')" />
    </div>
    <div class="fnwg-item-main">
      <div class="fnwg-item-head">
        <div class="fnwg-item-title">
          <span v-if="status !== undefined" :class="['fnwg-dot', status]" />
          <slot name="title">{{ title }}</slot>
        </div>
        <div class="fnwg-item-extra">
          <slot name="extra" />
        </div>
      </div>

      <div class="fnwg-item-body">
        <slot />
      </div>

      <div v-if="$slots.actions" class="fnwg-item-actions">
        <slot name="actions" />
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
withDefaults(
  defineProps<{
    title?: string
    status?: 'ok' | 'warn' | 'off' | 'down'
    selectable?: boolean
    selected?: boolean
  }>(),
  { title: '', status: undefined, selectable: false, selected: false },
)

const emit = defineEmits<{ (e: 'toggle'): void }>()
</script>

<style scoped>
.fnwg-item-card {
  display: flex;
  gap: 8px;
  padding: 12px;
  border: 1px solid var(--fnwg-border);
  border-radius: 10px;
  background: var(--fnwg-card);
  margin-bottom: 10px;
}

.fnwg-item-card.selected {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}

.fnwg-item-check {
  padding-top: 2px;
}

.fnwg-item-main {
  flex: 1;
  min-width: 0;
}

.fnwg-item-head {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 8px;
}

.fnwg-item-title {
  font-weight: 600;
  font-size: 14px;
  display: flex;
  align-items: center;
  gap: 4px;
  min-width: 0;
  word-break: break-word;
}

.fnwg-item-extra {
  display: flex;
  gap: 4px;
  flex-wrap: wrap;
  justify-content: flex-end;
  flex: 0 0 auto;
}

.fnwg-item-body {
  margin-top: 6px;
  font-size: 12.5px;
  color: var(--el-text-color-regular);
  line-height: 1.7;
}

.fnwg-item-actions {
  margin-top: 10px;
  padding-top: 8px;
  border-top: 1px dashed var(--el-border-color-lighter);
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

/* 移动端字段行：标签左、值右，自动换行 */
:deep(.fnwg-kv) {
  display: flex;
  gap: 6px;
  align-items: baseline;
}

:deep(.fnwg-kv-key) {
  flex: 0 0 auto;
  color: var(--el-text-color-secondary);
}

:deep(.fnwg-kv-val) {
  flex: 1;
  min-width: 0;
  word-break: break-all;
}
</style>
