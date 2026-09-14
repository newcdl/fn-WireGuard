<template>
  <div class="fnwg-scenario">
    <div class="fnwg-scenario-title">
      {{ title }}
      <span class="fnwg-scenario-sub">不确定怎么配？选一个最接近你目的的场景，参数会自动填好</span>
    </div>
    <div class="fnwg-scenario-list">
      <button
        v-for="p in presets"
        :key="p.key"
        type="button"
        class="fnwg-scenario-item"
        :class="{ active: modelValue === p.key }"
        @click="pick(p)"
      >
        <div class="fnwg-scenario-head">
          <span class="fnwg-scenario-name">{{ p.title }}</span>
          <el-icon v-if="modelValue === p.key" class="fnwg-scenario-check"><Select /></el-icon>
        </div>
        <div class="fnwg-scenario-desc">{{ p.desc }}</div>
        <div class="fnwg-scenario-outcome">
          <span>效果</span>{{ p.outcome }}
        </div>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { Select } from '@element-plus/icons-vue'
import type { ScenarioPreset } from '@/constants/fields'

const props = withDefaults(
  defineProps<{
    modelValue?: string
    presets: ScenarioPreset[]
    title?: string
  }>(),
  { title: '快速开始（推荐）', modelValue: '' },
)

const emit = defineEmits<{
  (e: 'update:modelValue', v: string): void
  (e: 'apply', v: Record<string, unknown>): void
}>()

function pick(p: ScenarioPreset) {
  emit('update:modelValue', p.key)
  emit('apply', p.values)
}
</script>

<style scoped>
.fnwg-scenario {
  margin-bottom: 14px;
}

.fnwg-scenario-title {
  font-size: 13px;
  font-weight: 600;
  margin-bottom: 8px;
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 6px;
}

.fnwg-scenario-sub {
  font-size: 12px;
  font-weight: 400;
  color: var(--el-text-color-secondary);
}

.fnwg-scenario-list {
  display: grid;
  gap: 8px;
  grid-template-columns: repeat(auto-fill, minmax(240px, 1fr));
}

.fnwg-scenario-item {
  text-align: left;
  cursor: pointer;
  padding: 10px 12px;
  border-radius: 10px;
  border: 1px solid var(--el-border-color);
  background: var(--el-fill-color-blank);
  transition: all 0.15s;
  font-family: inherit;
  color: inherit;
}

.fnwg-scenario-item:hover {
  border-color: var(--el-color-primary-light-5);
}

.fnwg-scenario-item.active {
  border-color: var(--el-color-primary);
  background: var(--el-color-primary-light-9);
}

.fnwg-scenario-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 6px;
}

.fnwg-scenario-name {
  font-size: 13px;
  font-weight: 600;
}

.fnwg-scenario-check {
  color: var(--el-color-primary);
}

.fnwg-scenario-desc {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
  line-height: 1.6;
}

.fnwg-scenario-outcome {
  font-size: 12px;
  color: var(--el-text-color-regular);
  margin-top: 6px;
  line-height: 1.6;
}

.fnwg-scenario-outcome span {
  display: inline-block;
  font-size: 11px;
  color: var(--el-color-success);
  margin-right: 4px;
}
</style>
