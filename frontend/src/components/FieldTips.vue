<template>
  <div v-if="meta.hint || showExample" class="fnwg-field-tips">
    <div v-if="meta.hint" class="fnwg-field-hint">{{ meta.hint }}</div>
    <div v-if="showExample && primaryExample" class="fnwg-field-example">
      <span class="fnwg-field-example-label">示例</span>
      <code>{{ primaryExample.value }}</code>
      <span class="fnwg-field-example-desc">— {{ primaryExample.desc }}</span>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import type { FieldMeta } from '@/constants/fields'

const props = withDefaults(
  defineProps<{
    meta: FieldMeta
    /** 是否在下方额外展示一条示例（复杂字段建议开启） */
    example?: boolean
  }>(),
  { example: false },
)

const primaryExample = computed(() => props.meta.examples?.[0])
const showExample = computed(() => props.example && !!primaryExample.value)
</script>

<style scoped>
.fnwg-field-tips {
  margin-top: 4px;
  line-height: 1.6;
}

.fnwg-field-hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.fnwg-field-example {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 2px;
  word-break: break-word;
}

.fnwg-field-example-label {
  color: var(--el-color-primary);
  margin-right: 4px;
}

.fnwg-field-example code {
  color: var(--el-color-success);
  word-break: break-all;
}
</style>
