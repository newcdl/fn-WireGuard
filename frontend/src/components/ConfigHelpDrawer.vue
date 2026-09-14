<template>
  <el-drawer
    :model-value="modelValue"
    :size="drawerSize"
    title="配置项说明大全"
    @update:model-value="emit('update:modelValue', $event)"
  >
    <div class="fnwg-help-drawer">
      <el-alert type="info" :closable="false" show-icon style="margin-bottom: 12px">
        <template #title>
          这里用最直白的语言解释了界面上每一项设置。看不懂某一项时，点击字段旁边的问号图标也能看到同样的说明。
        </template>
      </el-alert>

      <el-collapse v-model="active">
        <el-collapse-item v-for="g in groups" :key="g.key" :name="g.key">
          <template #title>
            <span class="fnwg-help-group-title">{{ g.title }}</span>
          </template>
          <div v-for="(meta, key) in g.fields" :key="key" class="fnwg-help-entry">
            <div class="fnwg-help-entry-title">{{ meta.label }}</div>
            <p>{{ meta.what }}</p>
            <p v-if="meta.why"><em>什么时候需要改：</em>{{ meta.why }}</p>
            <p v-if="meta.effect"><em>改完会怎样：</em>{{ meta.effect }}</p>
            <p v-if="meta.risk" class="fnwg-help-entry-risk"><em>注意事项：</em>{{ meta.risk }}</p>
            <div v-if="meta.examples?.length" class="fnwg-help-entries-examples">
              <div v-for="(ex, i) in meta.examples" :key="i" class="fnwg-help-entry-example">
                <strong>{{ ex.title }}</strong>
                <code>{{ ex.value }}</code>
                <span>{{ ex.desc }}</span>
              </div>
            </div>
          </div>
        </el-collapse-item>
      </el-collapse>
    </div>
  </el-drawer>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import type { FieldMeta } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'

defineProps<{
  modelValue: boolean
  groups: { key: string; title: string; fields: Record<string, FieldMeta> }[]
}>()

const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void }>()

const { drawerSize } = useBreakpoint()
const active = ref<string[]>([])
</script>

<style scoped>
.fnwg-help-drawer {
  padding-bottom: 20px;
}

.fnwg-help-group-title {
  font-weight: 600;
}

.fnwg-help-entry {
  padding: 8px 0 12px;
  border-bottom: 1px dashed var(--el-border-color-lighter);
}

.fnwg-help-entry:last-child {
  border-bottom: none;
}

.fnwg-help-entry-title {
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 4px;
}

.fnwg-help-entry p {
  margin: 2px 0;
  font-size: 12.5px;
  line-height: 1.7;
  color: var(--el-text-color-regular);
}

.fnwg-help-entry em {
  font-style: normal;
  color: var(--el-color-primary);
}

.fnwg-help-entry-risk p,
.fnwg-help-entry-risk {
  color: var(--el-color-warning);
}

.fnwg-help-entries-examples {
  margin-top: 6px;
}

.fnwg-help-entry-example {
  background: var(--el-fill-color-light);
  border-radius: 6px;
  padding: 6px 8px;
  margin-top: 4px;
  font-size: 12px;
  display: flex;
  flex-direction: column;
  gap: 2px;
}

.fnwg-help-entry-example code {
  color: var(--el-color-success);
  word-break: break-all;
}

.fnwg-help-entry-example span {
  color: var(--el-text-color-secondary);
}
</style>
