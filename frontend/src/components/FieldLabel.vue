<template>
  <span class="fnwg-field-label">
    <span class="fnwg-field-label-text">{{ meta.label }}</span>
    <el-popover
      :width="helpPopoverWidth"
      trigger="click"
      placement="top-start"
      :teleported="true"
      popper-class="fnwg-help-popper"
    >
      <template #reference>
        <!--
          @click.prevent 是必须的：el-form-item 会把标签渲染成 <label for="控件 id">，
          而问号就在标签里。不拦下默认行为的话，点问号会被浏览器当成「点击它关联的控件」——
          对于开关/勾选框就是被连带切换（看说明却把开关打开了）。
          只 preventDefault、不 stopPropagation：气泡自身的打开与点击外部关闭都依赖事件冒泡。
        -->
        <el-icon class="fnwg-field-help-icon" :title="`查看「${meta.label}」说明`" @click.prevent>
          <QuestionFilled />
        </el-icon>
      </template>

      <div class="fnwg-help">
        <div class="fnwg-help-title">{{ meta.label }}</div>

        <div class="fnwg-help-block">
          <span class="fnwg-help-tag">它是什么</span>
          <p>{{ meta.what }}</p>
        </div>

        <div v-if="meta.why" class="fnwg-help-block">
          <span class="fnwg-help-tag">什么时候需要改</span>
          <p>{{ meta.why }}</p>
        </div>

        <div v-if="meta.effect" class="fnwg-help-block">
          <span class="fnwg-help-tag">改完会怎样</span>
          <p>{{ meta.effect }}</p>
        </div>

        <div v-if="meta.risk" class="fnwg-help-block fnwg-help-risk">
          <span class="fnwg-help-tag">注意事项</span>
          <p>{{ meta.risk }}</p>
        </div>

        <div v-if="meta.examples?.length" class="fnwg-help-block">
          <span class="fnwg-help-tag">可以参考这样填</span>
          <div v-for="(ex, i) in meta.examples" :key="i" class="fnwg-help-example">
            <div class="fnwg-help-example-head">
              <strong>{{ ex.title }}</strong>
              <code>{{ ex.value }}</code>
            </div>
            <p>{{ ex.desc }}</p>
          </div>
        </div>
      </div>
    </el-popover>
  </span>
</template>

<script setup lang="ts">
import { QuestionFilled } from '@element-plus/icons-vue'
import type { FieldMeta } from '@/constants/fields'
import { useBreakpoint } from '@/composables/useBreakpoint'

defineProps<{ meta: FieldMeta }>()

const { helpPopoverWidth } = useBreakpoint()
</script>

<style scoped>
.fnwg-field-label {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  line-height: 1.4;
}

.fnwg-field-label-text {
  white-space: normal;
  word-break: break-word;
}

.fnwg-field-help-icon {
  color: var(--el-color-primary);
  cursor: pointer;
  font-size: 14px;
  flex: 0 0 auto;
}

.fnwg-field-help-icon:hover {
  opacity: 0.75;
}
</style>

<style>
/* 气泡内容为全局样式，需要覆盖 Element Plus 默认内边距 */
.fnwg-help-popper {
  max-height: 60vh;
  overflow: auto;
}

.fnwg-help {
  font-size: 13px;
  line-height: 1.65;
}

.fnwg-help-title {
  font-weight: 600;
  font-size: 14px;
  margin-bottom: 8px;
  padding-bottom: 6px;
  border-bottom: 1px solid var(--el-border-color-lighter);
}

.fnwg-help-block {
  margin-bottom: 10px;
}

.fnwg-help-block p {
  margin: 2px 0 0;
  color: var(--el-text-color-regular);
  word-break: break-word;
}

.fnwg-help-tag {
  display: inline-block;
  font-size: 11px;
  font-weight: 600;
  color: var(--el-color-primary);
  margin-bottom: 2px;
}

.fnwg-help-risk .fnwg-help-tag {
  color: var(--el-color-warning);
}

.fnwg-help-example {
  margin-top: 6px;
  padding: 6px 8px;
  border-radius: 6px;
  background: var(--el-fill-color-light);
}

.fnwg-help-example-head {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: baseline;
}

.fnwg-help-example-head code {
  font-size: 11px;
  word-break: break-all;
  color: var(--el-color-success);
}

.fnwg-help-example p {
  margin: 2px 0 0;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
