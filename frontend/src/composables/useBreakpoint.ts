import { computed, ref } from 'vue'

/**
 * 全局共享的窗口尺寸状态。
 * 布局、表格列、表单宽度都依赖它来做自适应，因此在模块级别只维护一份。
 */
const width = ref(typeof window === 'undefined' ? 1280 : window.innerWidth)
const height = ref(typeof window === 'undefined' ? 800 : window.innerHeight)

function update() {
  width.value = window.innerWidth
  height.value = window.innerHeight
}

if (typeof window !== 'undefined') {
  window.addEventListener('resize', update, { passive: true })
  window.addEventListener('orientationchange', update, { passive: true })
}

export function useBreakpoint() {
  /** 手机：纵向单列布局，表格退化为卡片 */
  const isMobile = computed(() => width.value < 768)
  /** 平板：保留表格但隐藏次要列 */
  const isTablet = computed(() => width.value >= 768 && width.value < 1200)
  const isDesktop = computed(() => width.value >= 1200)

  /** 表单抽屉宽度：手机上铺满 */
  const drawerSize = computed(() => (isMobile.value ? '100%' : '560px'))
  /** 弹窗宽度：手机上留一点边距 */
  const dialogWidth = computed(() => (isMobile.value ? '94%' : undefined))
  /** 帮助气泡宽度 */
  const helpPopoverWidth = computed(() => Math.min(360, Math.max(240, width.value - 48)))

  return { width, height, isMobile, isTablet, isDesktop, drawerSize, dialogWidth, helpPopoverWidth }
}
