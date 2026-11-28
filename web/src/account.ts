import { ref } from 'vue'
import { post } from './api'
import { state } from './state'
import { closeAllTabs } from './sessionTabs'

/**
 * 「改密码」弹窗的开关。
 *
 * 弹窗本身挂在 App.vue 上（脱离路由，任何页面都能弹），但入口不只在顶栏：
 * 性能模式的顶栏已经让位给画面，改密码要能从悬浮面板里叫出来。所以把开关
 * 提到模块级，谁都能触发，不用层层传事件。
 */
export const pwdOpen = ref(false)

export function openPasswordDialog() {
  pwdOpen.value = true
}

export function closePasswordDialog() {
  pwdOpen.value = false
}

/**
 * 退出登录。
 *
 * 先断开所有 RDP 标签：closeAllTabs 会关掉 WASM 会话、断开 WS 并擦掉内存里的
 * Windows 凭据，不然退出后这些还留在页面里。性能模式的会话由调用方先关。
 * 路由跳转留给调用方 —— 它可能还要先清自己的页面状态。
 */
export async function logoutNow(): Promise<void> {
  closeAllTabs()
  try {
    await post('/logout')
  } catch {
    /* 网络断了也要把本地登录态清掉，否则页面停在「已登录」但什么都做不了 */
  }
  state.user = null
}
