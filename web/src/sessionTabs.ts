// 多标签会话状态。凭据仅存内存，标签关闭即清除，不写 localStorage / URL。
import { reactive } from 'vue'
import type { Credentials } from './rdp'

export const MAX_TABS = 4

export interface TabInfo {
  key: string
  hostName: string
  hostId: number
  sessionId: number
  wsPath: string
  creds: Credentials
  status: 'connecting' | 'connected' | 'disconnected' | 'error'
}

export const workspace = reactive<{ tabs: TabInfo[]; active: string }>({
  tabs: [],
  active: '',
})

export function openTab(info: Omit<TabInfo, 'key' | 'status'>): TabInfo {
  if (workspace.tabs.length >= MAX_TABS) {
    throw new Error(`最多同时打开 ${MAX_TABS} 个会话，请先关闭一个标签`)
  }
  const key = typeof crypto.randomUUID === 'function' ? crypto.randomUUID() : String(Date.now() + Math.random())
  const tab: TabInfo = { ...info, key, status: 'connecting' }
  workspace.tabs.push(tab)
  workspace.active = key
  return tab
}

export function closeTab(key: string) {
  const i = workspace.tabs.findIndex(t => t.key === key)
  if (i >= 0) {
    const tab = workspace.tabs[i]
    wipeCreds(tab.creds)
    workspace.tabs.splice(i, 1)
  }
  if (workspace.active === key) {
    const next = workspace.tabs[Math.min(Math.max(i, 0), workspace.tabs.length - 1)]
    workspace.active = next ? next.key : ''
  }
}

// closeAllTabs 在退出登录或切换账号时清空工作区：
// 移除全部标签（触发 RdpCanvas 卸载并断开 WASM 会话）并擦除内存中的 Windows 凭据。
export function closeAllTabs() {
  for (const t of workspace.tabs) wipeCreds(t.creds)
  workspace.tabs.splice(0, workspace.tabs.length)
  workspace.active = ''
}

export function wipeCreds(c: Credentials) {
  c.username = ''
  c.password = ''
  c.domain = ''
}
