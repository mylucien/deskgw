import { reactive } from 'vue'

export interface CurrentUser {
  id: number
  username: string
  role: 'admin' | 'user'
  allow_file: boolean
  allow_clipboard: boolean
  max_sessions: number
}

// 服务端生效的配额。前端不再写死标签上限：面板上写 4、服务端按 2 拒绝，
// 用户只会觉得「明明还能点却连不上」。
export interface Limits {
  max_sessions: number
}

const DEFAULT_MAX_SESSIONS = 2

export const state = reactive({
  user: null as CurrentUser | null,
  limits: { max_sessions: DEFAULT_MAX_SESSIONS } as Limits,
  ready: false,
})

export function applyMe(payload: { user: CurrentUser; limits?: Partial<Limits> }) {
  state.user = payload.user
  state.limits = {
    max_sessions: payload.limits?.max_sessions || payload.user?.max_sessions || DEFAULT_MAX_SESSIONS,
  }
}

export async function refreshMe() {
  try {
    const payload = await import('./api').then(m => m.get<{ user: CurrentUser; limits: Limits }>('/me'))
    applyMe(payload)
  } catch {
    state.user = null
  } finally {
    state.ready = true
  }
}
