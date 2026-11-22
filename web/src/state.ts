import { reactive } from 'vue'

export interface CurrentUser {
  id: number
  username: string
  role: 'admin' | 'user'
  allow_file: boolean
  allow_clipboard: boolean
}

export const state = reactive({
  user: null as CurrentUser | null,
  ready: false,
})

export async function refreshMe() {
  try {
    const { user } = await import('./api').then(m => m.get<{ user: CurrentUser }>('/me'))
    state.user = user
  } catch {
    state.user = null
  } finally {
    state.ready = true
  }
}
