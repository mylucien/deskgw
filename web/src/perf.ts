// 性能模式会话的交接信息。票据只能用一次，放在内存里跨路由传，不写 URL 也不落盘。
import { reactive } from 'vue'

export interface PerfTicket {
  hostName: string
  hostId: number
  sessionId: number
  /** 形如 /ws/perf?ticket=…，由后端签发。 */
  wsPath: string
}

export const perfSession = reactive<{ current: PerfTicket | null }>({ current: null })

export function openPerf(t: PerfTicket) {
  perfSession.current = t
}

export function closePerf() {
  perfSession.current = null
}
