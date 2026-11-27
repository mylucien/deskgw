// 浏览器控制端的连接层：WebSocket 只管搬字节，解密/解码都在 Worker 里。
//
// 票据只能用一次，wsPath 由后端签发；ready 里的密钥在内存里交给 Worker，
// 主线程不保留。

import type { HostEvent, InputEvent } from './messages'

export interface PerfReady {
  type: 'ready'
  session_id: number
  host: { id: number; name: string; os: string }
  safety: string
  keys: any
}

export interface PerfStats {
  fps: number
  kbps: number
  bytes: number
  dropped: number
  rtt: number
  errors: number
}

export interface PerfHandlers {
  onReady?: (r: PerfReady) => void
  onEvent?: (e: HostEvent) => void
  onVideo?: (frame: VideoFrame) => void
  onStats?: (s: PerfStats) => void
  onError?: (kind: string, message: string) => void
  onEnded?: (reason: string) => void
  onFatal?: (message: string) => void
}

export interface PerfConnection {
  /** 发一批输入事件；t 是这些事件在控制端时钟上的时刻（微秒）。 */
  sendInput(events: InputEvent[], t: number): void
  /** 把一段文本推到被控端的剪贴板（大块通道）。 */
  sendClipboard(text: string): void
  close(): void
}

export function connectPerf(wsPath: string, hostId: number, h: PerfHandlers): PerfConnection {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(proto + '//' + location.host + wsPath)
  ws.binaryType = 'arraybuffer'

  let worker: Worker | null = null
  let workerReady = false
  let closed = false
  const backlog: ArrayBuffer[] = []
  let beat = 0

  const shutdown = () => {
    if (closed) return
    closed = true
    window.clearInterval(beat)
    worker?.terminate()
    worker = null
    ws.onclose = null
    ws.onmessage = null
    if (ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify({ type: 'disconnect' }))
      } catch {
        /* 已经断了 */
      }
    }
    ws.close()
  }

  function startWorker(keys: any) {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (ev: MessageEvent) => {
      const m = ev.data
      switch (m?.type) {
        case 'ready':
          workerReady = true
          for (const buf of backlog.splice(0)) worker!.postMessage({ type: 'frame', data: buf }, [buf])
          break
        case 'uplink':
          if (ws.readyState === WebSocket.OPEN) ws.send(m.data)
          break
        case 'video':
          h.onVideo?.(m.frame)
          break
        case 'event':
          h.onEvent?.(m.event as HostEvent)
          break
        case 'stats':
          h.onStats?.(m.stats as PerfStats)
          break
        case 'fatal':
          h.onFatal?.(m.message || '会话失败')
          break
        case 'ended':
          h.onEnded?.(m.reason || '')
          break
      }
    }
    worker.postMessage({ type: 'start', keys })
  }

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'connect', host: 'h' + hostId }))
  }

  ws.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      let m: any
      try {
        m = JSON.parse(ev.data)
      } catch {
        return
      }
      if (m.type === 'ready') {
        h.onReady?.(m as PerfReady)
        startWorker(m.keys)
      } else if (m.type === 'error') {
        h.onError?.(m.kind || '', m.message || '连接失败')
      } else if (m.type === 'ended') {
        h.onEnded?.(m.reason || '')
      }
      return
    }
    const buf = ev.data as ArrayBuffer
    if (workerReady && worker) worker.postMessage({ type: 'frame', data: buf }, [buf])
    else if (backlog.length < 64) backlog.push(buf)
  }

  ws.onclose = () => {
    if (!closed) h.onEnded?.('连接已关闭')
    shutdown()
  }

  // 与服务端 30 秒心跳对齐：空闲桌面没有画面变化时，靠它保住 WebSocket。
  beat = window.setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'ping' }))
  }, 30_000)

  return {
    sendClipboard(text: string) {
      if (worker && workerReady && text) worker.postMessage({ type: 'clipboard', text })
    },
    sendInput(events: InputEvent[], t: number) {
      if (workerReady && worker) worker.postMessage({ type: 'input', events, t })
    },
    close: shutdown,
  }
}
