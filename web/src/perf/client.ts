// 浏览器控制端的连接层：WebSocket 只管搬字节，解密/解码都在 Worker 里。
//
// 票据只能用一次，wsPath 由后端签发；ready 里的密钥在内存里交给 Worker，
// 主线程不保留。
//
// 生命周期只有三种收尾：error（带 kind，界面显示对应提示）、ended（正常结束，
// 带原因）、fatal（本地解码器等致命错误）。三者互斥，先到先算，后续的
// WebSocket onclose 不会再补一句「连接已关闭」把真正的原因盖掉。

import type { HostEvent, InputEvent, QualitySettings } from './messages'

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
  /** 累计丢弃帧数。 */
  dropped: number
  /** 最近一个统计周期的丢弃速率（帧/秒），用来判断「现在还在丢吗」。 */
  dropRate: number
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
  /** 设置画质（帧率/码率/短边），连上后与切换档位时各发一次。 */
  sendSettings(quality: QualitySettings): void
  /** 把一段文本推到被控端的剪贴板（大块通道）。 */
  sendClipboard(text: string): void
  close(): void
}

/** 等 ready 的上限。握手要经过 QUIC 拨号与 Noise 往返，正常一两秒。 */
const READY_TIMEOUT_MS = 20_000
/** 心跳间隔，与服务端的 WS ping 对齐。 */
const BEAT_MS = 30_000
/** 超过这么久没收到任何消息就认为链路已经断了（半开连接不会触发 onclose）。 */
const SILENCE_MS = 75_000

export function connectPerf(wsPath: string, hostId: number, h: PerfHandlers): PerfConnection {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const ws = new WebSocket(proto + '//' + location.host + wsPath)
  ws.binaryType = 'arraybuffer'

  let worker: Worker | null = null
  let workerReady = false
  let closed = false
  // ready 之前被拒（票据失效、主机不存在）浏览器只给一个笼统的 error 事件，
  // 具体状态码拿不到；记下来，让 onclose 的提示别把网络错误说成正常结束。
  let linkError = false
  let ready = false
  // 已经报过 error/ended/fatal 中的一种。
  let settled = false
  // ready 回调先于 Worker 启动，连上时的首次画质设置先攒着，Worker 就绪再发。
  let pendingQuality: QualitySettings | null = null
  const backlog: ArrayBuffer[] = []
  let beat = 0
  let readyTimer = 0
  let lastInbound = Date.now()

  const shutdown = (silent = false) => {
    if (closed) return
    closed = true
    window.clearInterval(beat)
    window.clearTimeout(readyTimer)
    worker?.terminate()
    worker = null
    ws.onclose = null
    ws.onmessage = null
    if (!silent && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify({ type: 'disconnect' }))
      } catch {
        /* 已经断了 */
      }
    }
    ws.close()
  }

  // 只报一次收尾，并顺手把连接关掉。silent 让关闭帧不再发 disconnect。
  const settle = (fn: () => void) => {
    if (settled) return
    settled = true
    fn()
    shutdown(true)
  }

  function startWorker(keys: any) {
    worker = new Worker(new URL('./worker.ts', import.meta.url), { type: 'module' })
    worker.onmessage = (ev: MessageEvent) => {
      const m = ev.data
      switch (m?.type) {
        case 'ready':
          workerReady = true
          if (pendingQuality) {
            worker.postMessage({ type: 'settings', quality: pendingQuality })
            pendingQuality = null
          }
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
          // 解码器起不来时 Worker 已经没救了：报错并关连接，别让会话记录
          // 一直挂在 active 上等用户点「返回主机列表」。
          settle(() => h.onFatal?.(m.message || '会话失败'))
          break
        case 'ended':
          settle(() => h.onEnded?.(m.reason || ''))
          break
      }
    }
    worker.postMessage({ type: 'start', keys })
  }

  ws.onopen = () => {
    ws.send(JSON.stringify({ type: 'connect', host: 'h' + hostId }))
  }

  ws.onerror = () => {
    linkError = true
  }

  ws.onmessage = (ev) => {
    lastInbound = Date.now()
    if (typeof ev.data === 'string') {
      let m: any
      try {
        m = JSON.parse(ev.data)
      } catch {
        return
      }
      if (m.type === 'ready') {
        ready = true
        window.clearTimeout(readyTimer)
        h.onReady?.(m as PerfReady)
        startWorker(m.keys)
      } else if (m.type === 'error') {
        settle(() => h.onError?.(m.kind || 'serverError', m.message || '连接失败'))
      } else if (m.type === 'ended') {
        settle(() => h.onEnded?.(m.reason || ''))
      }
      return
    }
    const buf = ev.data as ArrayBuffer
    if (workerReady && worker) worker.postMessage({ type: 'frame', data: buf }, [buf])
    else if (backlog.length < 64) backlog.push(buf)
  }

  ws.onclose = () => {
    if (closed) return
    if (!settled) {
      if (ready) {
        settled = true
        h.onEnded?.('连接已关闭')
      } else {
        settled = true
        // 到这一步连接已经被拒或中断。升级前的拒绝（票据失效、主机已删）
        // 只有一个 HTTP 状态码，浏览器不把它交给 JS，所以这里给一句能指导
        // 用户下一步的提示，而不是「连接已关闭」。
        h.onError?.(
          'connectFailed',
          linkError
            ? '连接被拒绝或中断：票据可能已失效（一次有效），或被控端已离线。'
            : '网关在握手完成前关闭了连接：票据可能已失效，请返回主机列表重试。',
        )
      }
    }
    shutdown(true)
  }

  readyTimer = window.setTimeout(() => {
    if (settled || ready) return
    settle(() => h.onError?.('serverError', '网关在 20 秒内没有完成握手，被控端可能不在线。'))
  }, READY_TIMEOUT_MS)

  // 心跳兼做半开检测：服务端收到 ping 会回 pong，任何消息都算活着。
  // 手机切网、Wi-Fi 掉线时 TCP 不会立刻报错，只靠 onclose 会一直显示「已连接」。
  let lastBeat = Date.now()
  beat = window.setInterval(() => {
    const now = Date.now()
    const gap = now - lastBeat
    lastBeat = now
    if (ws.readyState !== WebSocket.OPEN) return
    // 后台标签页的定时器会被浏览器压到一分钟甚至冻结，恢复后的第一拍不能
    // 当成链路中断，否则切回来就误报「网络中断」。
    if (gap <= BEAT_MS * 2 && now - lastInbound > SILENCE_MS) {
      settle(() => h.onEnded?.('网络中断（长时间没有收到数据）'))
      return
    }
    ws.send(JSON.stringify({ type: 'ping' }))
  }, BEAT_MS)

  return {
    sendClipboard(text: string) {
      if (worker && workerReady && text) worker.postMessage({ type: 'clipboard', text })
    },
    sendInput(events: InputEvent[], t: number) {
      if (workerReady && worker) worker.postMessage({ type: 'input', events, t })
    },
    sendSettings(quality: QualitySettings) {
      if (workerReady && worker) worker.postMessage({ type: 'settings', quality })
      else pendingQuality = quality
    },
    close: shutdown,
  }
}
