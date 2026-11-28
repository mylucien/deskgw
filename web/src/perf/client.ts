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
  /** 发一批输入事件。时间戳由 Worker 取，与心跳同一个时钟。 */
  sendInput(events: InputEvent[]): void
  /** 设置画质（帧率/码率/短边），连上后与切换档位时各发一次。 */
  sendSettings(quality: QualitySettings): void
  /** 把一段文本推到被控端的剪贴板（大块通道）。 */
  sendClipboard(text: string): void
  /**
   * 粘贴：先把文本推到大块通道，等它真的写进 WebSocket 之后再补一次 Ctrl+V。
   * 剪贴板走大块流、按键走控制流，两条流之间没有先后保证，直接连着发偶尔会
   * 粘到被控端的旧剪贴板内容。返回 true 表示内容超长被截断了。
   */
  sendPaste(text: string): boolean
  close(): void
}

/** 等 ready 的上限。握手要经过 QUIC 拨号与 Noise 往返，正常一两秒。 */
const READY_TIMEOUT_MS = 20_000
/** 心跳间隔，与服务端的 WS ping 对齐。 */
const BEAT_MS = 30_000
/** 超过这么久没收到任何消息就认为链路已经断了（半开连接不会触发 onclose）。 */
const SILENCE_MS = 75_000
/** 文本写进 WebSocket 之后等被控端收录剪贴板的时间，再让它粘贴。 */
const PASTE_GAP_MS = 60
/** 关闭时留给 Worker 把上行队列发完的时间。 */
const SHUTDOWN_GRACE_MS = 300
/**
 * 单条剪贴板的字节上限。网关的读限制是 maxBulkMsg(2MiB) 加转发头与长度前缀，
 * 这里留出 CBOR 与密封开销的余量。按 UTF-8 字节算：一个汉字占 3 字节，
 * 按字符数限会在中文上超出一倍多。
 */
export const MAX_CLIPBOARD_BYTES = 1_500_000
/** Worker 启动前最多攒多少个视频块（控制/大块通道的块一律不丢）。 */
const VIDEO_BACKLOG = 32

/** 按 UTF-8 字节截断，避开被切开的半个字符。返回是否发生了截断。 */
export function clipClipboard(text: string): { text: string; clipped: boolean } {
  if (!text) return { text, clipped: false }
  const bytes = new TextEncoder().encode(text)
  if (bytes.length <= MAX_CLIPBOARD_BYTES) return { text, clipped: false }
  const strict = new TextDecoder('utf-8', { fatal: true })
  // 最多回退 3 个字节就能落到完整字符的边界上。
  for (let end = MAX_CLIPBOARD_BYTES; end > MAX_CLIPBOARD_BYTES - 4; end--) {
    try {
      return { text: strict.decode(bytes.subarray(0, end)), clipped: true }
    } catch {
      /* 尾部半个字符，再退一个字节 */
    }
  }
  return { text: new TextDecoder().decode(bytes.subarray(0, MAX_CLIPBOARD_BYTES)), clipped: true }
}

/** 下行帧：0x01 是流数据，通道号 ≥ 2 表示画面。丢了只会少一帧。 */
function isVideoFrame(buf: ArrayBuffer): boolean {
  if (buf.byteLength < 2) return false
  const u8 = new Uint8Array(buf, 0, 2)
  return u8[0] === 0x01 && u8[1] >= 2
}

export function connectPerf(wsPath: string, hostId: number, h: PerfHandlers, display = 0): PerfConnection {
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
  let videoBacklog = 0
  let beat = 0
  let readyTimer = 0
  let lastInbound = Date.now()
  let pasteSeq = 0

  // 关闭时先把 Worker 的上行队列发完再 terminate：加密是异步链，
  // 立刻 terminate 会让「松开所有按键」一次也发不出去。
  const shutdown = (silent = false) => {
    if (closed) return
    closed = true
    window.clearInterval(beat)
    window.clearTimeout(readyTimer)
    ws.onmessage = null
    ws.onerror = null
    ws.onopen = null

    const w = worker
    worker = null
    workerReady = false
    let finished = false
    const finish = () => {
      if (finished) return
      finished = true
      w?.terminate()
      ws.onclose = null
      if (!silent && ws.readyState === WebSocket.OPEN) {
        try {
          ws.send(JSON.stringify({ type: 'disconnect' }))
        } catch {
          /* 已经断了 */
        }
      }
      ws.close()
    }

    if (!w) {
      finish()
      return
    }
    w.onmessage = (ev: MessageEvent) => {
      const m = ev.data
      if (m?.type === 'uplink') {
        // 收尾期间的上行帧照常发出去（releaseAll 就在里面）。
        if (ws.readyState === WebSocket.OPEN) {
          try {
            ws.send(m.data)
          } catch {
            /* 已断 */
          }
        }
      } else if (m?.type === 'flushed') {
        finish()
      }
    }
    w.postMessage({ type: 'flush' })
    window.setTimeout(finish, SHUTDOWN_GRACE_MS)
  }

  // 只报一次收尾，并顺手把连接关掉。silent 让关闭帧不再发 disconnect。
  const settle = (fn: () => void) => {
    if (settled) return
    settled = true
    fn()
    shutdown(true)
  }

  const queueInput = (events: InputEvent[]) => {
    if (workerReady && worker) worker.postMessage({ type: 'input', events })
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
          videoBacklog = 0
          break
        case 'uplink':
          if (ws.readyState === WebSocket.OPEN) ws.send(m.data)
          break
        case 'clipboard-sent': {
          // 文本已经在 WebSocket 上了，稍等被控端收录，再补 Ctrl+V。
          const id = m.id as number
          if (id !== pasteSeq) break
          window.setTimeout(() => {
            queueInput([
              { kind: 'key', code: 'KeyV', down: true },
              { kind: 'key', code: 'KeyV', down: false },
            ])
          }, PASTE_GAP_MS)
          break
        }
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
    // display 只影响握手时的 ControllerIntro.view：多显示器机器上指定先推
    // 哪块屏。协议没有运行中切换的消息，换屏要重连（面板里选完就重连）。
    const hello: Record<string, unknown> = { type: 'connect', host: 'h' + hostId }
    if (display > 0) hello.display = display
    ws.send(JSON.stringify(hello))
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
    if (workerReady && worker) {
      worker.postMessage({ type: 'frame', data: buf }, [buf])
      return
    }
    // Worker 启动前的积压。只丢视频块：控制通道与大块通道是长度前缀流，
    // 丢掉中间一块会让浏览器从错位的位置继续切帧，最终报「控制通道解密失败」。
    if (isVideoFrame(buf)) {
      if (videoBacklog >= VIDEO_BACKLOG) return
      videoBacklog++
    }
    backlog.push(buf)
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
      const clipped = clipClipboard(text)
      if (worker && workerReady && clipped.text) {
        worker.postMessage({ type: 'clipboard', text: clipped.text })
      }
    },
    sendPaste(text: string) {
      const clipped = clipClipboard(text)
      if (!worker || !workerReady || !clipped.text) return clipped.clipped
      const id = ++pasteSeq
      worker.postMessage({ type: 'clipboard', text: clipped.text, ack: id })
      return clipped.clipped
    },
    sendInput(events: InputEvent[]) {
      queueInput(events)
    },
    sendSettings(quality: QualitySettings) {
      if (workerReady && worker) worker.postMessage({ type: 'settings', quality })
      else pendingQuality = quality
    },
    close: shutdown,
  }
}
