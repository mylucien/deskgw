// 性能模式控制端的内核，跑在 Worker 里：解密、解析控制消息、解码 H.264。
//
// 主线程只做三件事：把 WebSocket 的二进制帧转进来、把这里产出的上行帧发出去、
// 把 VideoFrame 画到画布上。密钥只在 Worker 里，被控端与浏览器之间的端到端
// 加密到此为止，网关始终只见到密文。

import { avcCodecString, importKeyBundle, openSealed, parseMediaHeader, sealUnit } from './wire'
import type { SessionKeys } from './wire'
import { decodeHostDatagram, decodeHostMsg, encodeAck, encodeClipboard, encodeEcho, encodeInput, encodePing, encodeRequestKeyframe } from './messages'
import type { InputEvent } from './messages'

const VD = (self as any).VideoDecoder
const post = (msg: any, transfer?: Transferable[]) => (self as any).postMessage(msg, transfer || [])

let keys: SessionKeys | null = null
let ctrlBuf = new Uint8Array(0)
let ctrlChain: Promise<void> = Promise.resolve()
// 大块通道也是一条常驻流、连续的帧，必须按顺序解开（计数一个接一个）。
let bulkBuf = new Uint8Array(0)
let bulkSeq = -1
let bulkChain: Promise<void> = Promise.resolve()
let upChain: Promise<void> = Promise.resolve()
let pingTimer: number | undefined
let stopped = false

// 下行流的组装：每帧画面一条流（seq 由网关分配），控制通道固定 seq 0 常驻。
interface StreamBuf {
  parts: Uint8Array[]
  size: number
  arrived: number
}
const streams = new Map<number, StreamBuf>()

interface Waiting {
  seq: number
  key: boolean
  ts: number
  data: Uint8Array
}

interface DecoderState {
  decoder: any
  expected: number | null
  pending: Map<number, Waiting>
  decoded: Set<number>
  lastSeq: number
  askedAt: number
  width: number
  height: number
  codec: string
}
const decoders = new Map<number, DecoderState>()

const stats = { frames: 0, bytes: 0, dropped: 0, decodeErrors: 0, rtt: 0 }
let lastAck = new Map<number, { seq: number; arrived: number }>()

const nowUs = () => Math.round(performance.now() * 1000)

function concat(parts: Uint8Array[], total = 0): Uint8Array {
  const size = total || parts.reduce((n, p) => n + p.length, 0)
  const out = new Uint8Array(size)
  let off = 0
  for (const p of parts) {
    out.set(p, off)
    off += p.length
  }
  return out
}

self.onmessage = (ev: MessageEvent) => {
  const m = ev.data
  if (!m || typeof m !== 'object') return
  if (m.type === 'start') void start(m.keys)
  else if (m.type === 'frame') onBinary(new Uint8Array(m.data as ArrayBuffer))
  else if (m.type === 'input') sendControl(encodeInput(m.t, m.events as InputEvent[]))
  else if (m.type === 'clipboard') sendBulk(encodeClipboard(String(m.text || '')))
  else if (m.type === 'stop') stop()
}

async function start(bundle: any) {
  try {
    keys = await importKeyBundle(bundle)
  } catch (e) {
    post({ type: 'fatal', message: '会话密钥无法使用：' + String(e) })
    return
  }
  post({ type: 'ready' })
  lastStats = { frames: 0, bytes: 0, at: performance.now() }
  pingTimer = (self as any).setInterval(tick, 1000)
}

function stop() {
  stopped = true
  if (pingTimer !== undefined) (self as any).clearInterval(pingTimer)
  for (const st of decoders.values()) {
    try {
      st.decoder?.close()
    } catch {
      /* 已经关了 */
    }
  }
  decoders.clear()
  streams.clear()
}

// ---- 下行帧 ---------------------------------------------------------------

function onBinary(u8: Uint8Array) {
  if (!keys || stopped || u8.length < 2) return
  stats.bytes += u8.length
  switch (u8[0]) {
    case 0x01:
      onDownStream(u8)
      break
    case 0x02:
      void onDatagram(u8.subarray(2))
      break
  }
}

function onDownStream(u8: Uint8Array) {
  if (u8.length < 7) return
  const lane = u8[1]
  const view = new DataView(u8.buffer, u8.byteOffset, u8.byteLength)
  const seq = view.getUint32(2, true)
  const flags = u8[6]
  const data = u8.subarray(7)

  if (lane === 0) {
    // 控制通道：一条常驻流，里面是连续的长度前缀帧。
    ctrlBuf = concat([ctrlBuf, data], ctrlBuf.length + data.length)
    for (;;) {
      if (ctrlBuf.length < 4) break
      const n = new DataView(ctrlBuf.buffer, ctrlBuf.byteOffset, 4).getUint32(0, true)
      if (n === 0 || ctrlBuf.length < 4 + n) break
      const unit = ctrlBuf.slice(4, 4 + n)
      ctrlBuf = ctrlBuf.slice(4 + n)
      ctrlChain = ctrlChain.then(() => handleControl(unit))
    }
    return
  }
  if (lane === 1) {
    // 大块通道：剪贴板、光标图像。同样按长度前缀切，但共用一条流。
    if (bulkSeq !== seq) {
      bulkSeq = seq
      bulkBuf = new Uint8Array(0)
    }
    bulkBuf = concat([bulkBuf, data], bulkBuf.length + data.length)
    for (;;) {
      if (bulkBuf.length < 4) break
      const n = new DataView(bulkBuf.buffer, bulkBuf.byteOffset, 4).getUint32(0, true)
      if (n === 0 || bulkBuf.length < 4 + n) break
      const unit = bulkBuf.slice(4, 4 + n)
      bulkBuf = bulkBuf.slice(4 + n)
      bulkChain = bulkChain.then(() => handleBulk(unit))
    }
    return
  }
  if (lane < 2 || lane > 5) return

  let buf = streams.get(seq)
  if (!buf) {
    buf = { parts: [], size: 0, arrived: nowUs() }
    streams.set(seq, buf)
  }
  buf.parts.push(data)
  buf.size += data.length

  if (flags & 0x02) {
    // 网关整帧丢弃：清掉组装状态。
    streams.delete(seq)
    stats.dropped++
    return
  }
  if (!(flags & 0x01)) {
    if (streams.size > 96) dropStaleStreams()
    return
  }
  streams.delete(seq)
  const whole = concat(buf.parts, buf.size)
  if (whole.length < 4) return
  const n = new DataView(whole.buffer, whole.byteOffset, 4).getUint32(0, true)
  if (4 + n > whole.length) return
  void handleVideo(lane - 2, whole.subarray(4, 4 + n), buf.arrived)
}

function dropStaleStreams() {
  const cut = nowUs() - 3_000_000
  for (const [seq, b] of streams) {
    if (b.arrived < cut) streams.delete(seq)
  }
}

async function handleBulk(unit: Uint8Array) {
  if (!keys) return
  let plain: Uint8Array
  try {
    plain = await openSealed(keys.bulkRecv, unit)
  } catch {
    // 大块通道乱序/丢帧：跳过这一条，别把整个会话废掉（剪贴板不是关键路径）。
    console.warn('[perf] 大块通道解密失败')
    return
  }
  const ev = decodeHostMsg(plain)
  if (ev && ev.type === 'clipboard') post({ type: 'event', event: ev })
}

async function handleControl(unit: Uint8Array) {
  if (!keys) return
  let plain: Uint8Array
  try {
    plain = await openSealed(keys.controlRecv, unit)
  } catch {
    // 计数必须一个接一个：解不开说明这条通道已经乱了，继续收也没意义。
    post({ type: 'fatal', message: '控制通道解密失败，会话已失效' })
    return
  }
  const ev = decodeHostMsg(plain)
  if (!ev) return
  if (ev.type === 'bye') {
    post({ type: 'event', event: ev })
    post({ type: 'ended', reason: byeText(ev.reason) })
    return
  }
  post({ type: 'event', event: ev })
  if (ev.type === 'hello') askKeyframe(true)
}

function byeText(reason: number): string {
  if (reason === 0) return '被控端的用户断开了所有控制端。'
  if (reason === 1) return '被控端更换了控制码，会话已结束。'
  return '被控端结束了会话。'
}

async function onDatagram(sealed: Uint8Array) {
  if (!keys) return
  let plain: Uint8Array
  try {
    plain = await openSealed(keys.datagramRecv, sealed)
  } catch {
    return
  }
  const dg = decodeHostDatagram(plain)
  if (!dg) return
  if (dg.type === 'probe') {
    sendDatagram(encodeEcho(dg.t))
  } else {
    const rtt = (nowUs() - dg.t) / 1000
    if (rtt >= 0 && rtt < 60_000) stats.rtt = Math.round(rtt)
  }
}

// ---- 画面 ----------------------------------------------------------------

async function handleVideo(stream: number, unit: Uint8Array, arrived: number) {
  if (!keys) return
  const key = keys.video[stream]
  if (!key) return
  let plain: Uint8Array
  try {
    plain = await openSealed(key, unit)
  } catch {
    return
  }
  const h = parseMediaHeader(plain)
  if (!h || h.kind !== 1) return

  // 收到就确认，被控端的发送窗口才往前走。
  sendAck(h.seq, arrived, h.stream)

  if (h.codec !== 0) {
    postOnce('codec', { type: 'event', event: { type: 'notice', text: '被控端用的是 H.265，这一版只会解 H.264。', recovered: false } })
    return
  }
  const st = decoderState(h.stream, h.width, h.height)
  if (st.pending.size >= 24) {
    // 缺的帧一直没补上：丢掉积压，等下一个关键帧。
    st.pending.clear()
    st.expected = null
    askKeyframe()
  }
  st.pending.set(h.seq, { seq: h.seq, key: h.key, ts: h.captureUs, data: plain.subarray(h.headerLen) })
  drain(st)
}

const posted = new Set<string>()
function postOnce(tag: string, msg: any) {
  if (posted.has(tag)) return
  posted.add(tag)
  post(msg)
}

function decoderState(stream: number, width: number, height: number): DecoderState {
  let st = decoders.get(stream)
  if (!st) {
    st = {
      decoder: null, expected: null, pending: new Map(), decoded: new Set(),
      lastSeq: 0, askedAt: 0, width, height, codec: '',
    }
    decoders.set(stream, st)
  }
  st.width = width
  st.height = height
  return st
}

function ensureDecoder(st: DecoderState, sample: Uint8Array): boolean {
  if (st.decoder) return true
  if (!VD) {
    postOnce('nocodecs', { type: 'fatal', message: '这个浏览器不支持 WebCodecs，无法解码画面。' })
    return false
  }
  const codec = avcCodecString(sample)
  if (!codec) return false
  let dec: any
  try {
    dec = new VD({
      output: (frame: any) => {
        stats.frames++
        post({ type: 'video', frame }, [frame])
      },
      error: (e: any) => onDecoderError(st, e),
    })
    dec.configure({
      codec,
      codedWidth: st.width || 1920,
      codedHeight: st.height || 1080,
      optimizeForLatency: true,
      avc: { format: 'annexb' },
    })
  } catch (e) {
    st.decoder = null
    postOnce('decode-config', { type: 'fatal', message: '解码器初始化失败：' + String(e) })
    return false
  }
  st.decoder = dec
  st.codec = codec
  return true
}

function onDecoderError(st: DecoderState, e: any) {
  stats.decodeErrors++
  console.warn('[perf] 解码器出错', e)
  try {
    st.decoder?.close()
  } catch {
    /* 已经关了 */
  }
  st.decoder = null
  st.pending.clear()
  st.decoded.clear()
  st.expected = null
  askKeyframe()
}

function drain(st: DecoderState) {
  if (!st.decoder) {
    let first: Waiting | null = null
    for (const f of st.pending.values()) {
      if (f.key && (!first || f.seq < first.seq)) first = f
    }
    if (!first) return
    if (!ensureDecoder(st, first.data)) {
      // 等不来可用的关键帧（不是 H.264），别一直攒着。
      st.pending.clear()
      return
    }
    st.expected = first.seq
  }

  // 后面的关键帧可以跳过缺口：被控端放弃了那几帧，等下去只会越来越晚。
  // 有多个候选时取最小的，中间还能解的帧不白扔。
  if (st.expected !== null) {
    let jump = -1
    for (const f of st.pending.values()) {
      if (f.key && f.seq > st.expected + 3 && (jump < 0 || f.seq < jump)) jump = f.seq
    }
    if (jump >= 0) st.expected = jump
  }

  while (st.expected !== null) {
    const f = st.pending.get(st.expected)
    if (!f) break
    st.pending.delete(f.seq)
    if (!st.decoder) break
    try {
      st.decoder.decode(new (self as any).EncodedVideoChunk({
        type: f.key ? 'key' : 'delta',
        timestamp: f.ts,
        data: f.data,
      }))
    } catch (e) {
      onDecoderError(st, e)
      return
    }
    st.decoded.add(f.seq)
    if (st.decoded.size > 64) st.decoded.delete(f.seq - 64)
    st.lastSeq = f.seq
    st.expected++
  }
}

// ---- 上行 -----------------------------------------------------------------

function sendAck(seq: number, arrived: number, stream: number) {
  lastAck.set(stream, { seq, arrived })
  sendDatagram(encodeAck(seq, arrived, stream))
}

function sendDatagram(plain: Uint8Array) {
  if (!keys) return
  upChain = upChain.then(async () => {
    if (!keys || stopped) return
    const sealed = await sealUnit(keys.datagramSend, keys.datagramSendCounter++, plain)
    const out = new Uint8Array(2 + sealed.length)
    out[0] = 0x12
    out[1] = 1
    out.set(sealed, 2)
    post({ type: 'uplink', data: out.buffer }, [out.buffer])
  })
}

// sendBulk 写大块通道：帧里只有长度前缀，网关负责写会话头、开流。
function sendBulk(plain: Uint8Array) {
  if (!keys) return
  upChain = upChain.then(async () => {
    if (!keys || stopped) return
    const sealed = await sealUnit(keys.bulkSend, keys.bulkSendCounter++, plain)
    const out = new Uint8Array(6 + sealed.length)
    out[0] = 0x11
    out[1] = 1
    new DataView(out.buffer).setUint32(2, sealed.length, true)
    out.set(sealed, 6)
    post({ type: 'uplink', data: out.buffer }, [out.buffer])
  })
}

function sendControl(plain: Uint8Array) {
  if (!keys) return
  upChain = upChain.then(async () => {
    if (!keys || stopped) return
    const sealed = await sealUnit(keys.controlSend, keys.sendCounter++, plain)
    const out = new Uint8Array(6 + sealed.length)
    out[0] = 0x11
    out[1] = 0
    new DataView(out.buffer).setUint32(2, sealed.length, true)
    out.set(sealed, 6)
    post({ type: 'uplink', data: out.buffer }, [out.buffer])
  })
}

let askedAt = 0
function askKeyframe(force = false) {
  const now = nowUs()
  if (!force && now - askedAt < 500_000) return
  askedAt = now
  const last = Math.max(0, ...Array.from(decoders.values()).map((s) => s.lastSeq))
  sendControl(encodeRequestKeyframe(last, 0))
}

// ---- 心跳与统计 -----------------------------------------------------------

let lastStats = { frames: 0, bytes: 0, at: 0 }
function tick() {
  if (!keys || stopped) return
  sendDatagram(encodePing(nowUs()))
  // 确认可能丢：随每次心跳重发最近的几个，被控端收到重复的什么也不做。
  for (const [stream, a] of lastAck) sendDatagram(encodeAck(a.seq, a.arrived, stream))
  dropStaleStreams()

  const now = performance.now()
  if (lastStats.at) {
    const dt = (now - lastStats.at) / 1000
    post({
      type: 'stats',
      stats: {
        fps: Math.round((stats.frames - lastStats.frames) / dt),
        kbps: Math.round(((stats.bytes - lastStats.bytes) * 8) / dt / 1000),
        bytes: stats.bytes,
        dropped: stats.dropped,
        rtt: stats.rtt,
        errors: stats.decodeErrors,
      },
    })
  }
  lastStats = { frames: stats.frames, bytes: stats.bytes, at: now }
}
