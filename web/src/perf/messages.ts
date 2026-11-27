// 控制通道上的 CBOR 消息。被控端用 minicbor 派生编码：枚举是
// `[变体号, [字段…]]`，尾部取默认值的字段不写，所以字段按位置读、缺了用默认值。

import { CborReader, CborWriter } from './cbor'
import type { CborValue } from './cbor'

export interface DisplayInfo {
  index: number
  name: string
  x: number
  y: number
  width: number
  height: number
  primary: boolean
}

export type HostEvent =
  | {
      type: 'hello'
      hostname: string
      os: string
      version: string
      displays: DisplayInfo[]
      current: number
      codecs: number[]
      platform: number
      shown: number[]
      streams: number
      touch: boolean
    }
  | { type: 'displays'; displays: DisplayInfo[]; current: number; shown: number[] }
  | { type: 'encoder'; codec: number; name: string; hardware: boolean; width: number; height: number; stream: number }
  | { type: 'cursor'; visibility: number; slot: number; generation: number }
  /**
   * 光标形状，走大块通道。rgba 是宽×高×4 字节的 RGBA8（非预乘），
   * 热点是相对图像左上角的像素偏移。槽位/代际用来对抗乱序与复用。
   */
  | {
      type: 'cursorImage'
      slot: number
      generation: number
      width: number
      height: number
      hotX: number
      hotY: number
      rgba: Uint8Array
    }
  | { type: 'notice'; text: string; recovered: boolean }
  | { type: 'clipboard'; text: string }
  | { type: 'bye'; reason: number }
  | { type: 'other'; variant: number }

function arr(v: CborValue | undefined): CborValue[] {
  return Array.isArray(v) ? v : []
}

function num(v: CborValue | undefined, def = 0): number {
  return typeof v === 'number' ? v : def
}

function str(v: CborValue | undefined, def = ''): string {
  return typeof v === 'string' ? v : def
}

function parseDisplay(v: CborValue): DisplayInfo {
  const a = arr(v)
  return {
    index: num(a[0]),
    name: str(a[1]),
    x: num(a[2]),
    y: num(a[3]),
    width: num(a[4]),
    height: num(a[5]),
    primary: a[6] === true,
  }
}

function parseDisplays(v: CborValue | undefined): DisplayInfo[] {
  return arr(v).map(parseDisplay)
}

/** 被控端提示的类型编号换成中文，未知的返回空串（不显示）。 */
const notices: Record<number, string> = {
  0: '被控端没有可以采集的显示器。',
  1: '被控端是 Wayland 桌面，只能采集 X11 程序。',
  2: '屏幕采集失败，被控端正在重试。',
  4: '声音采集失败，被控端正在重试。',
  6: '被控端缺少系统权限：画面或操作可能不可用。',
}

export function decodeHostMsg(buf: Uint8Array): HostEvent | null {
  let outer: CborValue
  try {
    outer = new CborReader(buf).value()
  } catch {
    return null
  }
  const head = arr(outer)
  const variant = num(head[0], -1)
  if (variant < 0) return null
  const fields = arr(head[1])

  switch (variant) {
    case 1: {
      // Hello 是单字段变体：字段数组里套着 HostHello 的数组。老写法直接给数组，
      // 两种都接受，按第一项是不是字符串区分。
      const hello = Array.isArray(fields[0]) ? arr(fields[0]) : fields
      return {
        type: 'hello',
        hostname: str(hello[0]),
        os: str(hello[1]),
        version: str(hello[2]),
        displays: parseDisplays(hello[3]),
        current: num(hello[4]),
        codecs: arr(hello[5]).map((v) => num(v)),
        platform: num(hello[6]),
        shown: arr(hello[9]).map((v) => num(v)),
        streams: num(hello[10]),
        // 被控端能不能收 InputEvent::Touch，决定面板里是否给「触摸」选项。
        touch: hello[7] === true,
      }
    }
    case 4:
      return {
        type: 'displays',
        displays: parseDisplays(fields[0]),
        current: num(fields[1]),
        shown: arr(fields[2]).map((v) => num(v)),
      }
    case 5: {
      const notice = arr(fields[0])
      const id = num(notice[0], -1)
      if (id < 0) return { type: 'notice', text: '', recovered: true }
      const detail = arr(notice[1])[0]
      const text = notices[id] || ''
      return {
        type: 'notice',
        text: typeof detail === 'string' && detail ? `${text}（${detail}）` : text,
        recovered: id === 3 || id === 5,
      }
    }
    case 6:
      return {
        type: 'encoder',
        codec: num(fields[0]),
        name: str(fields[1]),
        hardware: fields[2] === true,
        width: num(fields[3]),
        height: num(fields[4]),
        stream: num(fields[5]),
      }
    case 7: {
      const shape = arr(fields[1])
      return {
        type: 'cursor',
        visibility: num(fields[0]),
        slot: num(shape[0], -1),
        generation: num(shape[1], -1),
      }
    }
    case 8:
      // 被控端剪贴板变了：大块通道上的单字段变体 [8, ["文本"]]。
      return { type: 'clipboard', text: str(fields[0]) }
    case 10: {
      // CursorImage = [10, [[槽位,代际],[宽,高,热点x,热点y,rgba]]]，大块通道。
      const ref = arr(fields[0])
      const shape = arr(fields[1])
      const rgba = shape[4]
      return {
        type: 'cursorImage',
        slot: num(ref[0], -1),
        generation: num(ref[1], -1),
        width: num(shape[0]),
        height: num(shape[1]),
        hotX: num(shape[2]),
        hotY: num(shape[3]),
        // CborReader 给的是底层缓冲的视图，复制一份，免得后续收包覆盖。
        rgba: rgba instanceof Uint8Array ? rgba.slice() : new Uint8Array(0),
      }
    }
    case 9:
      return { type: 'bye', reason: num(fields[0]) }
    default:
      return { type: 'other', variant }
  }
}

// ---- 发往被控端 -----------------------------------------------------------

/** 触摸阶段编号与 airhand_proto::session::TouchPhase 一致。 */
export type TouchPhaseName = 'down' | 'move' | 'up' | 'cancel'
const touchPhase: Record<TouchPhaseName, number> = { down: 0, move: 1, up: 2, cancel: 3 }

/** 输入事件。编号与 airhand_proto::session::InputEvent 一致。 */
export type InputEvent =
  | { kind: 'move'; x: number; y: number; stream?: number }
  | { kind: 'delta'; dx: number; dy: number }
  | { kind: 'button'; button: number; down: boolean }
  | { kind: 'wheel'; dx: number; dy: number }
  | { kind: 'key'; code: string; down: boolean }
  | { kind: 'text'; text: string }
  | { kind: 'releaseAll' }
  | { kind: 'touch'; id: number; phase: TouchPhaseName; x: number; y: number }

/**
 * ControllerMsg::Input = [1, [t, [事件…]]]。
 *
 * t 是控制端的时钟（微秒，与 Ping 同一个时钟），被控端用它丢掉晚到太久的
 * 输入；同一批里的事件按顺序执行，鼠标移动由被控端合并。
 */
export function encodeInput(t: number, events: InputEvent[]): Uint8Array {
  const w = new CborWriter()
  w.array(2).uint(1).array(2).uint(t).array(events.length)
  for (const e of events) {
    switch (e.kind) {
      case 'move':
        w.array(2).uint(0).array(e.stream ? 3 : 2).float32(e.x).float32(e.y)
        if (e.stream) w.uint(e.stream)
        break
      case 'delta':
        w.array(2).uint(1).array(2).int(e.dx).int(e.dy)
        break
      case 'button':
        w.array(2).uint(2).array(2).uint(e.button).bool(e.down)
        break
      case 'wheel':
        w.array(2).uint(3).array(2).int(e.dx).int(e.dy)
        break
      case 'key':
        w.array(2).uint(4).array(2).text(e.code).bool(e.down)
        break
      case 'text':
        w.array(2).uint(5).array(1).text(e.text)
        break
      case 'releaseAll':
        w.array(2).uint(6).array(0)
        break
      case 'touch':
        // 坐标同 MouseMove（归一化 0..1）；多点靠 id 区分，同一批是同一时刻。
        w.array(2).uint(7).array(4).uint(e.id & 0xff).uint(touchPhase[e.phase])
          .float32(e.x).float32(e.y)
        break
    }
  }
  return w.take()
}

/** 画质设置，字段名与被控端的 QualitySettings 一致（kbps、短边像素）。 */
export interface QualitySettings {
  fps: number
  bitrateKbps: number
  maxShort: number
  adaptive: boolean
  codec: number
  /** 把被控端光标画进画面（游戏模式）；false 时整项不写上线。 */
  drawCursor?: boolean
}

/**
 * ControllerMsg::Settings = [3, [[fps,码率,短边,自适应,codec,(画进画面?)]]]。
 * 最后一项是 skip_if=false，默认不写；被控端收到后自己夹到合法范围，没有回执。
 */
export function encodeSettings(q: QualitySettings): Uint8Array {
  const w = new CborWriter()
  const n = q.drawCursor ? 6 : 5
  w.array(2).uint(3).array(1).array(n)
    .uint(q.fps).uint(q.bitrateKbps).uint(q.maxShort).bool(q.adaptive).uint(q.codec)
  if (q.drawCursor) w.bool(true)
  return w.take()
}

/** ControllerMsg::Clipboard = [7, [文本]]，走大块通道。 */
export function encodeClipboard(text: string): Uint8Array {
  return new CborWriter().array(2).uint(7).array(1).text(text).take()
}

/** ControllerMsg::RequestKeyframe = [4, [after, stream?]]。 */
export function encodeRequestKeyframe(after: number, stream = 0): Uint8Array {
  const w = new CborWriter()
  const n = stream ? 2 : 1
  w.array(2).uint(4).array(n).uint(after >>> 0)
  if (stream) w.uint(stream)
  return w.take()
}

/** ControllerDatagram::Ping = [0, [t]]。 */
export function encodePing(t: number): Uint8Array {
  return new CborWriter().array(2).uint(0).array(1).uint(t).take()
}

/** ControllerDatagram::Ack = [1, [seq, arrived, stream?]]。 */
export function encodeAck(seq: number, arrived: number, stream = 0): Uint8Array {
  const w = new CborWriter()
  w.array(2).uint(1).array(stream ? 3 : 2).uint(seq >>> 0).uint(arrived)
  if (stream) w.uint(stream)
  return w.take()
}

/**
 * ControllerDatagram::Report = [4, [[frames, stalled], (stream?)]]。
 * 都是本周期（500ms）的个数，不是累计；frames=0 时上游不会发。
 */
export function encodeReport(frames: number, stalled: number, stream = 0): Uint8Array {
  const w = new CborWriter()
  w.array(2).uint(4).array(stream ? 2 : 1)
    .array(2).uint(frames).uint(stalled)
  if (stream) w.uint(stream)
  return w.take()
}

/** ControllerDatagram::Echo = [2, [t]]。 */
export function encodeEcho(t: number): Uint8Array {
  return new CborWriter().array(2).uint(2).array(1).uint(t).take()
}

/** 解 HostDatagram：0 Pong、1 Probe，其余返回 null。 */
export function decodeHostDatagram(buf: Uint8Array): { type: 'pong' | 'probe'; t: number } | null {
  let outer: CborValue
  try {
    outer = new CborReader(buf).value()
  } catch {
    return null
  }
  const head = arr(outer)
  const variant = num(head[0], -1)
  const t = num(arr(head[1])[0])
  if (variant === 0) return { type: 'pong', t }
  if (variant === 1) return { type: 'probe', t }
  return null
}
