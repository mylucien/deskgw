// RDP WASM 会话封装：Windows 凭据仅存在于浏览器内，网关不可见。
// 由 wasm-pack 从官方 IronRDP 源码构建，产物在 src/wasm/pkg（CI 生成）。
import init, {
  SessionBuilder,
  ClipboardData,
  DesktopSize,
  Extension,
  DeviceEvent,
  InputTransaction,
  RotationUnit,
} from './wasm/pkg/ironrdp_web.js'
import type { Session, SessionTerminationInfo } from './wasm/pkg/ironrdp_web.js'

let wasmReady: Promise<unknown> | null = null

export function ensureWasm(): Promise<unknown> {
  if (!wasmReady) wasmReady = init()
  return wasmReady
}

export interface Credentials {
  username: string
  password: string
  domain: string
}

export interface RdpOptions {
  wsUrl: string
  /** 目标主机 IP（仅用于 TLS SNI 与证书名称，连接目标由网关按票据决定）。 */
  destination: string
  /** TOFU 指纹的存储键，通常用主机 ID。 */
  fingerprintKey: string
  canvas: HTMLCanvasElement
  credentials: Credentials
  width: number
  height: number
  /** 是否启用剪贴板同步，跟随用户权限 allow_clipboard。 */
  allowClipboard?: boolean
  onLog?: (level: string, message: string) => void
}

export interface RdpSession {
  shutdown: () => void
  resize: (width: number, height: number) => void
  sendCtrlAltDel: () => void
  /** 把键盘焦点交还远程桌面（点击工具栏后需要重新聚焦）。 */
  focus: () => void
  terminated: Promise<string>
}

export function resolveWsUrl(path: string): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return scheme + '//' + location.host + path
}

// 浏览器 KeyboardEvent.code → PS/2 Set 1 扫描码。
// 扩展键必须带 0xE0 前缀：IronRDP 以 `scancode & 0xE000 == 0xE000` 判定扩展键，
// 传通键码（例如 0xCB）会被当作普通键，Delete / Home / 方向键在远端全部失效。
const codeMap: Record<string, number> = {
  KeyA: 0x1e, KeyB: 0x30, KeyC: 0x2e, KeyD: 0x20, KeyE: 0x12, KeyF: 0x21,
  KeyG: 0x22, KeyH: 0x23, KeyI: 0x17, KeyJ: 0x24, KeyK: 0x25, KeyL: 0x26,
  KeyM: 0x32, KeyN: 0x31, KeyO: 0x18, KeyP: 0x19, KeyQ: 0x10, KeyR: 0x13,
  KeyS: 0x1f, KeyT: 0x14, KeyU: 0x16, KeyV: 0x2f, KeyW: 0x11, KeyX: 0x2d,
  KeyY: 0x15, KeyZ: 0x2c,
  Digit1: 0x02, Digit2: 0x03, Digit3: 0x04, Digit4: 0x05, Digit5: 0x06,
  Digit6: 0x07, Digit7: 0x08, Digit8: 0x09, Digit9: 0x0a, Digit0: 0x0b,
  Enter: 0x1c, NumpadEnter: 0xe01c,
  Escape: 0x01, Backspace: 0x0e, Tab: 0x0f, Space: 0x39,
  Minus: 0x0c, Equal: 0x0d, BracketLeft: 0x1a, BracketRight: 0x1b,
  Backslash: 0x2b, Semicolon: 0x27, Quote: 0x28, Backquote: 0x29,
  Comma: 0x33, Period: 0x34, Slash: 0x35,
  CapsLock: 0x3a, ShiftLeft: 0x2a, ShiftRight: 0xe036,
  ControlLeft: 0x1d, ControlRight: 0xe01d,
  AltLeft: 0x38, AltRight: 0xe038,
  MetaLeft: 0xe05b, MetaRight: 0xe05c, ContextMenu: 0xe05d,
  PrintScreen: 0xe037, ScrollLock: 0x46,
  Insert: 0xe052, Home: 0xe047, PageUp: 0xe049, Delete: 0xe053,
  End: 0xe04f, PageDown: 0xe051,
  ArrowLeft: 0xe04b, ArrowRight: 0xe04d, ArrowUp: 0xe048, ArrowDown: 0xe050,
  NumpadDivide: 0xe035, NumpadMultiply: 0x37, NumpadSubtract: 0x4a, NumpadAdd: 0x4e,
  NumpadDecimal: 0x53, Numpad0: 0x52, Numpad1: 0x4f, Numpad2: 0x50, Numpad3: 0x51,
  Numpad4: 0x4b, Numpad5: 0x4c, Numpad6: 0x4d, Numpad7: 0x47, Numpad8: 0x48, Numpad9: 0x49,
  F1: 0x3b, F2: 0x3c, F3: 0x3d, F4: 0x3e, F5: 0x3f, F6: 0x40,
  F7: 0x41, F8: 0x42, F9: 0x43, F10: 0x44, F11: 0x57, F12: 0x58,
}

// code 缺失或为 "Unidentified" 时的兜底映射（按 KeyboardEvent.key）。
const scancodeMap: Record<string, number> = {
  'a': 0x1e, 'b': 0x30, 'c': 0x2e, 'd': 0x20, 'e': 0x12, 'f': 0x21,
  'g': 0x22, 'h': 0x23, 'i': 0x17, 'j': 0x24, 'k': 0x25, 'l': 0x26,
  'm': 0x32, 'n': 0x31, 'o': 0x18, 'p': 0x19, 'q': 0x10, 'r': 0x13,
  's': 0x1f, 't': 0x14, 'u': 0x16, 'v': 0x2f, 'w': 0x11, 'x': 0x2d,
  'y': 0x15, 'z': 0x2c,
  '1': 0x02, '2': 0x03, '3': 0x04, '4': 0x05, '5': 0x06,
  '6': 0x07, '7': 0x08, '8': 0x09, '9': 0x0a, '0': 0x0b,
  'Enter': 0x1c, 'Escape': 0x01, 'Backspace': 0x0e, 'Tab': 0x0f,
  ' ': 0x39, '-': 0x0c, '=': 0x0d, '[': 0x1a, ']': 0x1b,
  '\\': 0x2b, ';': 0x27, "'": 0x28, '`': 0x29, ',': 0x33,
  '.': 0x34, '/': 0x35, 'CapsLock': 0x3a, 'Shift': 0x2a,
  'Control': 0x1d, 'Alt': 0x38,
}
const specialMap: Record<string, number> = {
  'F1': 0x3b, 'F2': 0x3c, 'F3': 0x3d, 'F4': 0x3e, 'F5': 0x3f,
  'F6': 0x40, 'F7': 0x41, 'F8': 0x42, 'F9': 0x43, 'F10': 0x44,
  'F11': 0x57, 'F12': 0x58,
  'Insert': 0xe052, 'Home': 0xe047, 'PageUp': 0xe049, 'Delete': 0xe053,
  'End': 0xe04f, 'PageDown': 0xe051,
  'ArrowRight': 0xe04d, 'ArrowLeft': 0xe04b, 'ArrowDown': 0xe050, 'ArrowUp': 0xe048,
  'ContextMenu': 0xe05d, 'PrintScreen': 0xe037,
}

function scancodeOf(e: KeyboardEvent): number | null {
  if (codeMap[e.code] !== undefined) return codeMap[e.code]
  if (specialMap[e.key] !== undefined) return specialMap[e.key]
  if (scancodeMap[e.key] !== undefined) return scancodeMap[e.key]
  const k = e.key.toLowerCase()
  return scancodeMap[k] !== undefined ? scancodeMap[k] : null
}

// 把任意抛出物转成一句话。
//
// wasm 侧早先把错误包装成不透明对象，前端 `String(e)` 只能得到
// “[object Object]”，故障原因完全丢失。这里把能拿到的字段都摊开，
// 依次尝试 Error.message、对象的 message、JSON，最后才退回 String。
export function describeError(e: unknown): string {
  if (e instanceof Error) return e.message || e.name || String(e)
  if (typeof e === 'string') return e
  if (e && typeof e === 'object') {
    const anyErr = e as any
    if (typeof anyErr.message === 'string' && anyErr.message) return anyErr.message
    try {
      const json = JSON.stringify(e)
      if (json && json !== '{}') return json
    } catch { /* 循环引用或含不可序列化字段 */ }
    const str = Object.prototype.toString.call(e)
    if (str !== '[object Object]') return str
  }
  return String(e)
}

// 建立 RDP 会话并绑定画布输入。该函数返回后不再持有凭据。
export async function connectRdp(opts: RdpOptions): Promise<RdpSession> {
  await ensureWasm()
  const log = opts.onLog || (() => {})
  log('info', '正在初始化 RDP 协议栈')

  // 剪贴板回调在 connect 时才被读取，先声明会话占位供回调引用。
  let session: Session | null = null

  const builder = new SessionBuilder()
  builder.username(opts.credentials.username)
  builder.password(opts.credentials.password)
  if (opts.credentials.domain) builder.serverDomain(opts.credentials.domain)
  // destination 由网关强制替换为数据库中的主机地址，这里仅作协议占位。
  builder.destination(opts.destination)
  builder.proxyAddress(opts.wsUrl)
  // 首次连接不传指纹（TOFU）；之后传入已记录的指纹，变化即阻断，
  // 避免把 NLA 凭据交给被替换的主机。
  const fpKey = 'deskgw.cert.' + opts.fingerprintKey
  let expectedFp = ''
  try { expectedFp = localStorage.getItem(fpKey) || '' } catch { /* 隐私模式 */ }
  if (expectedFp) builder.expectedFingerprint(expectedFp)
  builder.desktopSize(new DesktopSize(opts.width, opts.height))
  builder.renderCanvas(opts.canvas)
  builder.extension(new Extension('enable_credssp', true))

  // 只打印 host 与路径，查询串里是票据，不写进日志。
  try {
    const u = new URL(opts.wsUrl)
    log('info', '正在连接网关 ' + u.host + u.pathname)
  } catch { /* 地址异常时留给 connect 报错 */ }

  // 一张 4K 截图约 1–3 MiB。wasm 侧还要把 PNG 转成 CF_DIBV5（未压缩位图，
  // 体积会再涨几倍），所以上限压在 4 MiB，超过就跳过并提示。
  const MAX_CLIPBOARD_IMAGE = 4 * 1024 * 1024

  const toBlob = (value: unknown): Blob | null => {
    if (value instanceof Uint8Array) return new Blob([value], { type: 'image/png' })
    if (Array.isArray(value)) return new Blob([new Uint8Array(value)], { type: 'image/png' })
    return null
  }

  // 把远端剪贴板写进浏览器。图片优先，写不进去时退回文本，
  // Firefox 不支持脚本写图片剪贴板，这条降级路径是常态而非异常。
  const writeRemoteClipboard = async (data: ClipboardData) => {
    let text = ''
    let png: Blob | null = null
    try {
      for (const item of data.items()) {
        const mime = item.mimeType()
        if (!text && mime === 'text/plain') {
          const value = item.value()
          if (typeof value === 'string') text = value
        } else if (!png && mime === 'image/png') {
          const blob = toBlob(item.value())
          const size = blob?.size ?? 0
          if (size > MAX_CLIPBOARD_IMAGE) {
            log('warn', '远端剪贴板图片过大，已跳过（' + Math.round(size / 1024) + ' KiB）')
          } else {
            png = blob
          }
        }
      }
    } catch (e: any) {
      log('warn', '解析远端剪贴板失败：' + (e?.message || e))
      return
    }
    if (png) {
      try {
        await navigator.clipboard.write([new ClipboardItem({ 'image/png': png })])
        return
      } catch (e: any) {
        log('warn', '写入图片到本地剪贴板失败（' + (e?.message || e) + '），改为写文本')
      }
    }
    if (text) {
      try { await navigator.clipboard.writeText(text) }
      catch (e: any) { log('warn', '写入本地剪贴板失败：' + (e?.message || e)) }
    }
  }

  // 把浏览器剪贴板的当前内容交给远端。读取只在用户手势内可用，
  // 所以由按下粘贴键时触发，而不是轮询。
  const pushLocalClipboard = async (trigger: string, quiet = false) => {
    const s = session
    if (!s) return
    let text = ''
    let png: Uint8Array | null = null
    try {
      for (const item of await navigator.clipboard.read()) {
        if (!text && item.types.includes('text/plain')) {
          text = await (await item.getType('text/plain')).text()
        }
        if (!png && item.types.includes('image/png')) {
          const blob = await item.getType('image/png')
          if (blob.size > MAX_CLIPBOARD_IMAGE) {
            log('warn', '本地剪贴板图片过大，已跳过（' + Math.round(blob.size / 1024) + ' KiB）')
          } else {
            png = new Uint8Array(await blob.arrayBuffer())
          }
        }
      }
    } catch {
      // 浏览器不支持 read() 或权限被拒时退回只读文本。
      try { text = await navigator.clipboard.readText() }
      catch (e: any) {
        // 远端按下粘贴时浏览器没有用户手势，读取被拒是常态，不打扰用户；
        // 本地按 Ctrl+V 时才是真的权限问题，需要提示。
        if (!quiet) log('warn', '读取本地剪贴板失败（' + trigger + '）：' + (e?.message || e))
        return
      }
    }
    if (!text && !png) return
    try {
      const data = new ClipboardData()
      if (text) data.addText('text/plain', text)
      if (png) data.addBinary('image/png', png)
      await s.onClipboardPaste(data)
    } catch (e: any) {
      log('warn', '同步剪贴板到远端失败：' + (e?.message || e))
    }
  }

  if (opts.allowClipboard !== false) {
    // 远端复制后把内容写进浏览器剪贴板（文本与图片）。
    builder.remoteClipboardChangedCallback((data: ClipboardData) => {
      void writeRemoteClipboard(data)
    })
    // 远端按下粘贴时会要求本地内容；拿不到就保持远端原有内容。
    builder.forceClipboardUpdateCallback(() => {
      void pushLocalClipboard('远端请求', true)
    })
  }

  // 连接阶段失败时把原因摊平再抛出：调用方只负责展示，不再判断类型。
  let opened: Session
  try {
    opened = await builder.connect()
  } catch (e) {
    throw new Error(describeError(e))
  }
  session = opened
  const active: Session = opened
  // 记录本次实际证书指纹，供下次连接比对。
  try {
    const fp = active.certificateFingerprint()
    if (fp && fp !== expectedFp) localStorage.setItem(fpKey, fp)
  } catch { /* 旧版本没有该方法时忽略 */ }
  log('info', 'NLA 认证通过，远程会话已建立')

  let stopped = false
  let finish!: (reason: string) => void
  const terminated = new Promise<string>((resolve) => { finish = resolve })

  const runPromise: Promise<SessionTerminationInfo> = active.run()
  runPromise.then((info) => {
    if (!stopped) finish(info.reason() || 'remote-closed')
  }).catch((e: unknown) => {
    if (!stopped) finish(describeError(e) || 'session-error')
  })

  const send = (fn: (t: InputTransaction) => void) => {
    if (stopped) return
    const t = new InputTransaction()
    fn(t)
    try { active.applyInputs(t) } catch { /* 会话可能已结束 */ }
  }

  // 输入法提交的文本走 Unicode 通道：扫描码只能表达物理按键，
  // 拼音、日文、手写都不在键位表里。
  const sendText = (text: string) => {
    const chars = Array.from(text)
    if (!chars.length) return
    send((t) => {
      for (const ch of chars) {
        t.addEvent(DeviceEvent.unicodePressed(ch))
        t.addEvent(DeviceEvent.unicodeReleased(ch))
      }
    })
  }

  const canvas = opts.canvas
  // 浏览器只在可编辑元素上启动输入法，canvas 永远收不到 composition 事件。
  // 叠一个 1×1 的透明 textarea 承担键盘与输入法：鼠标仍落在 canvas 上，
  // 点击画布时把焦点交给它。pointer-events:none 让它不拦截鼠标，
  // 但 focus() 不受该属性影响。
  const parent = canvas.parentElement
  if (parent && getComputedStyle(parent).position === 'static') parent.style.position = 'relative'
  const sink = document.createElement('textarea')
  sink.setAttribute('aria-hidden', 'true')
  sink.setAttribute('autocomplete', 'off')
  sink.setAttribute('autocapitalize', 'off')
  sink.setAttribute('autocorrect', 'off')
  sink.spellcheck = false
  sink.tabIndex = -1
  sink.style.cssText = 'position:absolute;left:0;top:0;width:1px;height:1px;padding:0;border:0;' +
    'margin:0;opacity:0;pointer-events:none;resize:none;overflow:hidden;'
  parent?.appendChild(sink)
  // 焦点归 textarea，canvas 不再参与 Tab 序列。
  canvas.tabIndex = -1
  const focus = () => { try { sink.focus({ preventScroll: true }) } catch { /* ignore */ } }

  // 远端桌面尺寸随 resize 变化，鼠标映射必须用当前值而不是连接时的快照。
  const viewport = { width: opts.width, height: opts.height }
  const onMouseMove = (e: MouseEvent) => {
    const rect = canvas.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return
    const x = Math.max(0, Math.min(viewport.width - 1, Math.round((e.clientX - rect.left) * viewport.width / rect.width)))
    const y = Math.max(0, Math.min(viewport.height - 1, Math.round((e.clientY - rect.top) * viewport.height / rect.height)))
    send((t) => t.addEvent(DeviceEvent.mouseMove(x, y)))
  }
  const onMouseDown = (e: MouseEvent) => {
    // 阻止浏览器把焦点交给 canvas，否则键盘事件不会再进 textarea。
    e.preventDefault()
    // 输入法候选框出现在 caret 处，把 1×1 的 textarea 挪到点击位置，
    // 候选框才会跟着用户的视线而不是钉在左上角。
    const rect = canvas.getBoundingClientRect()
    sink.style.left = Math.max(0, Math.min(rect.width - 1, e.clientX - rect.left)) + 'px'
    sink.style.top = Math.max(0, Math.min(rect.height - 1, e.clientY - rect.top)) + 'px'
    focus()
    send((t) => t.addEvent(DeviceEvent.mouseButtonPressed(e.button)))
  }
  const onMouseUp = (e: MouseEvent) => { send((t) => t.addEvent(DeviceEvent.mouseButtonReleased(e.button))) }
  const onWheel = (e: WheelEvent) => {
    e.preventDefault()
    const vertical = Math.abs(e.deltaY) >= Math.abs(e.deltaX)
    const raw = vertical ? e.deltaY : e.deltaX
    if (!raw) return
    // RDP 的滚轮量是有符号的：负值向用户方向滚动，正值远离用户。
    // 浏览器 deltaY 正值为向下滚，因此取反；绝对值会丢失方向。
    let amount: number
    let unit: RotationUnit
    if (e.deltaMode === 1) {
      amount = Math.round(raw)
      unit = RotationUnit.Line
    } else if (e.deltaMode === 2) {
      amount = Math.round(raw)
      unit = RotationUnit.Page
    } else {
      // 像素模式：浏览器一格约 100px，直接按像素发送（mstsc 一格为 120 像素）。
      amount = Math.round(raw)
      unit = RotationUnit.Pixel
    }
    // 协议字段是 16 位有符号整数，超范围会被截断成反向滚动，这里先夹紧。
    amount = Math.max(-32767, Math.min(32767, Math.round(-amount)))
    if (amount === 0) return
    send((t) => t.addEvent(DeviceEvent.wheelRotations(vertical, amount, unit)))
  }
  // 输入法组合期间的按键属于拼音编码，不能当扫描码发给远端，
  // 否则“nihao”会先打出一串字母再补上“你好”。
  let composing = false
  const isIme = (e: KeyboardEvent) => composing || e.isComposing || e.keyCode === 229

  // 本地粘贴：先把内容交给远端，再发 Ctrl+V。顺序反了远端会读到上一次的剪贴板。
  const forwardPaste = async () => {
    await pushLocalClipboard('用户粘贴')
    send((t) => {
      t.addEvent(DeviceEvent.keyPressed(0x1d))
      t.addEvent(DeviceEvent.keyPressed(0x2f))
      t.addEvent(DeviceEvent.keyReleased(0x2f))
      t.addEvent(DeviceEvent.keyReleased(0x1d))
    })
    sink.value = ''
  }

  const onKeyDown = (e: KeyboardEvent) => {
    if (isIme(e)) return
    if ((e.ctrlKey || e.metaKey) && !e.altKey && e.code === 'KeyV') {
      e.preventDefault()
      void forwardPaste()
      return
    }
    const code = scancodeOf(e)
    if (code !== null) { send((t) => t.addEvent(DeviceEvent.keyPressed(code))); e.preventDefault() }
  }
  const onKeyUp = (e: KeyboardEvent) => {
    if (isIme(e)) return
    const code = scancodeOf(e)
    if (code !== null) { send((t) => t.addEvent(DeviceEvent.keyReleased(code))); e.preventDefault() }
  }
  const onCompositionStart = () => { composing = true }
  const onCompositionEnd = (e: CompositionEvent) => {
    composing = false
    const text = e.data || ''
    sink.value = ''
    if (text) sendText(text)
  }
  // 兜底：个别输入法不派发 compositionend，只给 input。
  const onInput = () => {
    if (composing) return
    const text = sink.value
    if (!text) return
    sink.value = ''
    sendText(text)
  }
  const onContextMenu = (e: Event) => e.preventDefault()
  // 焦点离开时释放所有按键，否则 Alt+Tab 切走时的修饰键会卡在远端。
  const onBlur = () => { try { active.releaseAllInputs() } catch { /* ignore */ } }

  canvas.addEventListener('mousemove', onMouseMove)
  canvas.addEventListener('mousedown', onMouseDown)
  canvas.addEventListener('mouseup', onMouseUp)
  canvas.addEventListener('wheel', onWheel, { passive: false })
  canvas.addEventListener('contextmenu', onContextMenu)
  sink.addEventListener('keydown', onKeyDown)
  sink.addEventListener('keyup', onKeyUp)
  sink.addEventListener('compositionstart', onCompositionStart)
  sink.addEventListener('compositionend', onCompositionEnd)
  sink.addEventListener('input', onInput)
  sink.addEventListener('blur', onBlur)

  const detach = () => {
    canvas.removeEventListener('mousemove', onMouseMove)
    canvas.removeEventListener('mousedown', onMouseDown)
    canvas.removeEventListener('mouseup', onMouseUp)
    canvas.removeEventListener('wheel', onWheel)
    canvas.removeEventListener('contextmenu', onContextMenu)
    sink.removeEventListener('keydown', onKeyDown)
    sink.removeEventListener('keyup', onKeyUp)
    sink.removeEventListener('compositionstart', onCompositionStart)
    sink.removeEventListener('compositionend', onCompositionEnd)
    sink.removeEventListener('input', onInput)
    sink.removeEventListener('blur', onBlur)
    sink.remove()
  }
  terminated.finally(detach)

  return {
    shutdown: () => {
      if (stopped) return
      stopped = true
      try { active.shutdown() } catch { /* ignore */ }
      finish('user-closed')
    },
    focus,
    resize: (w: number, h: number) => {
      if (w <= 0 || h <= 0) return
      viewport.width = w
      viewport.height = h
      try { active.resize(w, h) } catch { /* ignore */ }
    },
    sendCtrlAltDel: () => {
      send((t) => {
        t.addEvent(DeviceEvent.keyPressed(0x1d))   // Ctrl
        t.addEvent(DeviceEvent.keyPressed(0x38))   // Alt
        t.addEvent(DeviceEvent.keyPressed(0xe053)) // Delete（扩展键）
        t.addEvent(DeviceEvent.keyReleased(0xe053))
        t.addEvent(DeviceEvent.keyReleased(0x38))
        t.addEvent(DeviceEvent.keyReleased(0x1d))
      })
    },
    terminated,
  }
}
