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
  setColorDepth,
} from './wasm/pkg/ironrdp_web.js'
import type { Session, SessionTerminationInfo } from './wasm/pkg/ironrdp_web.js'

let wasmReady: Promise<unknown> | null = null

export function ensureWasm(): Promise<unknown> {
  if (!wasmReady) {
    wasmReady = init().catch((e: unknown) => {
      // 失败时清掉缓存：换浏览器或恢复网络后不必整页刷新。
      wasmReady = null
      throw new Error(
        '加载 RDP 协议组件失败。若浏览器较旧（iOS 16.4 / Chrome 91 / Firefox 89 之前），'
        + '可能不支持 WebAssembly SIMD；否则请确认本站静态资源可以正常下载。'
        + '原因：' + describeError(e),
      )
    })
  }
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
  /**
   * 触摸设备的初始输入模式。pointer＝触控板式（默认），touch＝点哪打哪。
   * 桌面浏览器恒为 touch，鼠标事件不受影响。
   */
  inputMode?: InputMode
  onLog?: (level: string, message: string) => void
  /** 软键盘被唤出或收起时通知界面，用于同步按钮状态。 */
  onKeyboard?: (open: boolean) => void
}

export type InputMode = 'touch' | 'pointer'

export interface RdpSession {
  shutdown: () => void
  resize: (width: number, height: number) => void
  sendCtrlAltDel: () => void
  /** 把键盘焦点交还远程桌面（点击工具栏后需要重新聚焦）。触摸设备上不会弹键盘。 */
  focus: () => void
  /** 在触摸设备上切换输入模式；桌面浏览器调用无副作用。 */
  setInputMode: (mode: InputMode) => void
  /** 唤出软键盘。必须由用户手势触发，否则浏览器会拒绝聚焦。 */
  showKeyboard: () => void
  hideKeyboard: () => void
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

// 远端在 NLA 阶段拒绝登录。与密码错误的 STATUS_WRONG_PASSWORD(0xc000006a)
// 不是一回事：这个码多半是远端残留会话、账户策略或主机刚唤醒，重试有意义。
export function isLogonFailure(e: unknown): boolean {
  return /LogonFailure|STATUS_LOGON_FAILURE|0xc000006d/i.test(describeError(e))
}

// 远端桌面尺寸不能直接用浏览器 CSS 像素：手机 DPR 高、CSS 尺寸小（例如 390×780），
// 这个值会被 Windows 收缩到最小分辨率，画面比例也对不上容器。这里按容器宽高比换算，
// 短边不低于 640，长边不超过 maxLong，8 像素对齐（RDP 桌面尺寸的常见约束）。
export function pickDesktopSize(
  width: number,
  height: number,
  maxLong = 1920,
): { width: number; height: number } {
  const MIN_SHORT = 640
  let w = Math.max(1, Math.round(width))
  let h = Math.max(1, Math.round(height))
  const short = Math.min(w, h)
  if (short < MIN_SHORT) {
    const k = MIN_SHORT / short
    w *= k
    h *= k
  }
  const long = Math.max(w, h)
  if (long > maxLong) {
    const k = maxLong / long
    w *= k
    h *= k
  }
  const align = (v: number) => Math.max(8, Math.round(v / 8) * 8)
  return { width: align(w), height: align(h) }
}

// 打印服务端版本，用于区分「升级没生效」与「协议问题」。失败不影响连接。
async function reportServerVersion(log: (level: string, message: string) => void): Promise<void> {
  try {
    const resp = await fetch('/api/health', { cache: 'no-store' })
    if (resp.ok) {
      const info = await resp.json()
      if (info && info.version) log('info', '服务端版本 ' + info.version)
    }
  } catch { /* 健康检查失败不影响连接 */ }
}

// 指针模式下的默认箭头。服务器只在 CursorStyle::Default 时告诉客户端「用系统
// 默认光标」，不带位图；触摸屏没有系统光标可借，所以自绘一个。
const DEFAULT_CURSOR_SVG = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="19" viewBox="0 0 12 19">'
  + '<path d="M1 1v15.2l3.7-3.6 2.4 4.8 2.3-1.1-2.3-4.7h5.4z"'
  + ' fill="#fff" stroke="#000" stroke-width="1" stroke-linejoin="round"/></svg>',
)

// 建立 RDP 会话并绑定画布输入。该函数返回后不再持有凭据。
export async function connectRdp(opts: RdpOptions): Promise<RdpSession> {
  const log = opts.onLog || (() => {})

  // 版本自证只用于日志，不能挡在 WASM 下载前面：两者并行发起，等 WASM
  // 就绪后再补这一行日志。
  const healthDone = reportServerVersion(log)

  // 临时 A/B 开关：主机列表页带 ?depth=32 打开一次，选择会记在 sessionStorage
  // 里供后续连接读取。服务器只在 32bpp 会话里真正下发 RemoteFX 帧，16bpp 下
  // 能力集里宣告的 RemoteFX 不会生效。默认 16，保持既有行为直到实测确认。
  let depth = '16'
  try { depth = sessionStorage.getItem('deskgw.depth') || '16' } catch { /* 隐私模式 */ }
  const wideColor = depth === '32'

  await ensureWasm()
  // 必须在 wasm 初始化之后调用：这些导出函数直接操作实例内存。
  setColorDepth(wideColor ? 32 : 16)
  if (wideColor) log('info', '色深 32 位（RemoteFX 实验），文字边缘轻微变软表示编码器已生效')
  await healthDone
  log('info', '正在初始化 RDP 协议栈')

  // 剪贴板回调在 connect 时才被读取，先声明会话占位供回调引用。
  let session: Session | null = null

  // ---- 画布环境 ----
  const canvas = opts.canvas
  const parent = canvas.parentElement
  if (parent && getComputedStyle(parent).position === 'static') parent.style.position = 'relative'

  // 主输入是否为触摸。触屏笔记本接了鼠标时这里是 false，按桌面处理：
  // 点画布即接管键盘，不会把软键盘顶出来。
  const touchDevice = window.matchMedia('(pointer: coarse)').matches
  // 只要设备支持触摸就提供指针模式与键盘按钮（触屏笔记本也能用）。
  const hasTouch = touchDevice || navigator.maxTouchPoints > 0
  // 远端桌面尺寸随 resize 变化，输入映射必须用当前值而不是连接时的快照。
  const viewport = { width: opts.width, height: opts.height }

  // 触摸设备默认指针模式：手指点哪打哪无法命中 1–2 像素的窗口边框，
  // 而指针模式还能靠拖动微调。
  let inputMode: InputMode = opts.inputMode === 'touch'
    ? 'touch'
    : opts.inputMode === 'pointer' ? 'pointer' : (touchDevice ? 'pointer' : 'touch')

  // 指针模式下由本地维护远端指针坐标，与触摸位置无关。
  const pointerPos = { x: Math.round(viewport.width / 2), y: Math.round(viewport.height / 2) }

  // 触摸屏没有系统光标，指针模式必须自绘一个，否则用户看不见指到了哪里。
  const cursorEl = document.createElement('img')
  cursorEl.alt = ''
  cursorEl.draggable = false
  cursorEl.style.cssText = 'position:absolute;left:0;top:0;pointer-events:none;z-index:1;'
    + 'display:none;will-change:transform;'
  parent?.appendChild(cursorEl)

  // 最近一次服务器下发的光标样式。切换模式或容器尺寸变化后要重放一次。
  const lastCursor = { kind: 'default' as 'default' | 'hidden' | 'url', data: '', hx: 0, hy: 0 }
  let cursorNatW = 0
  let cursorNatH = 0

  // 远端光标热点按当前 CSS 缩放比换算。cursor 的坐标单位是 CSS 像素，而热点
  // 来自远端桌面像素：画面被缩小时不换算，箭头尖端会与实际点击点错开几像素，
  // 拖窗口边缘这种 1–2 像素的目标就点不中。
  const cursorScale = () => {
    const rect = canvas.getBoundingClientRect()
    return rect.width > 0 && canvas.width > 0 ? rect.width / canvas.width : 1
  }

  const drawCursorOverlay = () => {
    if (inputMode !== 'pointer' || !hasTouch || lastCursor.kind === 'hidden') {
      cursorEl.style.display = 'none'
      return
    }
    const rect = canvas.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) {
      cursorEl.style.display = 'none'
      return
    }
    const prect = parent ? parent.getBoundingClientRect() : null
    // 指针坐标是远端像素，位移与尺寸都按同一比例换算成 CSS 像素。
    // 1920 的桌面缩到 390 宽时比例只有 0.2，32 像素的箭头会缩成 6 像素，
    // 这里兜一个 14 像素的最小可视尺寸（热点按同一比例换算，不偏）。
    const k = cursorScale()
    const natMax = Math.max(cursorNatW, cursorNatH)
    const scale = natMax > 0 && natMax * k < 14 ? 14 / natMax : k
    cursorEl.style.display = 'block'
    cursorEl.style.width = Math.max(1, Math.round(cursorNatW * scale)) + 'px'
    cursorEl.style.height = Math.max(1, Math.round(cursorNatH * scale)) + 'px'
    const left = rect.left - (prect ? prect.left : 0) + pointerPos.x * k - lastCursor.hx * scale
    const top = rect.top - (prect ? prect.top : 0) + pointerPos.y * k - lastCursor.hy * scale
    cursorEl.style.transform = 'translate3d(' + Math.round(left) + 'px,' + Math.round(top) + 'px,0)'
  }

  const applyCanvasCursor = () => {
    if (inputMode === 'pointer' && hasTouch) {
      canvas.style.cursor = 'none'
      drawCursorOverlay()
      return
    }
    cursorEl.style.display = 'none'
    if (lastCursor.kind === 'hidden') {
      canvas.style.cursor = 'none'
      return
    }
    if (lastCursor.kind === 'url' && lastCursor.data) {
      const k = cursorScale()
      const hx = Math.round(lastCursor.hx * k)
      const hy = Math.round(lastCursor.hy * k)
      canvas.style.cursor = 'url("' + lastCursor.data + '") ' + hx + ' ' + hy + ', default'
      return
    }
    canvas.style.cursor = 'default'
  }

  const setCursorImage = (src: string, hx: number, hy: number) => {
    lastCursor.data = src
    lastCursor.hx = hx
    lastCursor.hy = hy
    if (!src || cursorEl.getAttribute('src') === src) return
    // 位图尺寸要等图片解码才知道；解码前先按当前比例摆一次，避免闪到左上角。
    cursorNatW = 0
    cursorNatH = 0
    cursorEl.onload = () => {
      cursorNatW = cursorEl.naturalWidth || 0
      cursorNatH = cursorEl.naturalHeight || 0
      drawCursorOverlay()
    }
    cursorEl.src = src
  }

  // 先按默认箭头摆一份，服务端下发真实光标前的几帧也有可见指针。
  setCursorImage(DEFAULT_CURSOR_SVG, 0, 0)
  applyCanvasCursor()

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
  // 开启 Display Control 虚拟通道：没有它，会话中的 resize 请求会被服务端忽略，
  // 窗口尺寸变化后远端桌面仍然停在连接时的分辨率。
  builder.extension(new Extension('display_control', true))

  // 远端下发光标样式时更新光标。data 是 data:image/png;base64,... 的完整 URI，
  // 热点按图片原始像素给出。桌面模式直接交给 CSS，指针模式画在覆盖层上。
  builder.setCursorStyleCallbackContext(opts.canvas)
  builder.setCursorStyleCallback((kind: string, data: unknown, hotspotX: number, hotspotY: number) => {
    if (kind === 'hidden') {
      lastCursor.kind = 'hidden'
    } else if (kind === 'url' && typeof data === 'string' && data) {
      lastCursor.kind = 'url'
      setCursorImage(data, hotspotX | 0, hotspotY | 0)
    } else {
      lastCursor.kind = 'default'
      setCursorImage(DEFAULT_CURSOR_SVG, 0, 0)
    }
    applyCanvasCursor()
  })

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

  // 远端剪贴板的最新文本。远端复制后我们会把它写回本地浏览器剪贴板，此时两边
  // 内容一致；用户在远端按粘贴时若再把这份内容推回去，会把远端剪贴板里的其它
  // 格式（HTML、图片）一起清掉，粘贴结果就从「刚复制的链接」变成浏览器里的旧
  // 内容。所以推送前要比对，相同就跳过。
  let remoteText = ''

  // writeText 要求文档有焦点，失焦时会被拒。用隐藏 textarea + execCommand 兜底，
  // 保证本地剪贴板真的被远端内容覆盖 —— 否则下一次推送会把旧内容盖到远端去。
  const copyViaTextarea = (value: string) => {
    try {
      const ta = document.createElement('textarea')
      ta.value = value
      ta.setAttribute('readonly', '')
      ta.style.cssText = 'position:fixed;top:-1000px;left:-1000px;opacity:0'
      document.body.appendChild(ta)
      ta.select()
      const ok = document.execCommand('copy')
      ta.remove()
      return ok
    } catch {
      return false
    }
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
      remoteText = text
      try { await navigator.clipboard.writeText(text) }
      catch (e: any) {
        if (!copyViaTextarea(text)) log('warn', '写入本地剪贴板失败：' + (e?.message || e))
      }
    }
  }

  // 把浏览器剪贴板的当前内容交给远端。读取只在用户手势内可用，
  // 所以由按下粘贴键时触发，而不是轮询。
  const pushLocalClipboard = async (trigger: string, quiet = false, force = false) => {
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
    // 本地内容与远端最新文本一致时不必再推：推上去只会把远端剪贴板里的其它
    // 格式清掉，反而破坏用户刚在远端复制的内容。带图片时不比对，图片无从比较。
    if (!force && !png && text === remoteText) return
    try {
      const data = new ClipboardData()
      if (text) data.addText('text/plain', text)
      if (png) data.addBinary('image/png', png)
      await s.onClipboardPaste(data)
      if (!png) remoteText = text
    } catch (e: any) {
      log('warn', '同步剪贴板到远端失败：' + (e?.message || e))
    }
  }

  // 页面内复制时系统剪贴板还没写入，直接拿 copy 事件里的文本推给远端。
  const pushTextToRemote = async (text: string) => {
    const s = session
    if (!s || !text) return
    try {
      const data = new ClipboardData()
      data.addText('text/plain', text)
      await s.onClipboardPaste(data)
      remoteText = text
    } catch (e: any) {
      log('warn', '同步剪贴板到远端失败：' + (e?.message || e))
    }
  }

  // 在页面里复制（主机名、路径、日志）就地同步，不必等远端按粘贴时再来要。
  const onCopy = (e: ClipboardEvent) => {
    const text = e.clipboardData?.getData('text/plain') || window.getSelection()?.toString() || ''
    if (!text) return
    void pushTextToRemote(text)
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
    // 重试会重新走一遍 connectRdp，先把自绘光标摘掉，免得叠出第二层。
    cursorEl.remove()
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

  // 浏览器只在可编辑元素上启动输入法，canvas 永远收不到 composition 事件。
  // 叠一个 1×1 的透明 textarea 承担键盘与输入法：鼠标仍落在 canvas 上。
  // pointer-events:none 让它不拦截鼠标，但 focus() 不受该属性影响。
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

  // 软键盘只能由显式操作唤出。之前每次点画布都 focus 一次 textarea，手机上
  // 表现为「点哪都弹出键盘」，键盘还会挤压可视高度、触发远端改分辨率。
  const focusSink = () => { try { sink.focus({ preventScroll: true }) } catch { /* ignore */ } }
  const focus = () => { if (!touchDevice) focusSink() }
  const notifyKeyboard = (open?: boolean) => {
    const value = open === undefined ? document.activeElement === sink : open
    try { opts.onKeyboard?.(value) } catch { /* 界面回调抛错不影响输入 */ }
  }
  // 输入法候选框出现在 caret 处，把 textarea 挪到手指位置，候选框才跟着视线。
  const positionSink = (clientX: number, clientY: number) => {
    const rect = canvas.getBoundingClientRect()
    sink.style.left = Math.max(0, Math.min(rect.width - 1, clientX - rect.left)) + 'px'
    sink.style.top = Math.max(0, Math.min(rect.height - 1, clientY - rect.top)) + 'px'
  }

  const pointAt = (clientX: number, clientY: number) => {
    const rect = canvas.getBoundingClientRect()
    if (rect.width <= 0 || rect.height <= 0) return null
    const x = Math.max(0, Math.min(viewport.width - 1, Math.round((clientX - rect.left) * viewport.width / rect.width)))
    const y = Math.max(0, Math.min(viewport.height - 1, Math.round((clientY - rect.top) * viewport.height / rect.height)))
    return { x, y }
  }

  // 指针移动按帧合并：一次移动风暴里只有最后一个位置真正有意义。
  // 原来每条事件都要重排一次布局、新建 InputTransaction 再跨一次 wasm 边界，
  // 高刷鼠标下这些调用会和画面渲染抢同一个主线程。
  let pendingMove: { clientX: number; clientY: number } | null = null
  let moveRaf = 0
  const flushMove = () => {
    moveRaf = 0
    const pending = pendingMove
    pendingMove = null
    if (!pending) return
    const p = pointAt(pending.clientX, pending.clientY)
    if (!p) return
    send((t) => t.addEvent(DeviceEvent.mouseMove(p.x, p.y)))
  }
  const queueMove = (clientX: number, clientY: number) => {
    pendingMove = { clientX, clientY }
    if (!moveRaf) moveRaf = requestAnimationFrame(flushMove)
  }
  // 按键前先把待发的移动落地，否则远端会先收到点击、再收到旧坐标。
  const flushMoveNow = () => {
    if (moveRaf) { cancelAnimationFrame(moveRaf); moveRaf = 0 }
    flushMove()
  }

  // 按下后由 window 接管移动与抬起：拖窗口边缘时指针几十毫秒内就会移出画布，
  // 只监听 canvas 会丢掉后续事件，远端表现为「拖一下就断」，按钮状态还会卡住。
  let draggingButton: number | null = null

  const onMouseMove = (e: MouseEvent) => {
    if (draggingButton !== null) return
    queueMove(e.clientX, e.clientY)
  }
  const onWindowMove = (e: MouseEvent) => {
    if (draggingButton === null) return
    queueMove(e.clientX, e.clientY)
  }
  const onWindowUp = (e: MouseEvent) => {
    if (draggingButton === null) return
    draggingButton = null
    flushMoveNow()
    const p = pointAt(e.clientX, e.clientY)
    send((t) => {
      if (p) t.addEvent(DeviceEvent.mouseMove(p.x, p.y))
      t.addEvent(DeviceEvent.mouseButtonReleased(e.button))
    })
  }
  // 指针移出浏览器窗口后收不到 mouseup，窗口失焦时补一次释放，
  // 避免远端一直认为左键是按下的。
  const onWindowBlur = () => {
    if (draggingButton === null) return
    const button = draggingButton
    draggingButton = null
    send((t) => t.addEvent(DeviceEvent.mouseButtonReleased(button)))
  }

  const onMouseDown = (e: MouseEvent) => {
    // 阻止浏览器把焦点交给 canvas，否则键盘事件不会再进 textarea。
    e.preventDefault()
    flushMoveNow()
    positionSink(e.clientX, e.clientY)
    // 触摸设备不自动聚焦：那是软键盘反复弹出的根因，键盘改由工具栏按钮唤出。
    focus()
    // 按下点必须单独发一次：用户可能先停住再按下，那时挂起的移动早被 rAF
    // 消费掉了，只发按键会让远端在旧位置按下。
    const p = pointAt(e.clientX, e.clientY)
    send((t) => {
      if (p) t.addEvent(DeviceEvent.mouseMove(p.x, p.y))
      t.addEvent(DeviceEvent.mouseButtonPressed(e.button))
    })
    draggingButton = e.button
  }

  // ---- 指针模式：把触摸屏当触控板 ----
  // 触摸模式是「点哪打哪」，命中精度等于画面缩放比乘以一个像素；1920 的桌面缩到
  // 390 宽时连窗口边框都不到一个屏幕像素。指针模式把手指当相对位移输入，
  // 指针位置由本地维护，可以慢慢挪到目标上再按下。
  const POINTER_GAIN = 1.5      // 手指移动 1 屏幕像素带动指针移动多少屏幕像素
  const TAP_SLOP = 10           // 超过这个位移（CSS 像素）就不再算点击
  const LONG_PRESS_MS = 520     // 单击后按住多久算右键
  const DOUBLE_TAP_MS = 320     // 两次按下间隔超过这个值就不算双击
  // 双击后的第二下必须晚于系统双击窗口按下，否则远端会把它当成「第二次单击」：
  // 落在标题栏上就是直接最大化，永远进不了拖拽。Windows 默认双击间隔 500ms。
  const DOUBLE_CLICK_WINDOW = 560

  interface Gesture {
    id: number
    startX: number
    startY: number
    lastX: number
    lastY: number
    downAt: number
    moved: boolean
    holding: boolean
    second: boolean
    rightFired: boolean
    longTimer: number
    holdTimer: number
  }

  // 同时按下的触摸点，只有两个及以上才用于滚动。
  const touches = new Map<number, { x: number; y: number }>()
  let gesture: Gesture | null = null
  let lastTapAt = 0     // 上一次点击抬起（或双击中的第一次按下）的时刻
  let lastDownAt = 0    // 上一次完整点击按下的时刻，用于把拖拽按下推到双击窗口之外
  let scrolling = false
  let scrollAccum = 0
  let scrollLastY = 0

  const buzz = (ms: number) => { try { navigator.vibrate?.(ms) } catch { /* iOS 不支持 */ } }

  // 指针位置按帧提交：一次拖动会上百个 pointermove，只有最后一个位置有意义。
  let pointerRaf = 0
  let pointerDirty = false
  const flushPointer = () => {
    pointerRaf = 0
    if (!pointerDirty) return
    pointerDirty = false
    drawCursorOverlay()
    send((t) => t.addEvent(DeviceEvent.mouseMove(
      Math.round(pointerPos.x),
      Math.round(pointerPos.y),
    )))
  }
  const commitPointer = () => {
    pointerDirty = true
    if (!pointerRaf) pointerRaf = requestAnimationFrame(flushPointer)
  }
  const commitPointerNow = () => {
    if (pointerRaf) { cancelAnimationFrame(pointerRaf); pointerRaf = 0 }
    flushPointer()
  }

  // 手指位移换算成远端像素：屏幕上大致 1:1，乘增益减少来回划动。
  const pointerGain = () => {
    const rect = canvas.getBoundingClientRect()
    return rect.width > 0 ? (viewport.width / rect.width) * POINTER_GAIN : POINTER_GAIN
  }

  const movePointerBy = (dx: number, dy: number) => {
    // 保留小数：慢速拖动时每次位移可能不足一个远端像素，取整会把它们全部丢掉。
    pointerPos.x = Math.max(0, Math.min(viewport.width - 1, pointerPos.x + dx))
    pointerPos.y = Math.max(0, Math.min(viewport.height - 1, pointerPos.y + dy))
    commitPointer()
  }

  const clickAtPointer = (button: number) => {
    commitPointerNow()
    send((t) => {
      t.addEvent(DeviceEvent.mouseButtonPressed(button))
      t.addEvent(DeviceEvent.mouseButtonReleased(button))
    })
  }

  const clearGestureTimers = (g: Gesture) => {
    if (g.longTimer) window.clearTimeout(g.longTimer)
    if (g.holdTimer) window.clearTimeout(g.holdTimer)
    g.longTimer = 0
    g.holdTimer = 0
  }

  const startHold = (g: Gesture) => {
    if (g.holding) return
    g.holding = true
    commitPointerNow()
    send((t) => t.addEvent(DeviceEvent.mouseButtonPressed(0)))
    buzz(8)
  }

  const releaseHold = (g: Gesture) => {
    if (!g.holding) return
    g.holding = false
    commitPointerNow()
    send((t) => t.addEvent(DeviceEvent.mouseButtonReleased(0)))
  }

  // 第二根手指落下即进入滚动，同时取消单指手势，避免顺手点出一次左键。
  const beginScroll = () => {
    if (gesture) {
      clearGestureTimers(gesture)
      releaseHold(gesture)
      gesture = null
    }
    const pts = [...touches.values()]
    if (pts.length < 2) return
    scrolling = true
    scrollAccum = 0
    scrollLastY = (pts[0].y + pts[1].y) / 2
  }

  const updateScroll = () => {
    const pts = [...touches.values()]
    if (pts.length < 2) return
    const y = (pts[0].y + pts[1].y) / 2
    scrollAccum += y - scrollLastY
    scrollLastY = y
    // 小于 6 像素先攒着，避免每帧都发一条滚轮事件。
    if (Math.abs(scrollAccum) < 6) return
    // 像素单位下 120 等于一格滚轮，这里 60 CSS 像素滚一格，接近触屏手感。
    const amount = Math.max(-3000, Math.min(3000, Math.round(-scrollAccum * 2)))
    scrollAccum = 0
    if (!amount) return
    send((t) => t.addEvent(DeviceEvent.wheelRotations(true, amount, RotationUnit.Pixel)))
  }

  const onPointerDown = (e: PointerEvent) => {
    if (e.pointerType === 'mouse') return
    e.preventDefault()
    positionSink(e.clientX, e.clientY)
    try { canvas.setPointerCapture(e.pointerId) } catch { /* ignore */ }

    if (inputMode === 'pointer') {
      touches.set(e.pointerId, { x: e.clientX, y: e.clientY })
      if (touches.size >= 2) { beginScroll(); return }
      const now = Date.now()
      const second = now - lastTapAt < DOUBLE_TAP_MS
      const g: Gesture = {
        id: e.pointerId,
        startX: e.clientX, startY: e.clientY,
        lastX: e.clientX, lastY: e.clientY,
        downAt: now,
        moved: false, holding: false, second, rightFired: false,
        longTimer: 0, holdTimer: 0,
      }
      gesture = g
      if (second) {
        // 双击后按住 = 左键拖拽，但按下时刻要推迟到第一次按下之后
        // DOUBLE_CLICK_WINDOW：提前按下会被远端合并成一次双击。
        // 期间手指可以照常挪动指针，按下时位置已经变了，更不会被算作双击。
        const delay = Math.max(90, DOUBLE_CLICK_WINDOW - (now - lastDownAt))
        g.holdTimer = window.setTimeout(() => {
          if (gesture === g) startHold(g)
        }, delay)
      } else {
        lastDownAt = now
        // 单击后按住：右键。
        g.longTimer = window.setTimeout(() => {
          if (gesture !== g || g.moved) return
          g.rightFired = true
          clickAtPointer(2)
          buzz(14)
        }, LONG_PRESS_MS)
      }
      return
    }

    // 触摸模式：手指位置即远端指针位置，按下就是左键按下，拖动即拖拽。
    flushMoveNow()
    const p = pointAt(e.clientX, e.clientY)
    if (!p) return
    send((t) => {
      t.addEvent(DeviceEvent.mouseMove(p.x, p.y))
      t.addEvent(DeviceEvent.mouseButtonPressed(0))
    })
  }

  const onPointerMove = (e: PointerEvent) => {
    if (e.pointerType === 'mouse') return
    if (inputMode !== 'pointer') {
      if (!e.buttons) return
      queueMove(e.clientX, e.clientY)
      return
    }
    const pt = touches.get(e.pointerId)
    if (!pt) return
    pt.x = e.clientX
    pt.y = e.clientY
    if (scrolling) { updateScroll(); return }
    const g = gesture
    if (!g || g.id !== e.pointerId) return
    const dx = e.clientX - g.lastX
    const dy = e.clientY - g.lastY
    g.lastX = e.clientX
    g.lastY = e.clientY
    if (!g.moved) {
      if (Math.hypot(e.clientX - g.startX, e.clientY - g.startY) < TAP_SLOP) return
      g.moved = true
      // 移动了就不再是单击，右键计时作废。双击后的第二下保留按住计时器：
      // 按下仍要等过双击窗口，但指针从这一刻起就跟手。
      if (g.longTimer) { window.clearTimeout(g.longTimer); g.longTimer = 0 }
    }
    const k = pointerGain()
    movePointerBy(dx * k, dy * k)
    // 双击后的第二下已经划过抖动阈值：两次按下的位置差本身就打破了双击判定，
    // 不必再等计时器，立刻按下开始拖。否则指针先跑开再按下，会拖错目标。
    if (g.second && !g.holding) {
      if (g.holdTimer) { window.clearTimeout(g.holdTimer); g.holdTimer = 0 }
      startHold(g)
    }
  }

  const onPointerUp = (e: PointerEvent) => {
    if (e.pointerType === 'mouse') return
    if (inputMode !== 'pointer') {
      const p = pointAt(e.clientX, e.clientY)
      send((t) => {
        if (p) t.addEvent(DeviceEvent.mouseMove(p.x, p.y))
        t.addEvent(DeviceEvent.mouseButtonReleased(0))
      })
      return
    }
    touches.delete(e.pointerId)
    if (scrolling) {
      if (touches.size < 2) scrolling = false
      return
    }
    const g = gesture
    if (!g || g.id !== e.pointerId) return
    clearGestureTimers(g)
    gesture = null
    const wasHolding = g.holding
    releaseHold(g)
    if (!g.moved && !g.rightFired && !wasHolding) {
      // 单击立刻发左键，不为双击判定加延迟：第二次点击落在同一个位置就是双击。
      clickAtPointer(0)
      lastTapAt = Date.now()
      lastDownAt = g.downAt
      buzz(4)
    }
  }

  // 触摸被系统取消（来电、手势返回）时只释放，不再补一次点击。
  const onPointerCancel = (e: PointerEvent) => {
    if (e.pointerType === 'mouse') return
    if (inputMode !== 'pointer') {
      send((t) => t.addEvent(DeviceEvent.mouseButtonReleased(0)))
      return
    }
    touches.delete(e.pointerId)
    if (touches.size < 2) scrolling = false
    const g = gesture
    if (!g || g.id !== e.pointerId) return
    clearGestureTimers(g)
    gesture = null
    releaseHold(g)
  }
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
    await pushLocalClipboard('用户粘贴', false, true)
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
  const onBlur = () => {
    try { active.releaseAllInputs() } catch { /* ignore */ }
    notifyKeyboard()
  }
  // 旋转屏幕、地址栏收起都会改变画布在页面里的位置，自绘指针要跟着挪。
  const onViewportChange = () => drawCursorOverlay()

  // 指针模式先把位置对齐一次，自绘指针与服务端指针从同一处起步。
  if (inputMode === 'pointer') commitPointerNow()

  canvas.addEventListener('mousemove', onMouseMove)
  canvas.addEventListener('mousedown', onMouseDown)
  window.addEventListener('mousemove', onWindowMove)
  window.addEventListener('mouseup', onWindowUp)
  window.addEventListener('blur', onWindowBlur)
  window.addEventListener('resize', onViewportChange)
  canvas.addEventListener('pointerdown', onPointerDown)
  canvas.addEventListener('pointermove', onPointerMove)
  canvas.addEventListener('pointerup', onPointerUp)
  canvas.addEventListener('pointercancel', onPointerCancel)
  canvas.addEventListener('wheel', onWheel, { passive: false })
  canvas.addEventListener('contextmenu', onContextMenu)
  sink.addEventListener('keydown', onKeyDown)
  sink.addEventListener('keyup', onKeyUp)
  sink.addEventListener('compositionstart', onCompositionStart)
  sink.addEventListener('compositionend', onCompositionEnd)
  sink.addEventListener('input', onInput)
  sink.addEventListener('blur', onBlur)
  if (opts.allowClipboard !== false) document.addEventListener('copy', onCopy)

  const detach = () => {
    if (moveRaf) { cancelAnimationFrame(moveRaf); moveRaf = 0 }
    if (pointerRaf) { cancelAnimationFrame(pointerRaf); pointerRaf = 0 }
    pendingMove = null
    if (gesture) clearGestureTimers(gesture)
    gesture = null
    touches.clear()
    canvas.removeEventListener('mousemove', onMouseMove)
    canvas.removeEventListener('mousedown', onMouseDown)
    window.removeEventListener('mousemove', onWindowMove)
    window.removeEventListener('mouseup', onWindowUp)
    window.removeEventListener('blur', onWindowBlur)
    window.removeEventListener('resize', onViewportChange)
    canvas.removeEventListener('pointerdown', onPointerDown)
    canvas.removeEventListener('pointermove', onPointerMove)
    canvas.removeEventListener('pointerup', onPointerUp)
    canvas.removeEventListener('pointercancel', onPointerCancel)
    canvas.removeEventListener('wheel', onWheel)
    canvas.removeEventListener('contextmenu', onContextMenu)
    sink.removeEventListener('keydown', onKeyDown)
    sink.removeEventListener('keyup', onKeyUp)
    sink.removeEventListener('compositionstart', onCompositionStart)
    sink.removeEventListener('compositionend', onCompositionEnd)
    sink.removeEventListener('input', onInput)
    sink.removeEventListener('blur', onBlur)
    document.removeEventListener('copy', onCopy)
    sink.remove()
    cursorEl.remove()
    canvas.style.cursor = ''
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
    showKeyboard: () => {
      focusSink()
      notifyKeyboard(true)
    },
    hideKeyboard: () => {
      try { sink.blur() } catch { /* ignore */ }
      notifyKeyboard(false)
    },
    setInputMode: (mode: InputMode) => {
      if (mode === inputMode) return
      // 切换模式时释放按键，否则左键会卡在按下状态。
      if (gesture) {
        clearGestureTimers(gesture)
        releaseHold(gesture)
        gesture = null
      }
      scrolling = false
      touches.clear()
      // 切换模式前的点击不应被算成双击序列的一半。
      lastTapAt = 0
      lastDownAt = 0
      inputMode = mode
      applyCanvasCursor()
      // 切到指针模式时把远端指针挪到自绘指针的位置，两边保持重合。
      if (mode === 'pointer') commitPointerNow()
    },
    resize: (w: number, h: number) => {
      if (w <= 0 || h <= 0) return
      viewport.width = w
      viewport.height = h
      // 分辨率变了，指针可能落在桌面外。
      pointerPos.x = Math.min(pointerPos.x, w - 1)
      pointerPos.y = Math.min(pointerPos.y, h - 1)
      try { active.resize(w, h) } catch { /* ignore */ }
      drawCursorOverlay()
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
