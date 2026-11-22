// RDP WASM 会话封装：Windows 凭据仅存在于浏览器内，网关不可见。
import init, {
  SessionBuilder,
  DesktopSize,
  Extension,
  DeviceEvent,
  InputTransaction,
  RotationUnit,
} from 'ironrdp-wasm'
import type { Session, SessionTerminationInfo } from 'ironrdp-wasm'

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
  canvas: HTMLCanvasElement
  credentials: Credentials
  width: number
  height: number
  onLog?: (level: string, message: string) => void
}

export interface RdpSession {
  shutdown: () => void
  resize: (width: number, height: number) => void
  sendCtrlAltDel: () => void
  terminated: Promise<string>
}

export function resolveWsUrl(path: string): string {
  const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:'
  return scheme + '//' + location.host + path
}

// 浏览器 KeyboardEvent.key → PS/2 Set 1 通键扫描码（无扩展前缀）。
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
  'Control': 0x1d, 'Alt': 0x38, 'ContextMenu': 0xdd,
}
const specialMap: Record<string, number> = {
  'F1': 0x3b, 'F2': 0x3c, 'F3': 0x3d, 'F4': 0x3e, 'F5': 0x3f,
  'F6': 0x40, 'F7': 0x41, 'F8': 0x42, 'F9': 0x43, 'F10': 0x44,
  'F11': 0x57, 'F12': 0x58, 'Insert': 0xd2, 'Home': 0xc7,
  'PageUp': 0xc9, 'Delete': 0xd3, 'End': 0xcf, 'PageDown': 0xd1,
  'ArrowRight': 0xcd, 'ArrowLeft': 0xcb, 'ArrowDown': 0xd0, 'ArrowUp': 0xc8,
}

function scancodeOf(e: KeyboardEvent): number | null {
  if (specialMap[e.key] !== undefined) return specialMap[e.key]
  if (scancodeMap[e.key] !== undefined) return scancodeMap[e.key]
  const k = e.key.toLowerCase()
  return scancodeMap[k] !== undefined ? scancodeMap[k] : null
}

// 建立 RDP 会话并绑定画布输入。该函数返回后不再持有凭据。
export async function connectRdp(opts: RdpOptions): Promise<RdpSession> {
  await ensureWasm()
  const log = opts.onLog || (() => {})
  log('info', '正在初始化 RDP 协议栈')

  const builder = new SessionBuilder()
  builder.username(opts.credentials.username)
  builder.password(opts.credentials.password)
  if (opts.credentials.domain) builder.serverDomain(opts.credentials.domain)
  // destination 由网关强制替换为数据库中的主机地址，这里仅作协议占位。
  builder.destination('deskgw.invalid:3389')
  builder.proxyAddress(opts.wsUrl)
  builder.desktopSize(new DesktopSize(opts.width, opts.height))
  builder.renderCanvas(opts.canvas)
  builder.extension(new Extension('enable_credssp', true))

  const session: Session = await builder.connect()
  log('info', 'NLA 认证通过，远程会话已建立')

  let stopped = false
  let finish!: (reason: string) => void
  const terminated = new Promise<string>((resolve) => { finish = resolve })

  const runPromise: Promise<SessionTerminationInfo> = session.run()
  runPromise.then((info) => {
    if (!stopped) finish(info.reason() || 'remote-closed')
  }).catch((e: any) => {
    if (!stopped) finish(String(e?.message || e || 'session-error'))
  })

  const send = (fn: (t: InputTransaction) => void) => {
    if (stopped) return
    const t = new InputTransaction()
    fn(t)
    try { session.applyInputs(t) } catch { /* 会话可能已结束 */ }
  }

  const canvas = opts.canvas
  canvas.tabIndex = 0
  const onMouseMove = (e: MouseEvent) => {
    const rect = canvas.getBoundingClientRect()
    const x = Math.max(0, Math.min(opts.width, Math.round((e.clientX - rect.left) * opts.width / rect.width)))
    const y = Math.max(0, Math.min(opts.height, Math.round((e.clientY - rect.top) * opts.height / rect.height)))
    send((t) => t.addEvent(DeviceEvent.mouseMove(x, y)))
  }
  const onMouseDown = (e: MouseEvent) => { send((t) => t.addEvent(DeviceEvent.mouseButtonPressed(e.button))) }
  const onMouseUp = (e: MouseEvent) => { send((t) => t.addEvent(DeviceEvent.mouseButtonReleased(e.button))) }
  const onWheel = (e: WheelEvent) => {
    const vertical = Math.abs(e.deltaY) >= Math.abs(e.deltaX)
    const amount = vertical ? e.deltaY : e.deltaX
    const unit = e.deltaMode === 1 ? RotationUnit.Line : e.deltaMode === 2 ? RotationUnit.Page : RotationUnit.Pixel
    send((t) => t.addEvent(DeviceEvent.wheelRotations(vertical, Math.abs(amount), unit)))
    e.preventDefault()
  }
  const onKeyDown = (e: KeyboardEvent) => {
    const code = scancodeOf(e)
    if (code !== null) { send((t) => t.addEvent(DeviceEvent.keyPressed(code))); e.preventDefault() }
  }
  const onKeyUp = (e: KeyboardEvent) => {
    const code = scancodeOf(e)
    if (code !== null) { send((t) => t.addEvent(DeviceEvent.keyReleased(code))); e.preventDefault() }
  }
  const onContextMenu = (e: Event) => e.preventDefault()

  canvas.addEventListener('mousemove', onMouseMove)
  canvas.addEventListener('mousedown', onMouseDown)
  canvas.addEventListener('mouseup', onMouseUp)
  canvas.addEventListener('wheel', onWheel, { passive: false })
  canvas.addEventListener('keydown', onKeyDown)
  canvas.addEventListener('keyup', onKeyUp)
  canvas.addEventListener('contextmenu', onContextMenu)

  const detach = () => {
    canvas.removeEventListener('mousemove', onMouseMove)
    canvas.removeEventListener('mousedown', onMouseDown)
    canvas.removeEventListener('mouseup', onMouseUp)
    canvas.removeEventListener('wheel', onWheel)
    canvas.removeEventListener('keydown', onKeyDown)
    canvas.removeEventListener('keyup', onKeyUp)
    canvas.removeEventListener('contextmenu', onContextMenu)
  }
  terminated.finally(detach)

  return {
    shutdown: () => {
      if (stopped) return
      stopped = true
      try { session.shutdown() } catch { /* ignore */ }
      finish('user-closed')
    },
    resize: (w: number, h: number) => {
      try { session.resize(w, h) } catch { /* ignore */ }
    },
    sendCtrlAltDel: () => {
      send((t) => {
        t.addEvent(DeviceEvent.keyPressed(0x1d))   // Ctrl
        t.addEvent(DeviceEvent.keyPressed(0x38))   // Alt
        t.addEvent(DeviceEvent.keyPressed(0xd3))   // Delete
        t.addEvent(DeviceEvent.keyReleased(0xd3))
        t.addEvent(DeviceEvent.keyReleased(0x38))
        t.addEvent(DeviceEvent.keyReleased(0x1d))
      })
    },
    terminated,
  }
}
