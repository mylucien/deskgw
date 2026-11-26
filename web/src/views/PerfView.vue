<template>
  <div class="perf-page">
    <div class="perf-head">
      <div class="who">
        <strong>{{ ready?.host.name || perfSession.current?.hostName || '性能模式' }}</strong>
        <span v-if="ready" class="tag ok">端到端加密</span>
        <span v-if="ready" class="muted small">安全码 <b>{{ ready.safety }}</b></span>
      </div>
      <div class="meter" v-if="state === 'ready' && hasFrame">
        <span>{{ resLabel }}</span>
        <span>{{ stats.fps }} fps</span>
        <span>{{ rateLabel }}</span>
        <span>RTT {{ stats.rtt }} ms</span>
        <span v-if="stats.dropped">丢 {{ stats.dropped }}</span>
      </div>
      <div class="acts">
        <button @click="leave">返回主机列表</button>
        <button v-if="state === 'ready'" class="primary" @click="hangup">断开</button>
      </div>
    </div>

    <div class="stage" ref="stage">
      <canvas
        ref="canvas"
        tabindex="0"
        title="点击画面后可直接用键盘和鼠标操作，支持中文输入法"
        :class="{ idle: !hasFrame }"
        :style="{ cursor: cursorStyle }"
        @pointerdown="onPointerDown"
        @pointerup="onPointerUp"
        @pointercancel="onPointerUp"
        @pointermove="onPointerMove"
        @wheel.prevent="onWheel"
        @contextmenu.prevent
      ></canvas>

      <!--
        输入代理：画面本身收不到输入法组字，所以用这个不可见的 textarea 接住。
        可打印字符不拦默认行为，交给它；上屏的文本再作为 ControllerMsg 的 Text 发出。
      -->
      <textarea
        ref="ime"
        class="ime"
        rows="1"
        tabindex="-1"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck="false"
        aria-hidden="true"
        @input="onImeInput"
        @compositionend="onCompositionEnd"
        @blur="onImeBlur"
      ></textarea>

      <div v-if="state !== 'ready' || !hasFrame" class="overlay">
        <div class="overlay-card">
          <template v-if="!perfSession.current">
            <h3>没有待连接的会话</h3>
            <p class="muted">请从主机列表点「性能模式」重新进入。</p>
            <button @click="leave">返回主机列表</button>
          </template>
          <template v-else-if="state === 'connecting'">
            <h3>正在建立端到端会话</h3>
            <p class="muted">握手、派生密钥、等待被控端的第一帧画面…</p>
          </template>
          <template v-else-if="state === 'error'">
            <h3>连接失败</h3>
            <p class="error">{{ errorText }}</p>
            <p v-if="hint" class="muted small">{{ hint }}</p>
            <button @click="leave">返回主机列表</button>
          </template>
          <template v-else-if="state === 'ended'">
            <h3>会话已结束</h3>
            <p class="muted">{{ endedReason || '被控端或网关结束了这次会话。' }}</p>
            <button @click="leave">返回主机列表</button>
          </template>
          <template v-else>
            <h3>已连接，正在等画面</h3>
            <p class="muted">{{ waitingText }}</p>
            <p v-if="encoderName" class="muted small">编码器：{{ encoderName }}</p>
          </template>
        </div>
      </div>

      <div v-if="banner" class="banner">{{ banner }}</div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { perfSession, closePerf } from '../perf'
import { connectPerf } from '../perf/client'
import type { PerfConnection, PerfReady, PerfStats } from '../perf/client'
import type { HostEvent, InputEvent } from '../perf/messages'

type State = 'connecting' | 'ready' | 'error' | 'ended'

const router = useRouter()
const stage = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
const ime = ref<HTMLTextAreaElement | null>(null)

const state = ref<State>('connecting')
const ready = ref<PerfReady | null>(null)
const hasFrame = ref(false)
const errorKind = ref('')
const errorText = ref('')
const endedReason = ref('')
const banner = ref('')
const encoderName = ref('')
const frameSize = reactive({ w: 0, h: 0 })
const stats = reactive<PerfStats>({ fps: 0, kbps: 0, bytes: 0, dropped: 0, rtt: 0, errors: 0 })
const cursorStyle = ref<'default' | 'none'>('default')

let conn: PerfConnection | null = null
let bannerTimer = 0

const hints: Record<string, string> = {
  codeNotFound: '被控端不在线：确认 Airhand 正在运行，且已连上这台网关。',
  hostBusy: '这台被控端已经有会话了，先结束那一个再试。',
  pairingRequired: '被控端的 config.toml 里没有这台网关的控制端公钥，补上 [[paired]] 后重启 Airhand。',
  hostKeyChanged: '被控端换了身份密钥（重装或换机），需要在后台重新批准。',
  incompatible: '两端的会话版本不一致，升级到同一版本。',
  limit: '达到并发上限，稍后再试或调高后台的限额。',
  disabled: '性能模式没有启用，检查网关的 perf.enabled。',
}
const hint = computed(() => hints[errorKind.value] || '')
const resLabel = computed(() => (frameSize.w ? `${frameSize.w}×${frameSize.h}` : '—'))
const rateLabel = computed(() => (stats.kbps >= 1000 ? (stats.kbps / 1000).toFixed(1) + ' Mbps' : stats.kbps + ' kbps'))
const waitingText = computed(() =>
  ready.value ? '握手已完成，正在等被控端的第一个关键帧。' : '正在等待网关的 ready。',
)

function setBanner(text: string) {
  banner.value = text
  window.clearTimeout(bannerTimer)
  bannerTimer = window.setTimeout(() => (banner.value = ''), 8000)
}

// ---- 键鼠输入 -------------------------------------------------------------
//
// 鼠标用归一化坐标（0..1，相对第 0 路画面），键盘用 KeyboardEvent.code。
// 事件先攒一帧再发：鼠标移动只留最后一个，点击、滚轮、按键保持先后。

let pending: InputEvent[] = []
let raf = 0
// 被控端对光标的三种说法（协议 CursorVisibility）：0 隐藏（游戏里转视角）、
// 1 显示且由控制端画、2 已经画在画面里。只有 0 才发相对移动，2 照常发绝对坐标。
let cursorMode: 0 | 1 | 2 = 1

function flushInput() {
  raf = 0
  if (!pending.length) return
  const events = pending
  pending = []
  conn?.sendInput(events, Math.round(performance.now() * 1000))
}

function push(ev: InputEvent) {
  pending.push(ev)
  if (!raf) raf = requestAnimationFrame(flushInput)
}

function pushMove(ev: InputEvent) {
  const last = pending[pending.length - 1]
  if (last && last.kind === 'move') pending[pending.length - 1] = ev
  else pending.push(ev)
  if (!raf) raf = requestAnimationFrame(flushInput)
}

/** 指针在画布上的位置，归一化到 0..1；拖到画布外时夹住。 */
function point(ev: { clientX: number; clientY: number }) {
  const c = canvas.value
  if (!c) return null
  const r = c.getBoundingClientRect()
  if (!r.width || !r.height) return null
  return {
    x: Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width)),
    y: Math.min(1, Math.max(0, (ev.clientY - r.top) / r.height)),
  }
}

// 浏览器与协议对鼠标键的编号不同：中键在浏览器是 1、协议里是 2。
const webButton: Record<number, number> = { 0: 0, 2: 1, 1: 2, 3: 3, 4: 4 }

function onPointerDown(ev: PointerEvent) {
  focusIme(ev)
  canvas.value?.setPointerCapture?.(ev.pointerId)
  const p = point(ev)
  if (p && cursorMode !== 0) pushMove({ kind: 'move', x: p.x, y: p.y })
  const b = webButton[ev.button]
  if (b !== undefined) {
    push({ kind: 'button', button: b, down: true })
    ev.preventDefault()
  }
}

function onPointerUp(ev: PointerEvent) {
  const b = webButton[ev.button]
  if (b !== undefined) push({ kind: 'button', button: b, down: false })
  try {
    canvas.value?.releasePointerCapture?.(ev.pointerId)
  } catch {
    /* 没捕获过 */
  }
}

function onPointerMove(ev: PointerEvent) {
  if (cursorMode === 0) {
    // 被控端把光标藏起来了（游戏里转视角）：改发相对移动。
    const dx = Math.round(ev.movementX)
    const dy = Math.round(ev.movementY)
    if (dx || dy) push({ kind: 'delta', dx, dy })
    return
  }
  const p = point(ev)
  if (p) pushMove({ kind: 'move', x: p.x, y: p.y })
}

/** 一格滚轮是 120：像素模式按 100px 一格折算，行、页按浏览器给的倍数。 */
function wheelStep(v: number, mode: number) {
  const raw = mode === 0 ? (v / 100) * 120 : v * (mode === 1 ? 120 : 1200)
  return Math.max(-2400, Math.min(2400, Math.round(raw)))
}

function onWheel(ev: WheelEvent) {
  const dx = wheelStep(ev.deltaX, ev.deltaMode)
  const dy = wheelStep(ev.deltaY, ev.deltaMode)
  if (dx || dy) push({ kind: 'wheel', dx, dy })
}

/** 这些键不走文本，直接按物理键发给被控端。 */
const NAMED_KEYS = new Set([
  'Escape', 'Tab', 'Enter', 'Backspace', 'Delete', 'Insert',
  'Home', 'End', 'PageUp', 'PageDown',
  'ArrowUp', 'ArrowDown', 'ArrowLeft', 'ArrowRight',
  'Shift', 'Control', 'Alt', 'Meta', 'CapsLock', 'ContextMenu',
  'Pause', 'ScrollLock', 'NumLock', 'PrintScreen',
])

/** 带修饰键的组合、功能键、编辑键走物理键；其余可打印字符交给输入代理。 */
function isPhysicalKey(ev: KeyboardEvent): boolean {
  if (ev.ctrlKey || ev.altKey || ev.metaKey) return true
  if (/^F\d{1,2}$/.test(ev.key)) return true
  return NAMED_KEYS.has(ev.key)
}

// 按下时发过 Key 的键：抬起时必须发，哪怕这时修饰键已经松开。
const heldKeys = new Set<string>()

function onKey(ev: KeyboardEvent, down: boolean) {
  if (state.value !== 'ready') return
  const el = ev.target as HTMLElement | null
  const tag = el?.tagName
  // 页面上的输入框、按钮、可编辑区还给自己；隐藏的输入代理除外，它是画面的嘴。
  if (tag === 'INPUT' || tag === 'SELECT' || tag === 'BUTTON' || el?.isContentEditable) return
  if (tag === 'TEXTAREA' && el !== ime.value) return
  // 输入法组字期间整段交给输入法：不上屏、也不拦默认行为。
  if (ev.isComposing) return
  // 刷新、全屏、开发者工具交还给浏览器。
  if (ev.key === 'F5' || ev.key === 'F11' || ev.key === 'F12') return
  // 输入法接管的键（Chrome 里是 Process / Unidentified）：不拦，让它启动组字。
  if (ev.key === 'Process' || ev.key === 'Unidentified') return

  if (!down) {
    if (ev.code && heldKeys.delete(ev.code)) {
      push({ kind: 'key', code: ev.code, down: false })
      ev.preventDefault()
    }
    return
  }
  if (!isPhysicalKey(ev)) return
  if (!ev.code) return
  heldKeys.add(ev.code)
  push({ kind: 'key', code: ev.code, down: true })
  ev.preventDefault()
}

/** 把输入代理挪到指针处（输入法候选框跟着走）并聚焦。 */
function focusIme(ev?: { clientX: number; clientY: number }) {
  const el = ime.value
  const box = stage.value
  if (!el || !box) return
  if (ev) {
    const r = box.getBoundingClientRect()
    const x = Math.min(Math.max(ev.clientX - r.left, 0), r.width - 1)
    const y = Math.min(Math.max(ev.clientY - r.top, 0), r.height - 1)
    el.style.left = x + 'px'
    el.style.top = y + 'px'
  }
  if (document.activeElement !== el) el.focus({ preventScroll: true })
}

/** 上屏的文本（含输入法、粘贴）走 ControllerMsg 的 Text，交给被控端按 Unicode 注入。 */
function onImeInput(ev: Event) {
  const el = ime.value
  if (!el) return
  // 组字中间态，等 composition 结束后那一次 input。
  if ((ev as InputEvent).isComposing) return
  const text = el.value
  if (!text) return
  el.value = ''
  push({ kind: 'text', text })
}

function onCompositionEnd() {
  // 兜底：个别输入法结束后不再派发 input，这里补一次（已经处理过则为空）。
  const el = ime.value
  if (!el) return
  queueMicrotask(() => {
    const text = el.value
    if (!text) return
    el.value = ''
    push({ kind: 'text', text })
  })
}

function onImeBlur() {
  if (ime.value) ime.value.value = ''
}

/** 失焦或页面隐藏时松开所有按键，免得打字机效应。 */
function releaseAll() {
  if (!conn) return
  heldKeys.clear()
  pending.push({ kind: 'releaseAll' })
  flushInput()
}

function onBlur() {
  releaseAll()
}

function onVisibility() {
  if (document.hidden) releaseAll()
}

function onKeyDown(ev: KeyboardEvent) {
  onKey(ev, true)
}

function onKeyUp(ev: KeyboardEvent) {
  onKey(ev, false)
}

function onVideo(frame: VideoFrame) {
  const c = canvas.value
  if (!c) {
    frame.close()
    return
  }
  // 画布按画面原始尺寸走，显示大小交给 CSS，比例不会被拉伸。
  if (c.width !== frame.displayWidth || c.height !== frame.displayHeight) {
    c.width = frame.displayWidth
    c.height = frame.displayHeight
    frameSize.w = frame.displayWidth
    frameSize.h = frame.displayHeight
  }
  const ctx = c.getContext('2d', { alpha: false })
  if (ctx) {
    try {
      // VideoFrame 是 CanvasImageSource，TS 的旧 lib 里还没列进去。
      ctx.drawImage(frame as unknown as CanvasImageSource, 0, 0)
    } catch (e) {
      console.warn('[perf] 画一帧失败', e)
    }
  }
  frame.close()
  hasFrame.value = true
}

function onEvent(ev: HostEvent) {
  if (ev.type === 'encoder') {
    encoderName.value = `${ev.name}${ev.hardware ? '（硬件）' : ''}`
  } else if (ev.type === 'cursor') {
    // 1 = 显示着，用本地光标；2 = 被控端已经把光标画进画面，藏本地光标；
    // 0 = 隐藏，藏本地光标并改发相对移动。
    const v = ev.visibility
    cursorMode = v === 1 ? 1 : v === 2 ? 2 : 0
    cursorStyle.value = cursorMode === 1 ? 'default' : 'none'
  } else if (ev.type === 'notice') {
    if (!ev.recovered && ev.text) setBanner(ev.text)
    else if (ev.recovered) banner.value = ''
  }
}

function connect() {
  const cur = perfSession.current
  if (!cur) return
  state.value = 'connecting'
  conn = connectPerf(cur.wsPath, cur.hostId, {
    onReady: (r) => {
      ready.value = r
      state.value = 'ready'
      nextTick(() => focusIme())
    },
    onEvent,
    onVideo,
    onStats: (s) => Object.assign(stats, s),
    onError: (kind, message) => {
      errorKind.value = kind
      errorText.value = message
      state.value = 'error'
    },
    onEnded: (reason) => {
      if (state.value === 'error') return
      endedReason.value = reason
      state.value = 'ended'
    },
    onFatal: (message) => {
      errorText.value = message
      state.value = 'error'
    },
  })
}

function shutdown() {
  window.clearTimeout(bannerTimer)
  // 先把按下的键松开再断，免得被控端留下按住的状态。
  releaseAll()
  if (raf) {
    cancelAnimationFrame(raf)
    raf = 0
  }
  conn?.close()
  conn = null
  pending = []
}

function hangup() {
  shutdown()
  state.value = 'ended'
  endedReason.value = '已主动断开。'
}

function leave() {
  shutdown()
  closePerf()
  router.push({ name: 'hosts' })
}

onMounted(() => {
  nextTick(() => focusIme())
  window.addEventListener('keydown', onKeyDown)
  window.addEventListener('keyup', onKeyUp)
  window.addEventListener('blur', onBlur)
  document.addEventListener('visibilitychange', onVisibility)
  connect()
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeyDown)
  window.removeEventListener('keyup', onKeyUp)
  window.removeEventListener('blur', onBlur)
  document.removeEventListener('visibilitychange', onVisibility)
  shutdown()
})
</script>

<style scoped>
.perf-page {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 56px);
  min-height: 0;
  background: #0f1115;
}
.perf-head {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 10px 18px;
  background: #161a20;
  border-bottom: 1px solid #262b33;
  color: #e5e7eb;
}
.perf-head .who { display: flex; align-items: center; gap: 10px; min-width: 0; }
.perf-head .who strong { font-size: 15px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.perf-head .muted { color: #9ca3af; }
.perf-head .muted b { color: #e5e7eb; font-variant-numeric: tabular-nums; letter-spacing: .5px; }
.perf-head .meter { display: flex; gap: 14px; margin-left: auto; font-size: 12px; color: #9ca3af;
  font-variant-numeric: tabular-nums; }
.perf-head .acts { display: flex; gap: 8px; margin-left: auto; }
.perf-head .meter + .acts { margin-left: 4px; }
.perf-head button { background: #232830; border-color: #333a45; color: #e5e7eb; }
.perf-head button:hover:not(:disabled) { background: #2b323c; }
.perf-head button.primary { background: #2563eb; border-color: #2563eb; }

.stage {
  position: relative;
  flex: 1;
  min-height: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  overflow: hidden;
  background: #000;
}
.stage canvas {
  display: block;
  max-width: 100%;
  max-height: 100%;
  width: auto;
  height: auto;
  background: #000;
  outline: none;
  user-select: none;
  -webkit-user-select: none;
}
.stage canvas.idle { opacity: 0; }

/* 输入代理：看不见、点不到，只用来接输入法；候选框跟着它走。 */
.stage .ime {
  position: absolute;
  left: 50%;
  top: 50%;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: 0;
  border: 0;
  opacity: .01;
  resize: none;
  overflow: hidden;
  font-size: 16px;
  line-height: 16px;
  color: transparent;
  background: transparent;
  caret-color: transparent;
  pointer-events: none;
  z-index: 2;
}

.overlay {
  position: absolute;
  inset: 0;
  display: grid;
  place-items: center;
  background: rgba(10, 12, 16, .72);
}
.overlay-card {
  width: 460px;
  max-width: 90%;
  background: #1b1e24;
  color: #e5e7eb;
  border: 1px solid #343945;
  border-radius: 12px;
  padding: 22px;
  text-align: center;
}
.overlay-card h3 { margin: 0 0 8px; font-size: 17px; }
.overlay-card .muted { color: #9ca3af; font-size: 13px; margin: 0 0 10px; }
.overlay-card .error { color: #fecaca; background: #3f1d1d; border-color: #7f1d1d; text-align: left; }
.overlay-card button { margin-top: 8px; background: #232830; border-color: #333a45; color: #e5e7eb; }

.banner {
  position: absolute;
  left: 50%;
  bottom: 18px;
  transform: translateX(-50%);
  padding: 8px 14px;
  border-radius: 8px;
  background: rgba(38, 42, 51, .94);
  color: #fde68a;
  font-size: 13px;
  border: 1px solid #4b5563;
}
</style>
