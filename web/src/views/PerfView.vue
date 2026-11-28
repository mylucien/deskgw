<template>
  <div class="perf-page" ref="pageEl" :class="{ immersive }">
    <div class="stage" ref="stage">
      <canvas
        ref="canvas"
        tabindex="0"
        :title="inputHint"
        :class="{ idle: !hasFrame }"
        :style="{ cursor: cursorStyle }"
        @pointerdown="onPointerDown"
        @pointerup="onPointerUp"
        @pointercancel="onPointerCancel"
        @pointermove="onPointerMove"
        @pointerenter="onPointerEnter"
        @pointerleave="onPointerLeave"
        @wheel.prevent="onWheel"
        @contextmenu.prevent
      ></canvas>

      <!--
        触屏的「指针」模式没有系统光标，用这张图画出手指操纵的虚拟指针。
        位置由 touch 手势层维护，坐标是 CSS 像素（相对画布左上角）。
      -->
      <img v-if="showVirtualCursor" ref="cursorEl" class="vcur" :src="cursorSrc"
        :style="{ visibility: cursorInside || touchDevice ? 'visible' : 'hidden' }" alt="" />

      <!--
        输入代理：画面本身收不到输入法组字，所以用这个不可见的 textarea 接住。
        可打印字符不拦默认行为，交给它；上屏的文本再作为 ControllerMsg 的 Text 发出。
      -->
      <textarea
        ref="ime"
        class="ime"
        rows="1"
        tabindex="-1"
        inputmode="text"
        enterkeyhint="enter"
        autocomplete="off"
        autocorrect="off"
        autocapitalize="off"
        spellcheck="false"
        aria-hidden="true"
        @input="onImeInput"
        @compositionend="onCompositionEnd"
        @focus="onImeFocus"
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
            <button class="primary" :disabled="reconnecting" @click="reconnect">
              {{ reconnecting ? '重连中…' : '重新连接' }}
            </button>
            <button @click="leave">返回主机列表</button>
          </template>
          <template v-else-if="state === 'ended'">
            <h3>会话已结束</h3>
            <p class="muted">{{ endedReason || '被控端或网关结束了这次会话。' }}</p>
            <button class="primary" :disabled="reconnecting" @click="reconnect">
              {{ reconnecting ? '重连中…' : '重新连接' }}
            </button>
            <button @click="leave">返回主机列表</button>
          </template>
          <template v-else>
            <h3>已连接，正在等画面</h3>
            <p class="muted">{{ waitingText }}</p>
            <p v-if="encoderName" class="muted small">编码器：{{ encoderName }}</p>
            <p v-if="firstFrameStuck" class="muted small">
              被控端可能锁屏、正在等 UAC 授权，或者画面采集没有启动。可以先断开重连。
            </p>
          </template>
        </div>
      </div>

      <div v-if="banner" class="banner">{{ banner }}</div>
    </div>

    <!-- 沉浸模式（浏览器不支持元素全屏时的退路）没有系统全屏的退出途径，
         留一个贴顶的退出按钮，免得用户只能刷新页面。 -->
    <button v-if="immersive" class="exit-fs" @click="exitImmersive">退出全屏</button>

    <!-- mousedown.prevent：按钮不抢焦点，点完面板还能继续打字。 -->
    <button class="fab" :class="{ on: menuOpen, drag: dragging }" :style="fabStyle"
      :aria-expanded="menuOpen" aria-label="会话菜单" title="会话菜单"
      @mousedown.prevent @pointerdown="onFabDown" @click="onFabTap">
      <span class="mark">DG</span>
      <span v-if="state === 'ready'" class="live"></span>
    </button>

    <div class="panel" :class="{ open: menuOpen }" :style="panelStyle" :inert="!menuOpen"
      :aria-hidden="!menuOpen" role="dialog" aria-label="会话菜单" ref="panelEl"
      @mousedown.prevent>
      <div class="p-top">
        <span class="p-cap">性能模式 · {{ ready?.host.name || perfSession.current?.hostName || '未连接' }}</span>
        <span v-if="ready" class="p-ok">加密</span>
        <button class="p-x" @click="closeMenu" aria-label="收起">×</button>
      </div>

      <div class="p-meta">
        <div v-if="ready">安全码 <b>{{ ready.safety }}</b></div>
        <div v-if="state === 'ready' && hasFrame">
          {{ resLabel }} · {{ stats.fps }} fps · {{ rateLabel }} · RTT {{ stats.rtt }} ms
          <span v-if="stats.dropRate">· 丢 {{ stats.dropRate }}/s</span>
          <span v-if="stats.errors">· 解码错误 {{ stats.errors }}</span>
        </div>
        <div v-if="hostHostname" class="p-sub">被控端：{{ hostHostname }}</div>
        <!-- 多显示器：协议没有运行中切换的消息，view 只在握手（ControllerIntro）
             里给一次，所以选屏靠重连生效。这里给出可点的入口，别让人以为
             画面是坏的。 -->
        <div v-if="displays.length > 1" class="p-sub">
          显示器 {{ displays.length }} 个 · 被控端在显示 {{ currentDisplay + 1 }}
          <div class="seg seg-disp">
            <button v-for="(d, i) in displays" :key="i" :class="{ on: displayIndex === i }"
              :title="`${d.name || '屏幕 ' + (i + 1)} · ${d.width}×${d.height}`"
              @click="switchDisplay(i)">屏 {{ i + 1 }}</button>
          </div>
          <span v-if="switchingDisplay">正在切换到显示器 {{ displayIndex + 1 }}…</span>
        </div>
      </div>

      <template v-if="state === 'ready'">
        <div class="p-div">画质</div>
        <div class="seg seg3">
          <button v-for="q in qualityPresets" :key="q.key" :class="{ on: quality === q.key }"
            :title="q.tip" @click="setQuality(q.key)">{{ q.label }}</button>
        </div>
        <p class="p-note">{{ qualityNote }}</p>

        <div class="p-div">按键模式</div>
        <div class="seg">
          <button :class="{ on: keyMode === 'text' }" @click="setKeyMode('text')">文本</button>
          <button :class="{ on: keyMode === 'physical' }" @click="setKeyMode('physical')">物理键</button>
        </div>
        <p v-if="keyMode === 'physical'" class="p-note">按键全部按扫描码发送；中文输入法不可用</p>

        <div class="p-div">输入方式</div>
        <div class="seg">
          <button :class="{ on: inputMode === 'pointer' }" @click="setInputMode('pointer')">指针</button>
          <button :class="{ on: inputMode === 'touch' }" :disabled="!hostTouch"
            :title="hostTouch ? '' : '被控端没有声明支持多点触摸'" @click="setInputMode('touch')">触摸</button>
        </div>
        <p v-if="!hostTouch" class="p-note">被控端不支持触摸，可使用指针</p>
      </template>

      <!-- 全屏与软键盘是「看和输」两个最常用的动作，放在面板里而不是画面上，
           免得挡住远端画面。触屏设备才需要软键盘按钮。 -->
      <div class="p-div">显示</div>
      <div class="seg" :class="{ seg1: !touchDevice }">
        <button :class="{ on: isFullscreen }" :title="fullscreenTip" @click="toggleFullscreen">
          {{ isFullscreen ? '退出全屏' : '全屏' }}
        </button>
        <button v-if="touchDevice" :class="{ on: keyboardUp }" :disabled="state !== 'ready'"
          :title="keyMode === 'physical' ? '物理键模式不发送输入法内容' : '弹出系统输入法'"
          @click="toggleKeyboard">{{ keyboardUp ? '收起键盘' : '键盘' }}</button>
      </div>
      <p v-if="touchDevice && keyMode === 'text'" class="p-note">
        手机/平板点画面不会自动弹键盘：要打字时点上面的「键盘」。
      </p>

      <!-- 顶栏隐藏后，导航与账号入口都在这儿。 -->
      <div class="p-div">账号</div>
      <div class="p-account">
        <span class="p-nm">{{ userName }}<i v-if="userRole" class="p-role">{{ userRole }}</i></span>
        <button class="p-link" @click="openPasswordDialog">改密码</button>
        <button class="p-link" @click="signOut">退出</button>
      </div>

      <div class="p-foot">
        <button v-if="state === 'ready'" class="danger" @click="hangup">断开连接</button>
        <button @click="leave">返回主机列表</button>
        <button v-if="isAdmin" @click="goAdmin">管理后台</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { perfSession, closePerf } from '../perf'
import { connectPerf } from '../perf/client'
import type { PerfConnection, PerfReady, PerfStats } from '../perf/client'
import type { DisplayInfo, HostEvent, InputEvent, QualitySettings } from '../perf/messages'
import { post } from '../api'
// 本文件里的 state 是会话状态机，登录态用别名，别搅在一起。
import { state as appState } from '../state'
import { openPasswordDialog, logoutNow } from '../account'

type State = 'connecting' | 'ready' | 'error' | 'ended'

const router = useRouter()
const stage = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
const ime = ref<HTMLTextAreaElement | null>(null)

const state = ref<State>('connecting')
const reconnecting = ref(false)
const ready = ref<PerfReady | null>(null)
const hasFrame = ref(false)
const errorKind = ref('')
const errorText = ref('')
const endedReason = ref('')
const banner = ref('')
const encoderName = ref('')
// 被控端自报的机器名，和后台登记的名字可能不一样，连着的时候两个都显示。
const hostHostname = ref('')
// 被控端报告的显示器列表与当前显示的那一块。
const displays = ref<DisplayInfo[]>([])
const currentDisplay = ref(0)
// 想看的显示器序号：握手时写进 ControllerIntro.view，换屏靠重连生效。
const displayIndex = ref(0)
const switchingDisplay = ref(false)
// ready 之后迟迟没有首帧（锁屏、UAC、采集没起来）时给一句提示。
const firstFrameStuck = ref(false)
const frameSize = reactive({ w: 0, h: 0 })
const stats = reactive<PerfStats>({ fps: 0, kbps: 0, bytes: 0, dropped: 0, dropRate: 0, rtt: 0, errors: 0 })
// 自绘光标的兜底图：还没收到被控端形状时用普通模式同款箭头。
const DEFAULT_CURSOR_SVG = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="12" height="19" viewBox="0 0 12 19">'
  + '<path d="M1 1v15.2l3.7-3.6 2.4 4.8 2.3-1.1-2.3-4.7h5.4z"'
  + ' fill="#fff" stroke="#000" stroke-width="1" stroke-linejoin="round"/></svg>',
)

// 远端光标形状：槽位 → 形状。代际只增不减，乱序或复用旧槽位的图像直接丢。
interface RemoteShape {
  slot: number
  generation: number
  width: number
  height: number
  hotX: number
  hotY: number
  url: string
}
const shapeCache = new Map<number, RemoteShape>()
let wantedSlot = -1
let wantedGen = -1
const activeShape = ref<RemoteShape | null>(null)
const cursorSrc = computed(() => activeShape.value?.url || DEFAULT_CURSOR_SVG)

const cursorEl = ref<HTMLImageElement | null>(null)
const touchDevice = window.matchMedia('(pointer: coarse)').matches || navigator.maxTouchPoints > 0

// 面板里的两项选择都记住。RDP 模式用的是另一套 localStorage 键，互不干扰。
type KeyMode = 'text' | 'physical'
type InputMode = 'pointer' | 'touch'
function saved<T extends string>(key: string, choices: readonly T[], fallback: T): T {
  try {
    const v = localStorage.getItem(key)
    if (v && (choices as readonly string[]).includes(v)) return v as T
  } catch { /* 隐私模式读不到，用默认值 */ }
  return fallback
}
const keyMode = ref<KeyMode>(saved('deskgw.perfKeyMode', ['text', 'physical'] as const, 'text'))
const inputMode = ref<InputMode>(saved('deskgw.perfInputMode', ['pointer', 'touch'] as const, 'pointer'))
const hostTouch = ref(false)

// 画质三档，数值与被控端 QualitySettings::default（30 帧 / 4000 kbps / 短边 1080）对齐。
// 自适应一直开：网络差时被控端自己降码率，比我们在这里猜更准。
type QualityKey = 'smooth' | 'balanced' | 'sharp'
const qualityPresets: Array<{ key: QualityKey; label: string; tip: string; quality: QualitySettings }> = [
  {
    key: 'smooth', label: '流畅', tip: '弱网优先：30 帧 / 短边 720 / 2 Mbps',
    quality: { fps: 30, bitrateKbps: 2000, maxShort: 720, adaptive: true, codec: 0 },
  },
  {
    key: 'balanced', label: '均衡', tip: '默认：30 帧 / 短边 1080 / 4 Mbps',
    quality: { fps: 30, bitrateKbps: 4000, maxShort: 1080, adaptive: true, codec: 0 },
  },
  {
    key: 'sharp', label: '清晰', tip: '高带宽：60 帧 / 原分辨率 / 8 Mbps',
    quality: { fps: 60, bitrateKbps: 8000, maxShort: 0, adaptive: true, codec: 0 },
  },
]
const quality = ref<QualityKey>(saved('deskgw.perfQuality', ['smooth', 'balanced', 'sharp'] as const, 'balanced'))
const qualityNote = computed(() => qualityPresets.find((p) => p.key === quality.value)?.tip || '')

function setQuality(key: QualityKey) {
  if (quality.value === key) return
  quality.value = key
  try { localStorage.setItem('deskgw.perfQuality', key) } catch { /* 隐私模式忽略 */ }
  conn?.sendSettings(currentQuality())
  refocus()
}

function currentQuality(): QualitySettings {
  const p = qualityPresets.find((x) => x.key === quality.value) || qualityPresets[1]
  // 直接给预设对象，被控端 sanitized() 会夹到合法范围；不在这里复制免得漏字段。
  return p.quality
}
const inputHint = computed(() =>
  inputMode.value === 'touch' ? '手指触摸画面操作被控端' :
    keyMode.value === 'physical' ? '点击画面后直接操作，按键按物理键发送' :
      '点击画面后可直接用键盘和鼠标操作，支持中文输入法',
)

// ---- 悬浮按钮（照普通模式的可拖动面板） ---------------------------------
const pageEl = ref<HTMLDivElement | null>(null)
const menuOpen = ref(false)
const panelEl = ref<HTMLElement | null>(null)
const FAB_SIZE = 46
const FAB_MARGIN = 14
const FAB_EDGE = 6
const POS_KEY = 'deskgw.perfFabPos'
const fabX = ref(-1)
const fabY = ref(-1)
const dragging = ref(false)
let dragFrom: { px: number; py: number; ox: number; oy: number } | null = null
let lastDragEndAt = 0
const vw = ref(window.innerWidth)
const vh = ref(window.innerHeight)

let conn: PerfConnection | null = null
let bannerTimer = 0
let firstFrameTimer = 0
/** ready 之后等首帧的上限，超过就提示可能是锁屏/UAC。 */
const FIRST_FRAME_WAIT_MS = 15_000

const hints: Record<string, string> = {
  codeNotFound: '主机与票据对不上：返回主机列表重新进入。',
  hostOffline: '被控端不在线：确认 Airhand 正在运行，且已连上这台网关。',
  notApproved: '这台被控端还没在后台批准：到「性能模式」待批准列表里点批准。',
  hostBusy: '这台被控端已经有会话了，先结束那一个再试。',
  pairingRequired: '被控端的 config.toml 里没有这台网关的控制端公钥，补上 [[paired]] 后重启 Airhand。',
  hostKeyChanged: '被控端换了身份密钥（重装或换机），到后台的待批准列表里重新批准一次即可。',
  incompatible: '两端的会话版本不一致，升级到同一版本。',
  limit: '网关的并发名额满了，稍后再试或调高后台的限额。',
  disabled: '性能模式没有启用，检查网关的 perf.enabled。',
  serverError: '网关连不上被控端（拨号超时或链路中断），稍后重试；持续失败请看网关日志。',
  connectFailed: '连接没有建立：票据一次性有效，网关也可能拒绝了升级。点「重新连接」换一张票据再试。',
}
const hint = computed(() => hints[errorKind.value] || '')
const resLabel = computed(() => (frameSize.w ? `${frameSize.w}×${frameSize.h}` : '—'))
const rateLabel = computed(() => (stats.kbps >= 1000 ? (stats.kbps / 1000).toFixed(1) + ' Mbps' : stats.kbps + ' kbps'))
const waitingText = computed(() =>
  ready.value ? '握手已完成，正在等被控端的第一个关键帧。' : '正在等待网关的 ready。',
)

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))
function maxX() { return Math.max(FAB_EDGE, vw.value - FAB_SIZE - FAB_EDGE) }
function maxY() { return Math.max(FAB_EDGE, vh.value - FAB_SIZE - FAB_EDGE) }

function measurePage() {
  const r = pageEl.value?.getBoundingClientRect()
  vw.value = Math.round(r?.width || window.innerWidth)
  vh.value = Math.round(r?.height || window.innerHeight)
  if (fabX.value < 0) {
    fabX.value = clamp(vw.value - FAB_SIZE - FAB_MARGIN, FAB_EDGE, maxX())
    fabY.value = clamp(vh.value - FAB_SIZE - FAB_MARGIN, FAB_EDGE, maxY())
  } else {
    fabX.value = clamp(fabX.value, FAB_EDGE, maxX())
    fabY.value = clamp(fabY.value, FAB_EDGE, maxY())
  }
}

function loadFabPos() {
  try {
    const p = JSON.parse(localStorage.getItem(POS_KEY) || 'null') as { x?: number; y?: number } | null
    if (p && Number.isFinite(p.x) && Number.isFinite(p.y)) {
      fabX.value = Math.round(p.x as number)
      fabY.value = Math.round(p.y as number)
    }
  } catch { /* 存坏了就放回右下角 */ }
}

function saveFabPos() {
  try {
    localStorage.setItem(POS_KEY, JSON.stringify({ x: Math.round(fabX.value), y: Math.round(fabY.value) }))
  } catch { /* 隐私模式写不进去，位置只在本页有效 */ }
}

const fabStyle = computed(() => ({
  transform: `translate3d(${Math.round(fabX.value)}px, ${Math.round(fabY.value)}px, 0)`,
}))

// 面板贴着按钮所在的一侧；上方放不下就翻到下方。
const panelStyle = computed(() => {
  const w = Math.min(288, vw.value - 28)
  const cx = fabX.value + FAB_SIZE / 2
  const left = clamp(cx < vw.value / 2 ? fabX.value : fabX.value + FAB_SIZE - w,
    14, Math.max(14, vw.value - w - 14))
  const originX = clamp(cx - left, 12, w - 12)
  const below = fabY.value + FAB_SIZE / 2 < vh.value / 2
  const style: Record<string, string> = { left: `${Math.round(left)}px`, width: `${Math.round(w)}px` }
  if (below) {
    style.top = `${Math.round(fabY.value + FAB_SIZE + 10)}px`
    style.maxHeight = `${Math.round(Math.max(160, vh.value - fabY.value - FAB_SIZE - 24))}px`
    style.transformOrigin = `${Math.round(originX)}px 0`
  } else {
    style.bottom = `${Math.round(vh.value - fabY.value + 10)}px`
    style.maxHeight = `${Math.round(Math.max(160, fabY.value - 24))}px`
    style.transformOrigin = `${Math.round(originX)}px 100%`
  }
  return style
})

function closeMenu() { menuOpen.value = false }

// ---- 全屏 ---------------------------------------------------------------
//
// 与 RDP 会话页同一套：先试元素全屏，浏览器不支持就退成「沉浸模式」。
// iOS Safari 到现在也没实现元素的 requestFullscreen，只能靠沉浸模式把页面
// 铺满可视区；真要连状态栏一起收掉，得「添加到主屏幕」后从 PWA 打开。
const immersive = ref(false)
const nativeFullscreen = ref(false)
const isFullscreen = computed(() => immersive.value || nativeFullscreen.value)
const fullscreenTip = computed(() =>
  isFullscreen.value ? '退出全屏' : '铺满整个屏幕，把浏览器界面收起来',
)

/** 全屏切换会改画布尺寸，虚拟光标与悬浮按钮的位置都得重算。 */
function afterFullscreen() {
  nextTick(() => { measurePage(); drawVirtualCursor() })
}

function enterImmersive() {
  immersive.value = true
  afterFullscreen()
  // 说清楚为什么没进真正的全屏，免得以为按钮坏了。
  if (!document.fullscreenElement) {
    setBanner('这台浏览器不支持原生全屏，已铺满整个页面；要真全屏请「添加到主屏幕」后再打开。')
  }
}

function exitImmersive() {
  immersive.value = false
  afterFullscreen()
}

function toggleFullscreen() {
  if (document.fullscreenElement) {
    // 老 Safari 用的是带前缀的那一套，两个都试一遍。
    const exit = document.exitFullscreen?.bind(document)
      || (document as Document & { webkitExitFullscreen?: () => void }).webkitExitFullscreen?.bind(document)
    try { void Promise.resolve(exit?.()).catch(() => { /* 已经退出了 */ }) } catch { /* 同上 */ }
    return
  }
  if (immersive.value) { exitImmersive(); return }
  const el = pageEl.value as (HTMLDivElement & { webkitRequestFullscreen?: () => Promise<void> }) | null
  if (!el) return
  // 老一点的 Safari 只认 webkit 前缀那一版。
  const req = el.requestFullscreen?.bind(el) || el.webkitRequestFullscreen?.bind(el)
  // 进全屏就是要看画面，面板先收起来。
  menuOpen.value = false
  if (!req) { enterImmersive(); return }
  try {
    Promise.resolve(req()).catch(enterImmersive)
  } catch {
    enterImmersive()
  }
}

function onFullscreenChange() {
  nativeFullscreen.value = !!document.fullscreenElement
  afterFullscreen()
}

// ---- 账号入口（顶栏隐藏后挪到这里） -------------------------------------
const userName = computed(() => appState.user?.username || '未登录')
const userRole = computed(() => appState.user?.role || '')
const isAdmin = computed(() => appState.user?.role === 'admin')

async function signOut() {
  shutdown()
  closePerf()
  await logoutNow()
  router.push({ name: 'login' })
}

function goAdmin() {
  shutdown()
  closePerf()
  router.push({ name: 'admin' })
}

// ---- 软键盘（手机 / 平板） ----------------------------------------------
//
// 文本都经隐藏的 textarea 上屏（输入法候选框要跟手），但它在触屏上没有焦点，
// 软键盘就不会出来；而「点画面就弹键盘」在手机上纯属误触，所以面板里单独留
// 一个「键盘」按钮。安卓上用返回键收起键盘不会触发 blur，焦点还留在输入框上，
// 靠 visualViewport 的高度变化把状态改回来，否则按钮一直显示「收起键盘」。
const keyboardUp = ref(false)

function onImeFocus() {
  keyboardUp.value = true
}

function showKeyboard() {
  if (state.value !== 'ready') return
  if (keyMode.value === 'physical') {
    setBanner('物理键模式不发送输入法内容，先切到「文本」再弹键盘。')
    return
  }
  focusIme()
  keyboardUp.value = true
  // 面板盖着半屏，收起来才看得见远端。
  menuOpen.value = false
}

function hideKeyboard() {
  ime.value?.blur()
  keyboardUp.value = false
  canvas.value?.focus({ preventScroll: true })
}

function toggleKeyboard() {
  if (keyboardUp.value) hideKeyboard()
  else showKeyboard()
}

/** 软键盘弹收都要重新摆虚拟光标：可视区高度变了。 */
function onViewportResize() {
  const vv = window.visualViewport
  if (!vv) return
  if (document.activeElement !== ime.value) {
    keyboardUp.value = false
    return
  }
  keyboardUp.value = window.innerHeight - vv.height > 120
}

function onFabDown(e: PointerEvent) {
  if (e.pointerType === 'mouse' && e.button !== 0) return
  dragFrom = { px: e.clientX, py: e.clientY, ox: fabX.value, oy: fabY.value }
  window.addEventListener('pointermove', onFabMove, { passive: false })
  window.addEventListener('pointerup', onFabEnd)
  window.addEventListener('pointercancel', onFabEnd)
}

function onFabMove(e: PointerEvent) {
  if (!dragFrom) return
  const dx = e.clientX - dragFrom.px
  const dy = e.clientY - dragFrom.py
  if (!dragging.value) {
    if (Math.hypot(dx, dy) < 6) return
    dragging.value = true
    menuOpen.value = false
  }
  e.preventDefault()
  fabX.value = clamp(dragFrom.ox + dx, FAB_EDGE, maxX())
  fabY.value = clamp(dragFrom.oy + dy, FAB_EDGE, maxY())
}

function onFabEnd() {
  window.removeEventListener('pointermove', onFabMove)
  window.removeEventListener('pointerup', onFabEnd)
  window.removeEventListener('pointercancel', onFabEnd)
  if (!dragFrom) return
  dragFrom = null
  if (!dragging.value) return
  dragging.value = false
  if (fabX.value < FAB_MARGIN + 12) fabX.value = FAB_EDGE
  else if (fabX.value > vw.value - FAB_SIZE - FAB_MARGIN - 12) fabX.value = maxX()
  saveFabPos()
  // 拖完浏览器还会补一次 click，用时间窗挡掉，别马上把面板又打开。
  lastDragEndAt = Date.now()
}

function onFabTap() {
  if (Date.now() - lastDragEndAt < 400) return
  menuOpen.value = !menuOpen.value
}

function onDocDown(e: PointerEvent) {
  if (!menuOpen.value) return
  const t = e.target as Node
  if (panelEl.value?.contains(t)) return
  if ((e.currentTarget as HTMLElement)?.classList?.contains('fab')) return
  // fab 上的 pointerdown 会在 click 之前到这里，不能因为点按钮就把面板收起又展开。
  if (t instanceof Element && t.closest('.fab')) return
  closeMenu()
}

function onWindowResize() { measurePage(); nextTick(drawVirtualCursor) }

function setKeyMode(mode: KeyMode) {
  if (keyMode.value === mode) return
  // 切走时把可能按住的键松开，免得模式变了留下卡键。
  releaseAll()
  keyMode.value = mode
  try { localStorage.setItem('deskgw.perfKeyMode', mode) } catch { /* 忽略 */ }
  if (ime.value) ime.value.value = ''
  menuOpen.value = false
  refocus()
}

function setInputMode(mode: InputMode) {
  if (inputMode.value === mode) return
  if (mode === 'touch' && !hostTouch.value) return
  releaseTouches()
  releaseGesture()
  releaseAll()
  inputMode.value = mode
  try { localStorage.setItem('deskgw.perfInputMode', mode) } catch { /* 忽略 */ }
  menuOpen.value = false
  // 触摸模式不要自动弹手机软键盘；refocus 会按模式选画布或输入代理。
  refocus()
}

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
const cursorMode = ref<0 | 1 | 2>(1)
// 自绘光标的兜底箭头：触屏没有系统光标；桌面收到远端形状时也自绘。
// 桌面还没收到形状时用系统默认箭头（cursorStyle），不自绘。
const showVirtualCursor = computed(() => hasFrame.value && cursorMode.value !== 0 && (
  (touchDevice && inputMode.value === 'pointer') || activeShape.value !== null
))
const cursorStyle = computed(() => {
  if (cursorMode.value !== 1) return 'none'
  // 有远端形状时藏掉系统光标，由自绘 img 接管；否则退回系统箭头。
  return activeShape.value ? 'none' : 'default'
})

// RGBA8（非预乘）转 PNG data URL，给自绘光标 img 用。
function shapeToUrl(width: number, height: number, rgba: Uint8Array): string | null {
  if (!width || !height || rgba.length !== width * height * 4) return null
  const c = document.createElement('canvas')
  c.width = width
  c.height = height
  const ctx = c.getContext('2d')
  if (!ctx) return null
  const img = ctx.createImageData(width, height)
  img.data.set(rgba)
  ctx.putImageData(img, 0, 0)
  return c.toDataURL('image/png')
}

const cursorInside = ref(true)

/** 当前自绘光标的落点（画布左上角为原点的 CSS 像素），形状晚到时按它立刻重绘。 */
let cursorXY = { x: 0, y: 0 }
function placeCursor(x: number, y: number) {
  cursorXY = { x, y }
  const el = cursorEl.value
  if (!el) return
  const s = activeShape.value
  const c = canvas.value
  // 形状像素是被控端屏幕上的，画布显示时可能缩放，光标同比例缩。
  const rect = c?.getBoundingClientRect()
  const scale = frameSize.w && rect?.width ? rect.width / frameSize.w : 1
  const w = s ? Math.max(1, s.width * scale) : 12
  const h = s ? Math.max(1, s.height * scale) : 19
  const hotX = s ? s.hotX * scale : 1
  const hotY = s ? s.hotY * scale : 1
  el.style.width = `${w}px`
  el.style.height = `${h}px`
  el.style.transform = `translate3d(${Math.round(x - hotX)}px,${Math.round(y - hotY)}px,0)`
}

// 高频 pointermove 下每帧最多摆一次光标：中间位置没人看得见，而且每次都读
// 布局会拖慢输入处理。
let cursorRaf = 0
let cursorAt = { x: 0, y: 0 }
function scheduleCursor(x: number, y: number) {
  cursorAt = { x, y }
  if (cursorRaf) return
  cursorRaf = requestAnimationFrame(() => {
    cursorRaf = 0
    placeCursor(cursorAt.x, cursorAt.y)
  })
}

function flushInput() {
  raf = 0
  if (!pending.length) return
  const events = pending
  pending = []
  // 时间戳由 Worker 取：协议要求输入与 Ping 用同一个时钟，主线程与 Worker
  // 是两个 realm，各自的 performance.now() 起点不同。
  conn?.sendInput(events)
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
  const r = canvas.value?.getBoundingClientRect()
  if (!r?.width || !r.height) return null
  return {
    x: Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width)),
    y: Math.min(1, Math.max(0, (ev.clientY - r.top) / r.height)),
  }
}

// 浏览器与协议对鼠标键的编号不同：中键在浏览器是 1、协议里是 2。
const webButton: Record<number, number> = { 0: 0, 2: 1, 1: 2, 3: 3, 4: 4 }

// 触摸模式：浏览器 pointerId → 协议的触摸点 id（0..9，与 MAX_TOUCH_POINTS 一致）。
const touches = new Map<number, { id: number; x: number; y: number }>()
function touchFor(pid: number, p: { x: number; y: number }): number | null {
  const old = touches.get(pid)
  if (old) return old.id
  if (touches.size >= 10) return null
  const used = new Set(Array.from(touches.values(), (t) => t.id))
  let id = 0
  while (id < 10 && used.has(id)) id++
  if (id >= 10) return null
  touches.set(pid, { id, ...p })
  return id
}

/** 失焦、切模式、断开时松开还没抬起的触摸点，免得被控端留下按着的点。 */
function releaseTouches(phase: 'up' | 'cancel' = 'cancel') {
  if (!touches.size) return
  for (const t of touches.values()) push({ kind: 'touch', id: t.id, phase, x: t.x, y: t.y })
  touches.clear()
}

// ---- 触屏「指针」模式：手指当触控板 ---------------------------------------
// 与普通模式同一套手感：相对位移 + 自绘光标 + 单击/双击拖拽/长按右键/双指滚动。
// 只在触屏的 pointer 模式生效；鼠标和原生 Touch 模式仍走各自的分支。
const POINTER_GAIN = 1.5      // 手指移动 1 CSS 像素带动指针移动多少 CSS 像素
const TAP_SLOP = 10           // 超过这个位移就不算点击
const LONG_PRESS_MS = 520     // 长按算右键
const DOUBLE_TAP_MS = 320     // 两次按下间隔小于这个值算双击
const DOUBLE_CLICK_WINDOW = 560

const vpointer = { x: 0.5, y: 0.5 } // 虚拟指针位置，归一化 0..1
const fingerPts = new Map<number, { x: number; y: number }>() // 触屏 pointerId → CSS 坐标
type TouchGesture = {
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
let gesture: TouchGesture | null = null
let scrolling = false
let scrollAccum = 0
let scrollLastY = 0
let lastTapAt = 0
let lastDownAt = 0

function drawVirtualCursor() {
  const c = canvas.value
  const stageEl = stage.value
  if (!c || !stageEl) return
  const r = c.getBoundingClientRect()
  const sr = stageEl.getBoundingClientRect()
  if (!r.width || !r.height) return
  placeCursor(r.left - sr.left + vpointer.x * r.width, r.top - sr.top + vpointer.y * r.height)
}

/** 手指位移换成归一化增量，保留小数，慢速拖动不会被取整吃掉。 */
function moveVirtualBy(dx: number, dy: number) {
  const r = canvas.value?.getBoundingClientRect()
  if (!r?.width || !r.height) return
  if (cursorMode.value === 0) {
    // 游戏里被控端藏了光标，跟鼠标路径一样改发相对位移。
    const mx = Math.round(dx * POINTER_GAIN)
    const my = Math.round(dy * POINTER_GAIN)
    if (mx || my) push({ kind: 'delta', dx: mx, dy: my })
    return
  }
  vpointer.x = Math.max(0, Math.min(1, vpointer.x + (dx * POINTER_GAIN) / r.width))
  vpointer.y = Math.max(0, Math.min(1, vpointer.y + (dy * POINTER_GAIN) / r.height))
  pushMove({ kind: 'move', x: vpointer.x, y: vpointer.y })
  requestAnimationFrame(drawVirtualCursor)
}

function syncVirtualPointer() {
  // 触控板模式下手指位置与指针位置无关，按键前必须把虚拟指针同步过去。
  // 游戏里被控端藏了光标，没有绝对坐标可同步，这里跳过。
  if (cursorMode.value !== 0) pushMove({ kind: 'move', x: vpointer.x, y: vpointer.y })
}

function clickAtPointer(button: number) {
  syncVirtualPointer()
  push({ kind: 'button', button, down: true })
  push({ kind: 'button', button, down: false })
}

function startHold(g: TouchGesture) {
  if (g.holding) return
  g.holding = true
  syncVirtualPointer()
  push({ kind: 'button', button: 0, down: true })
}

function releaseHold(g: TouchGesture) {
  if (!g.holding) return
  g.holding = false
  push({ kind: 'button', button: 0, down: false })
}

function clearGestureTimers(g: TouchGesture) {
  if (g.longTimer) window.clearTimeout(g.longTimer)
  if (g.holdTimer) window.clearTimeout(g.holdTimer)
  g.longTimer = 0
  g.holdTimer = 0
}

// 第二根手指落下就进入滚动，同时取消单指手势，免得顺手点出一次左键。
function beginScroll() {
  if (gesture) {
    clearGestureTimers(gesture)
    releaseHold(gesture)
    gesture = null
  }
  const pts = [...fingerPts.values()]
  if (pts.length < 2) return
  scrolling = true
  scrollAccum = 0
  scrollLastY = (pts[0].y + pts[1].y) / 2
}

function updateScroll() {
  const pts = [...fingerPts.values()]
  if (pts.length < 2) return
  const y = (pts[0].y + pts[1].y) / 2
  scrollAccum += y - scrollLastY
  scrollLastY = y
  if (Math.abs(scrollAccum) < 6) return
  // 60 CSS 像素一格，折算成协议的滚轮单位（一格 120）。
  const amount = Math.max(-2400, Math.min(2400, Math.round(-scrollAccum * 2)))
  scrollAccum = 0
  if (amount) push({ kind: 'wheel', dx: 0, dy: amount })
}

function isTouchPointer(ev: PointerEvent) {
  return ev.pointerType === 'touch' && touchDevice && inputMode.value === 'pointer'
}

/** 切模式、失焦、断开时收干净：定时器、按住的左键、滚动状态。 */
function releaseGesture() {
  if (gesture) {
    clearGestureTimers(gesture)
    releaseHold(gesture)
    gesture = null
  }
  scrolling = false
  fingerPts.clear()
  lastTapAt = 0
  lastDownAt = 0
}

// 首帧、切模式、光标可见性变化都会让虚拟光标出现或消失，出现后立刻摆到位。
watch(showVirtualCursor, (shown) => { if (shown) nextTick(drawVirtualCursor) })

function onPointerDown(ev: PointerEvent) {
  if (pendingRemote) void writeLocalClipboard(pendingRemote)
  canvas.value?.setPointerCapture?.(ev.pointerId)
  if (isTouchPointer(ev)) {
    ev.preventDefault()
    // 焦点给画布而不是隐藏输入框：手机别弹软键盘，桌面键盘照常由 window 接。
    // 但键盘已经弹着的时候别把焦点抢回来 —— 一抢软键盘就收起来，正在打的字就断了。
    if (document.activeElement !== ime.value) canvas.value?.focus({ preventScroll: true })
    fingerPts.set(ev.pointerId, { x: ev.clientX, y: ev.clientY })
    if (fingerPts.size >= 2) { beginScroll(); return }
    const now = Date.now()
    const second = now - lastTapAt < DOUBLE_TAP_MS
    const g: TouchGesture = {
      id: ev.pointerId,
      startX: ev.clientX, startY: ev.clientY,
      lastX: ev.clientX, lastY: ev.clientY,
      downAt: now,
      moved: false, holding: false, second, rightFired: false,
      longTimer: 0, holdTimer: 0,
    }
    gesture = g
    if (second) {
      // 双击后按住 = 拖拽；按下推迟到双击窗口之外，否则被远端合并成一次双击。
      const delay = Math.max(90, DOUBLE_CLICK_WINDOW - (now - lastDownAt))
      g.holdTimer = window.setTimeout(() => { if (gesture === g) startHold(g) }, delay)
    } else {
      lastDownAt = now
      g.longTimer = window.setTimeout(() => {
        if (gesture !== g || g.moved) return
        g.rightFired = true
        clickAtPointer(webButton[2])
        navigator.vibrate?.(14)
      }, LONG_PRESS_MS)
    }
    requestAnimationFrame(drawVirtualCursor)
    return
  }
  if (inputMode.value === 'touch') {
    const p = point(ev)
    if (p) {
      const id = touchFor(ev.pointerId, p)
      if (id !== null) {
        push({ kind: 'touch', id, phase: 'down', x: p.x, y: p.y })
        ev.preventDefault()
      }
    }
    return
  }
  // 文本模式才需要输入代理；手指点画面时别聚焦它，否则手机会弹软键盘。
  // pointerdown 被 preventDefault 了，浏览器不会自己改焦点，这里得显式聚焦画布，
  // 否则焦点还留在面板按钮上，onKey 会把按键让给按钮。
  if (keyMode.value === 'text' && ev.pointerType !== 'touch') focusIme(ev)
  else canvas.value?.focus({ preventScroll: true })
  // 被控端藏了光标（游戏）时只发相对位移：不锁定指针的话，鼠标到窗口边缘
  // 就停住，转视角会卡在边界上。锁定后浏览器不再夹住光标。
  if (cursorMode.value === 0 && document.pointerLockElement !== canvas.value) {
    canvas.value?.requestPointerLock?.()
  }
  const p = point(ev)
  if (p && cursorMode.value !== 0) pushMove({ kind: 'move', x: p.x, y: p.y })
  const b = webButton[ev.button]
  if (b !== undefined) {
    push({ kind: 'button', button: b, down: true })
    ev.preventDefault()
  }
}

function onPointerUp(ev: PointerEvent) {
  if (isTouchPointer(ev)) {
    fingerPts.delete(ev.pointerId)
    if (scrolling) {
      if (fingerPts.size < 2) scrolling = false
      return
    }
    const g = gesture
    if (!g || g.id !== ev.pointerId) return
    clearGestureTimers(g)
    gesture = null
    const wasHolding = g.holding
    releaseHold(g)
    if (!g.moved && !g.rightFired && !wasHolding) {
      clickAtPointer(0)
      lastTapAt = Date.now()
      lastDownAt = g.downAt
    }
    try { canvas.value?.releasePointerCapture?.(ev.pointerId) } catch { /* 没捕获过 */ }
    return
  }
  if (inputMode.value === 'touch') {
    const t = touches.get(ev.pointerId)
    if (t) {
      push({ kind: 'touch', id: t.id, phase: 'up', x: t.x, y: t.y })
      touches.delete(ev.pointerId)
    }
  } else {
    const b = webButton[ev.button]
    if (b !== undefined) push({ kind: 'button', button: b, down: false })
  }
  try {
    canvas.value?.releasePointerCapture?.(ev.pointerId)
  } catch {
    /* 没捕获过 */
  }
}

function onPointerCancel(ev: PointerEvent) {
  if (isTouchPointer(ev)) {
    fingerPts.delete(ev.pointerId)
    if (fingerPts.size < 2) scrolling = false
    const g = gesture
    if (g && g.id === ev.pointerId) {
      clearGestureTimers(g)
      releaseHold(g)
      gesture = null
    }
    return
  }
  const t = touches.get(ev.pointerId)
  if (!t) return
  push({ kind: 'touch', id: t.id, phase: 'cancel', x: t.x, y: t.y })
  touches.delete(ev.pointerId)
}

function onPointerMove(ev: PointerEvent) {
  if (isTouchPointer(ev)) {
    const pt = fingerPts.get(ev.pointerId)
    if (!pt) return
    pt.x = ev.clientX
    pt.y = ev.clientY
    ev.preventDefault()
    if (scrolling) { updateScroll(); return }
    const g = gesture
    if (!g || g.id !== ev.pointerId) return
    const dx = ev.clientX - g.lastX
    const dy = ev.clientY - g.lastY
    g.lastX = ev.clientX
    g.lastY = ev.clientY
    if (!g.moved) {
      if (Math.hypot(ev.clientX - g.startX, ev.clientY - g.startY) < TAP_SLOP) return
      g.moved = true
      // 移动了就不再是长按，右键计时作废。
      if (g.longTimer) { window.clearTimeout(g.longTimer); g.longTimer = 0 }
    }
    moveVirtualBy(dx, dy)
    // 双击的第二下划过抖动阈值后立刻按下，别等计时器，否则会拖错目标。
    if (g.second && !g.holding) {
      if (g.holdTimer) { window.clearTimeout(g.holdTimer); g.holdTimer = 0 }
      startHold(g)
    }
    return
  }
  if (inputMode.value === 'touch') {
    const t = touches.get(ev.pointerId)
    const p = point(ev)
    if (!t || !p) return
    t.x = p.x
    t.y = p.y
    push({ kind: 'touch', id: t.id, phase: 'move', x: p.x, y: p.y })
    ev.preventDefault()
    return
  }
  if (cursorMode.value === 0) {
    // 被控端把光标藏起来了（游戏里转视角）：改发相对移动。
    const dx = Math.round(ev.movementX)
    const dy = Math.round(ev.movementY)
    if (dx || dy) push({ kind: 'delta', dx, dy })
    return
  }
  const p = point(ev)
  if (p) pushMove({ kind: 'move', x: p.x, y: p.y })
  // 桌面收到远端形状后自绘光标，跟着系统指针走（触屏的虚拟指针走 drawVirtualCursor）。
  if (!touchDevice && activeShape.value) {
    const sr = stage.value?.getBoundingClientRect()
    if (sr) scheduleCursor(ev.clientX - sr.left, ev.clientY - sr.top)
  }
}

function onPointerEnter(ev: PointerEvent) {
  cursorInside.value = true
  if (activeShape.value && !touchDevice) {
    const sr = stage.value?.getBoundingClientRect()
    if (sr) placeCursor(ev.clientX - sr.left, ev.clientY - sr.top)
  }
}

function onPointerLeave() {
  // 离开画布时收起自绘光标，让系统箭头接管（触屏没有系统光标，不用管）。
  cursorInside.value = false
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
  // 物理键模式下连字母数字都走 Key，给读扫描码的程序（游戏）用。
  if (keyMode.value === 'physical') return true
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
  // 输入法组字期间：文本模式交给输入法；物理键模式严格不送中文，直接吃掉。
  if (ev.isComposing) {
    if (keyMode.value === 'physical') ev.preventDefault()
    return
  }
  // 刷新、全屏、开发者工具交还给浏览器。
  if (ev.key === 'F5' || ev.key === 'F11' || ev.key === 'F12') return
  // Chrome 用 Process / Unidentified 表示输入法接管的键。
  if (ev.key === 'Process' || ev.key === 'Unidentified') {
    if (keyMode.value === 'physical') ev.preventDefault()
    return
  }

  // Ctrl+V（macOS 上是 Cmd+V）：不直接发物理键，先由 paste 事件把本地剪贴板
  // 推给被控端，再让它粘贴。否则被控端粘的是它自己的旧剪贴板。
  //
  // 但 paste 只有焦点在可编辑元素上才会派发。物理键模式的焦点在 canvas 上，
  // 浏览器不会派发 paste —— 这就是「物理键模式按 Ctrl+V 没反应」的原因。
  // 这种情况下自己读剪贴板；文本模式走原来的 paste 事件，不重复读。
  if ((ev.ctrlKey || ev.metaKey) && !ev.altKey && ev.code === 'KeyV') {
    const t = ev.target as HTMLElement | null
    const editable = t?.tagName === 'TEXTAREA' || t?.tagName === 'INPUT' || t?.isContentEditable
    if (down && !editable) {
      ev.preventDefault()
      void pasteFromClipboard()
    }
    return
  }

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

/**
 * 把输入代理挪到指针处（输入法候选框跟着走）并聚焦。
 *
 * 已经在焦点上时也要重新聚焦一次：安卓和部分平板上用软键盘的返回键收起键盘，
 * 只是把键盘关掉，焦点仍留在输入框里。这时再调 focus()，浏览器认为「焦点没变」，
 * 不会弹键盘 —— 这就是「有时候点了没反应、键盘不出来」的根因。先 blur 再 focus，
 * 浏览器才会当成一次新的聚焦。
 */
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
  if (document.activeElement === el) el.blur()
  el.focus({ preventScroll: true })
  // 安卓 Chrome 提供显式的虚拟键盘接口，focus 之后补一刀成功率更高。
  const vk = (navigator as Navigator & { virtualKeyboard?: { show?: () => void } }).virtualKeyboard
  if (vk?.show) {
    try { vk.show() } catch { /* 不支持就算了，靠 focus 本身 */ }
  }
}

/** 把焦点还给画面。面板按钮点完（或用键盘选完）还能继续输入。 */
function refocus() {
  if (inputMode.value !== 'pointer' || keyMode.value !== 'text') {
    canvas.value?.focus({ preventScroll: true })
    return
  }
  // 触屏上 focusIme 会顺手把软键盘弹出来，点一下「画质」就弹键盘太吵；
  // 但键盘已经开着时要把焦点留在输入框上，否则改个设置键盘就被收走了。
  if (touchDevice && !keyboardUp.value) {
    canvas.value?.focus({ preventScroll: true })
    return
  }
  // 已经聚焦就不要再折腾：focusIme 的 blur+focus 会让软键盘先收再弹，闪一下。
  if (document.activeElement === ime.value) return
  focusIme()
}

/** 上屏的文本（含输入法、粘贴）走 ControllerMsg 的 Text，交给被控端按 Unicode 注入。 */
function onImeInput(ev: Event) {
  const el = ime.value
  if (!el) return
  // 物理键模式下没有 Text 这条路，输入法上屏的内容一律丢掉。
  if (keyMode.value === 'physical') {
    el.value = ''
    return
  }
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
    if (keyMode.value === 'physical') {
      el.value = ''
      return
    }
    const text = el.value
    if (!text) return
    el.value = ''
    push({ kind: 'text', text })
  })
}

function onImeBlur() {
  keyboardUp.value = false
  if (ime.value) ime.value.value = ''
}

// ---- 剪贴板 ---------------------------------------------------------------
//
// 被控端复制之后自动推到本地；本地粘贴时先把内容推过去再让被控端粘贴。
// 不做「本地剪贴板一变就推」，那样要么轮询要权限，要么两头来回推。

/** 上一次从被控端收到的文本，与收到的时刻。 */
let lastRemote = ''
let lastRemoteAt = 0
/** 页面没有焦点时写入本地剪贴板会失败，先存着，下次点击画面再试。 */
let pendingRemote = ''

async function writeLocalClipboard(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    pendingRemote = ''
  } catch {
    pendingRemote = text
  }
}

/**
 * 被控端剪贴板变了。
 *
 * 去重只能按「短时间内内容相同」判：之前是「文本等于上次远端文本就丢」，
 * 于是本地把内容改成别的之后，在远端再复制一次同样的内容就再也同步不过来。
 * 同一条通知重复送达只可能连着来，1.5 秒的窗口足够吃掉重复而不误伤。
 */
function onRemoteClipboard(text: string) {
  if (!text) return
  const now = Date.now()
  if (text === lastRemote && now - lastRemoteAt < 1500) return
  lastRemote = text
  lastRemoteAt = now
  if (document.hasFocus()) void writeLocalClipboard(text)
  else pendingRemote = text
}

/**
 * 粘贴（Ctrl/Cmd+V）。
 *
 * 监听挂在 window 上而不是隐藏的输入框上：物理键模式与触屏模式下指针按下
 * 时焦点给的是 canvas，paste 事件落在 canvas / body 上，只挂 textarea 就永远
 * 收不到 —— 表现为这两种模式下 Ctrl+V 既不发按键，也不推剪贴板。
 */
function onPaste(ev: ClipboardEvent) {
  if (state.value !== 'ready') return
  const text = ev.clipboardData?.getData('text/plain') || ''
  if (!text) return
  // 不让它落进隐藏的输入框（否则会当成一次 Text 输入又发一遍）。
  ev.preventDefault()
  // 超过网关的单条上限会被截断：说一声，别让人以为粘丢了半截。
  if (conn?.sendPaste(text)) {
    setBanner('粘贴内容超过单条上限（约 1.5 MB），已截断。')
  }
}

/**
 * 直接读系统剪贴板。
 *
 * 物理键模式（以及触屏）下焦点在 canvas 上，浏览器不会派发 paste，只能自己读。
 * readText 需要安全上下文（HTTPS，本站就是）和一次用户手势（keydown 算），
 * 但权限被拒时只能提示；Safari 会弹「允许粘贴」。
 */
async function pasteFromClipboard() {
  if (state.value !== 'ready') return
  const read = navigator.clipboard?.readText?.bind(navigator.clipboard)
  if (!read) {
    setBanner('这个浏览器不支持读取剪贴板，请切到「文本」模式再按 Ctrl+V。')
    return
  }
  try {
    const text = await read()
    if (!text) return
    if (conn?.sendPaste(text)) {
      setBanner('粘贴内容超过单条上限（约 1.5 MB），已截断。')
    }
  } catch {
    // 多半是权限被拒（或页面不在安全上下文）。别静默失败，否则又像「按了没反应」。
    setBanner('浏览器拒绝了剪贴板权限：允许后重按 Ctrl+V，或切到「文本」模式粘贴。')
  }
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
  releaseTouches()
  releaseGesture()
}

function onVisibility() {
  if (document.hidden) {
    releaseAll()
    releaseTouches()
    releaseGesture()
  }
}

function onKeyDown(ev: KeyboardEvent) {
  onKey(ev, true)
}

function onKeyUp(ev: KeyboardEvent) {
  onKey(ev, false)
}

let framePending: VideoFrame | null = null
let frameRaf = 0
let ctx2d: CanvasRenderingContext2D | null = null

function onVideo(frame: VideoFrame) {
  if (!canvas.value) {
    frame.close()
    return
  }
  // 主线程忙的时候 worker 的消息会排队。只保留最新一帧：旧帧不画也不 close
  // 会一直占着显存，而且排队越久延迟越高、永远追不回来。
  if (framePending) framePending.close()
  framePending = frame
  if (!frameRaf) frameRaf = requestAnimationFrame(drawFrame)
}

function drawFrame() {
  frameRaf = 0
  const frame = framePending
  framePending = null
  if (!frame) return
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
  // getContext 每帧调用虽然返回同一个对象，但要走一遍参数校验；缓存起来。
  if (!ctx2d) ctx2d = c.getContext('2d', { alpha: false })
  if (ctx2d) {
    try {
      // VideoFrame 是 CanvasImageSource，TS 的旧 lib 里还没列进去。
      ctx2d.drawImage(frame as unknown as CanvasImageSource, 0, 0)
    } catch (e) {
      console.warn('[perf] 画一帧失败', e)
    }
  }
  frame.close()
  if (!hasFrame.value) {
    hasFrame.value = true
    window.clearTimeout(firstFrameTimer)
    firstFrameStuck.value = false
  }
}

/**
 * 收到一个光标形状：先按槽位缓存，代际大的才覆盖（图像可能比 Cursor 引用先到）。
 * 只有当前引用的槽位+代际都对上，才立刻切换显示。
 */
function onCursorImage(ev: Extract<HostEvent, { type: 'cursorImage' }>) {
  if (ev.slot < 0 || ev.generation < 0 || ev.slot >= 32) return
  const prev = shapeCache.get(ev.slot)
  if (prev && prev.generation >= ev.generation) return
  const url = shapeToUrl(ev.width, ev.height, ev.rgba)
  if (!url) return
  const shape: RemoteShape = {
    slot: ev.slot, generation: ev.generation, width: ev.width, height: ev.height,
    hotX: ev.hotX, hotY: ev.hotY, url,
  }
  shapeCache.set(ev.slot, shape)
  if (ev.slot === wantedSlot && ev.generation === wantedGen) {
    activeShape.value = shape
    nextTick(() => placeCursor(cursorXY.x, cursorXY.y))
  }
}

function onEvent(ev: HostEvent) {
  if (ev.type === 'hello') {
    hostHostname.value = ev.hostname
    displays.value = ev.displays
    currentDisplay.value = ev.current
    // 被控端没声明 touch 时，面板里的「触摸」选项保持不可选。
    hostTouch.value = ev.touch
    if (inputMode.value === 'touch' && !ev.touch) {
      releaseTouches()
      releaseGesture()
      inputMode.value = 'pointer'
      try { localStorage.setItem('deskgw.perfInputMode', 'pointer') } catch { /* 忽略 */ }
    }
  } else if (ev.type === 'displays') {
    // 被控端换了分辨率、插拔显示器、切换主屏都会发这一条。
    displays.value = ev.displays
    currentDisplay.value = ev.current
  } else if (ev.type === 'encoder') {
    encoderName.value = `${ev.name}${ev.hardware ? '（硬件）' : ''}`
  } else if (ev.type === 'cursor') {
    // 1 = 显示着，用本地光标；2 = 被控端已经把光标画进画面，藏本地光标；
    // 0 = 隐藏，藏本地光标并改发相对移动。
    const v = ev.visibility
    cursorMode.value = v === 1 ? 1 : v === 2 ? 2 : 0
    // Cursor 带的形状引用才是当前该用哪个；-1 表示没有形状，退回系统箭头。
    wantedSlot = ev.slot
    wantedGen = ev.generation
    const hit = wantedSlot >= 0 ? shapeCache.get(wantedSlot) : null
    const next = hit && hit.generation === wantedGen ? hit : null
    if (next !== activeShape.value) {
      activeShape.value = next
      // 形状刚到时可能还没走过 pointermove，按上一次落点补绘一次。
      nextTick(() => placeCursor(cursorXY.x, cursorXY.y))
    }
  } else if (ev.type === 'cursorImage') {
    onCursorImage(ev)
  } else if (ev.type === 'clipboard') {
    onRemoteClipboard(ev.text)
  } else if (ev.type === 'notice') {
    if (!ev.recovered && ev.text) setBanner(ev.text)
    else if (ev.recovered) banner.value = ''
  }
}

function connect() {
  const cur = perfSession.current
  if (!cur) return
  // 上一次失败留下的 kind/文案不能带到这一次，否则会显示相反的提示。
  errorKind.value = ''
  errorText.value = ''
  endedReason.value = ''
  state.value = 'connecting'
  conn = connectPerf(cur.wsPath, cur.hostId, {
    onReady: (r) => {
      ready.value = r
      state.value = 'ready'
      // 握手用的是被控端默认画质；连上后按界面选的档位补发一次（client 会在 Worker 就绪后发）。
      conn?.sendSettings(currentQuality())
      // 触屏上不要主动聚焦输入框：没有用户手势，安卓会「聚焦了但不弹键盘」，
      // 焦点留在输入框里之后反而更难弹出来。手机/平板要打字按面板里的「键盘」。
      if (!touchDevice && inputMode.value === 'pointer' && keyMode.value === 'text') nextTick(() => focusIme())
      // 锁屏、UAC 授权框、采集没起来时画面就是不来。没有时限的话界面一直停在
      // 「正在等画面」，用户不知道该等还是该重连。
      window.clearTimeout(firstFrameTimer)
      firstFrameStuck.value = false
      firstFrameTimer = window.setTimeout(() => {
        if (!hasFrame.value && state.value === 'ready') firstFrameStuck.value = true
      }, FIRST_FRAME_WAIT_MS)
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
  }, displayIndex.value)
}

/** 换显示器：协议只认握手时给的 view，改完重连一次才生效。 */
async function switchDisplay(i: number) {
  if (i === displayIndex.value || switchingDisplay.value) return
  displayIndex.value = i
  switchingDisplay.value = true
  setBanner(`正在切换到显示器 ${i + 1}：需要重连一次会话。`)
  try {
    await reconnect()
  } finally {
    switchingDisplay.value = false
  }
}

function shutdown() {
  window.clearTimeout(bannerTimer)
  window.clearTimeout(firstFrameTimer)
  firstFrameStuck.value = false
  keyboardUp.value = false
  // 断开时把软键盘一起收掉，别留一个没有会话的键盘。
  ime.value?.blur()
  displays.value = []
  currentDisplay.value = 0
  // 先把按下的键、触摸点松开再断，免得被控端留下按住的状态。
  releaseAll()
  releaseTouches()
  releaseGesture()
  closeMenu()
  if (raf) {
    cancelAnimationFrame(raf)
    raf = 0
  }
  if (frameRaf) {
    cancelAnimationFrame(frameRaf)
    frameRaf = 0
  }
  if (cursorRaf) {
    cancelAnimationFrame(cursorRaf)
    cursorRaf = 0
  }
  if (framePending) {
    framePending.close()
    framePending = null
  }
  ctx2d = null
  conn?.close()
  conn = null
  pending = []
  // 槽位与代际只在本次会话有效，重连时不能拿旧形状去套新引用。
  shapeCache.clear()
  activeShape.value = null
  wantedSlot = -1
  wantedGen = -1
  cursorMode.value = 1
  cursorInside.value = true
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

// 重连要换一张新票据：旧票据一次性，失败的那次已经用掉了。和 RDP 模式一致。
async function reconnect() {
  const cur = perfSession.current
  if (reconnecting.value || !cur) return
  reconnecting.value = true
  shutdown()
  errorKind.value = ''
  errorText.value = ''
  endedReason.value = ''
  ready.value = null
  hasFrame.value = false
  frameSize.w = 0
  frameSize.h = 0
  encoderName.value = ''
  hostHostname.value = ''
  Object.assign(stats, { fps: 0, kbps: 0, bytes: 0, dropped: 0, dropRate: 0, rtt: 0, errors: 0 })
  state.value = 'connecting'
  try {
    const t = await post<{ session_id: number; ws_path: string }>('/perf/ticket', { host_id: cur.hostId })
    // 等待期间用户可能已经离开页面。
    if (!perfSession.current) return
    perfSession.current.sessionId = t.session_id
    perfSession.current.wsPath = t.ws_path
    connect()
  } catch (e: any) {
    // 票据接口的错误码与 ws 的 error.kind 是同一套，直接拿来选提示文案，
    // 否则 limit / disabled 这些写好的提示永远走不到。
    errorKind.value = typeof e?.code === 'string' ? e.code : 'serverError'
    errorText.value = '重连失败：' + (e?.message || '无法签发票据')
    state.value = 'error'
  } finally {
    reconnecting.value = false
  }
}

onMounted(() => {
  loadFabPos()
  nextTick(() => {
    measurePage()
    if (!touchDevice && inputMode.value === 'pointer' && keyMode.value === 'text') focusIme()
  })
  window.addEventListener('keydown', onKeyDown)
  window.addEventListener('keyup', onKeyUp)
  window.addEventListener('blur', onBlur)
  window.addEventListener('resize', onWindowResize)
  // 挂在 window 上：物理键与触屏模式下焦点在 canvas 上，paste 事件落在画布
  // 或 body 上再冒泡上来，只挂隐藏输入框收不到。
  window.addEventListener('paste', onPaste)
  document.addEventListener('visibilitychange', onVisibility)
  document.addEventListener('pointerdown', onDocDown)
  // 原生全屏退出走的是浏览器（Esc / 系统手势），状态得从事件里同步回来。
  document.addEventListener('fullscreenchange', onFullscreenChange)
  // 软键盘弹收只是改可视区高度，不会触发 window.resize。
  const vv = window.visualViewport
  vv?.addEventListener('resize', onViewportResize)
  vv?.addEventListener('scroll', onViewportResize)
  connect()
})

onBeforeUnmount(() => {
  window.removeEventListener('keydown', onKeyDown)
  window.removeEventListener('keyup', onKeyUp)
  window.removeEventListener('blur', onBlur)
  window.removeEventListener('resize', onWindowResize)
  window.removeEventListener('paste', onPaste)
  document.removeEventListener('visibilitychange', onVisibility)
  document.removeEventListener('pointerdown', onDocDown)
  document.removeEventListener('fullscreenchange', onFullscreenChange)
  const vv = window.visualViewport
  vv?.removeEventListener('resize', onViewportResize)
  vv?.removeEventListener('scroll', onViewportResize)
  shutdown()
  // 浏览器后退离开时不会走 leave()，票据留在内存里会被下一次进入误用。
  closePerf()
})
</script>

<style scoped>
.perf-page {
  position: relative;
  display: flex;
  flex-direction: column;
  /* 性能模式隐藏了顶部状态条，画面直接吃满视口。dvh 让手机地址栏收起时不跳。 */
  height: 100vh;
  height: 100dvh;
  min-height: 0;
  background: #0f1115;
}
/* 浏览器不给元素全屏时的退路：铺满可视区，盖住页面其它部分。 */
.perf-page.immersive { position: fixed; inset: 0; z-index: 9999; }

.exit-fs { position: absolute; top: 10px; left: 50%; transform: translateX(-50%); z-index: 45;
  padding: 5px 12px; border-radius: 999px; font-size: 12px;
  background: rgba(24, 27, 33, .86); border: 1px solid rgba(255, 255, 255, .16);
  color: #e5e7eb; -webkit-backdrop-filter: blur(10px); backdrop-filter: blur(10px); }
.exit-fs:hover { background: rgba(38, 43, 52, .94); }

/* ---------- 悬浮按钮与面板（与普通模式同一套路） ---------- */
.fab { position: absolute; left: 0; top: 0; width: 46px; height: 46px; padding: 0;
  border-radius: 50%; display: grid; place-items: center; z-index: 40;
  border: 1px solid rgba(255, 255, 255, .14);
  background: #2f3540; color: #fff; cursor: pointer;
  touch-action: none; -webkit-user-select: none; user-select: none;
  -webkit-tap-highlight-color: transparent; -webkit-touch-callout: none;
  box-shadow: 0 8px 22px rgba(0, 0, 0, .5);
  transition: transform .18s ease, box-shadow .16s ease; }
.fab:hover { background: #3a4250; box-shadow: 0 12px 26px rgba(0, 0, 0, .58); }
.fab.on { border-color: rgba(59, 130, 246, .6); }
.fab.drag { transition: none; cursor: grabbing; filter: brightness(1.12); }
.fab .mark { font-size: 12px; letter-spacing: .04em; font-weight: 600; }
.fab .live { position: absolute; bottom: 1px; right: 1px; width: 10px; height: 10px;
  border-radius: 50%; background: #22c55e; border: 2px solid #2f3540; }

.panel { position: absolute; z-index: 39;
  display: flex; flex-direction: column; overflow-y: auto;
  background: rgba(24, 27, 33, .96);
  -webkit-backdrop-filter: blur(18px); backdrop-filter: blur(18px);
  border: 1px solid rgba(255, 255, 255, .1); border-radius: 12px;
  box-shadow: 0 20px 48px rgba(0, 0, 0, .6);
  color: #e5e7eb; opacity: 0; transform: scale(.92) translateY(8px); pointer-events: none;
  transition: opacity .13s ease, transform .13s ease; }
.panel.open { opacity: 1; transform: none; pointer-events: auto; }
.p-top { display: flex; align-items: center; gap: 8px; padding: 11px 12px 9px;
  border-bottom: 1px solid rgba(255, 255, 255, .07); flex: none; }
.p-cap { font-size: 12px; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.p-ok { margin-left: auto; font-size: 11px; color: #4ade80; border: 1px solid rgba(74, 222, 128, .35);
  border-radius: 4px; padding: 1px 5px; flex: none; }
.p-x { width: 24px; height: 24px; border: 0; padding: 0; background: transparent;
  color: #98a1b0; cursor: pointer; font-size: 16px; line-height: 1; flex: none; }
.p-meta { padding: 10px 12px 4px; font-size: 12px; line-height: 1.7; color: #9ca3af;
  font-variant-numeric: tabular-nums; flex: none; }
.p-meta b { color: #e5e7eb; letter-spacing: .5px; }
.p-sub { color: #8f9aaa; font-size: 11px; }
/* 顶栏隐藏后，用户名与「改密码 / 退出」挪到这里。 */
.p-account { display: flex; align-items: center; gap: 6px; padding: 0 12px 4px;
  font-size: 12px; color: #e5e7eb; flex: none; }
.p-account .p-nm { flex: 1; min-width: 0; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
.p-account .p-role { margin-left: 6px; font-style: normal; font-size: 10px; color: #93c5fd;
  border: 1px solid rgba(147, 197, 253, .35); border-radius: 4px; padding: 0 4px; }
.p-account .p-link { flex: none; border: 0; background: transparent; color: #98a1b0;
  font-size: 12px; padding: 4px 2px; }
.p-account .p-link:hover { color: #93c5fd; }
.p-div { padding: 8px 12px 6px; font-size: 11px; color: #98a1b0; flex: none; }
.p-note { margin: 6px 12px 0; font-size: 11px; color: #8f9aaa; line-height: 1.6; flex: none; }
.seg { display: grid; grid-template-columns: 1fr 1fr; gap: 4px; margin: 0 12px; padding: 3px;
  background: #16191f; border: 1px solid rgba(255, 255, 255, .08); border-radius: 8px; flex: none; }
/* 画质三档：不加这条会按两列排成 2+1。 */
.seg.seg3 { grid-template-columns: repeat(3, 1fr); }
/* 只有「全屏」一个按钮时（桌面没有软键盘），别留半格空位。 */
.seg.seg1 { grid-template-columns: 1fr; }
/* 显示器按钮：数量不定（常见 2–3 块），按数量摊开，别沿用两列固定。 */
.seg.seg-disp { grid-template-columns: repeat(auto-fit, minmax(48px, 1fr)); margin: 6px 0 0; }
.seg button { border: 0; padding: 6px 0; border-radius: 6px; background: transparent;
  color: #98a1b0; font-size: 12px; }
.seg button.on { background: #2563eb; color: #fff; }
.seg button:hover:not(:disabled):not(.on) { background: rgba(255, 255, 255, .06); }
.seg button:disabled { opacity: .4; cursor: not-allowed; }
/* 面板底部只有一个动作：「返回主机列表」与「断开」原来并排放着，功能重叠；
   返回走页面顶部的导航，这里只留当前状态下真正有用的那一个。 */
.p-foot { display: grid; grid-template-columns: 1fr; gap: 6px;
  padding: 12px 12px 12px; margin-top: auto; flex: none; }
.p-foot button { font-size: 12px; padding: 6px 0; background: #232830;
  border-color: #333a45; color: #e5e7eb; }
.p-foot button:hover:not(:disabled) { background: #2b323c; }
.p-foot button.danger { color: #fca5a5; border-color: rgba(239, 68, 68, .35); }

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
  touch-action: none;
  -webkit-tap-highlight-color: transparent;
}
.stage canvas.idle { opacity: 0; }

/* 触屏指针模式的自绘光标；transform 由手势层按画布缩放比定位。 */
.stage .vcur {
  position: absolute;
  left: 0;
  top: 0;
  width: 12px;
  height: 19px;
  pointer-events: none;
  z-index: 3;
  will-change: transform;
}

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
/* 主按钮要压过上面那条（同特异性，靠后生效）。 */
.overlay-card button.primary { background: #2563eb; border-color: #2563eb; color: #fff; }
.overlay-card button.primary:hover:not(:disabled) { background: #1d4ed8; }
.overlay-card button + button { margin-left: 8px; }

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
