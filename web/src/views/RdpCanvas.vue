<template>
  <div class="rdp-canvas">
    <div class="rc-main">
      <div class="rc-stage" ref="wrap" :class="{ immersive }">
        <canvas ref="canvas"></canvas>
        <button v-if="immersive" class="rc-exit" @click="exitImmersive">退出全屏</button>
        <div v-if="!connected" class="overlay">
          <div class="overlay-card">
            <h3>{{ statusText }}</h3>
            <p class="muted">{{ detail }}</p>
            <div v-if="logs.length" class="logbox">
              <p v-for="(l, i) in logs" :key="i" class="logline">[{{ l.level }}] {{ l.message }}</p>
            </div>
            <div v-if="canReconnect" class="overlay-actions">
              <!-- 指纹变了要给出明确出口，否则只能去清站点数据 -->
              <button v-if="fpMismatch" class="primary" :disabled="reconnecting" @click="trustCert">
                {{ reconnecting ? '重连中…' : '信任新证书并重连' }}
              </button>
              <button :class="{ primary: !fpMismatch }" :disabled="reconnecting" @click="reconnect">
                {{ reconnecting ? '重连中…' : '重新连接' }}
              </button>
              <button v-if="fpMismatch" @click="close">关闭标签</button>
            </div>
          </div>
        </div>
      </div>
      <FilePanel v-if="showFiles && canFile" :session-id="tab.sessionId" :creds="tab.creds" @close="closeFiles" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onActivated, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { connectRdp, describeError, isFingerprintMismatch, isLogonFailure, pickDesktopSize, resolveWsUrl } from '../rdp'
import type { InputMode, RdpSession } from '../rdp'
import { post } from '../api'
import { closeTab, wipeCreds } from '../sessionTabs'
import type { TabInfo } from '../sessionTabs'
import { state } from '../state'
import FilePanel from './FilePanel.vue'

const props = defineProps<{ tab: TabInfo; active: boolean }>()
// 远端尺寸变化要同步到会话页的面板与标签列表，那里是唯一显示分辨率的地方。
const emit = defineEmits<{ (e: 'viewport', size: { w: number; h: number }): void }>()
const wrap = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)
const canFile = computed(() => !!state.user?.allow_file)

const vpWidth = ref(1280)
const vpHeight = ref(720)
const resolution = ref('0')
const connected = ref(false)
const detail = ref('正在建立 RDP 隧道…')
const logs = ref<{ level: string; message: string }[]>([])
const showFiles = ref(false)
// iOS Safari（iPhone）没有网页全屏 API，退化成分页内的沉浸模式。
const immersive = ref(false)
// 连接失败或远端结束后保留标签与内存中的凭据，允许一键重连：
// 之前「已断开」状态从未被赋值，正常退出也显示成「连接失败」，
// 用户只能重新走一遍主机列表 + 输密码。
const canReconnect = ref(false)
const fpMismatch = ref(false)
const reconnecting = ref(false)
let session: RdpSession | null = null
// 自动重试是异步的，期间组件可能已被卸载，落笔前要检查。
let unmounted = false

// 触摸设备才显示指针/触摸切换与键盘按钮。触屏笔记本也满足条件。
const touch = window.matchMedia('(pointer: coarse)').matches || navigator.maxTouchPoints > 0
const MODE_KEY = 'deskgw.inputMode'
function readMode(): InputMode {
  try {
    const v = localStorage.getItem(MODE_KEY)
    if (v === 'touch' || v === 'pointer') return v
  } catch { /* 隐私模式 */ }
  return 'pointer'
}
// 指针模式：手指当触控板，适合点小按钮和拖窗口边框。
const inputMode = ref<InputMode>(readMode())
const keyboardOpen = ref(false)
function setMode(mode: InputMode) {
  if (inputMode.value === mode) return
  inputMode.value = mode
  try { localStorage.setItem(MODE_KEY, mode) } catch { /* 隐私模式 */ }
  session?.setInputMode(mode)
}
function toggleKeyboard() {
  if (!session) return
  if (keyboardOpen.value) session.hideKeyboard()
  else session.showKeyboard()
}

const statusText = computed(() => ({
  connecting: '正在连接', connected: '已连接', disconnected: '已断开', error: '连接失败',
}[props.tab.status]))

function addLog(level: string, message: string) {
  logs.value.push({ level, message })
  if (logs.value.length > 40) logs.value.shift()
}
function fitViewport() {
  const el = wrap.value
  if (!el) return
  // 固定分辨率模式下不跟随容器。
  if (resolution.value !== '0') return
  // 软键盘弹出会把可视高度压掉一半，此时按剩余空间算分辨率会让远端画面缩水。
  if (keyboardOpen.value) return
  // 元素脱离文档或整块隐藏时 clientWidth/Height 是 0。原来会回落到 1280×720，
  // 于是「在主机页缩放窗口 → 已保活的会话被重设成 1280×720」。
  // 量不到尺寸就跳过，等回到工作区 onActivated 再量。
  if (el.clientWidth < 2 || el.clientHeight < 2) return
  // 按物理像素取基准（DPR 封顶 2）；手机再压一道长边上限，避免 wasm 解码跟不上。
  const dpr = Math.min(window.devicePixelRatio || 1, 2)
  const coarse = window.matchMedia('(pointer: coarse)').matches
  const size = pickDesktopSize(
    el.clientWidth * dpr,
    el.clientHeight * dpr,
    coarse ? 1280 : 1920,
  )
  if (size.width === vpWidth.value && size.height === vpHeight.value) return
  vpWidth.value = size.width
  vpHeight.value = size.height
  emit('viewport', { w: size.width, h: size.height })
  if (session) session.resize(size.width, size.height)
}
// 手机地址栏收起、软键盘弹出都会触发 resize，逐次改远端分辨率会拖慢会话，
// 这里合并成一次，只在真正停下后重新协商。
let fitTimer: number | undefined
function scheduleFit() {
  if (fitTimer) window.clearTimeout(fitTimer)
  fitTimer = window.setTimeout(() => { fitTimer = undefined; fitViewport() }, 220)
}
function applyResolution() {
  if (resolution.value === '0') { fitViewport(); session?.focus(); return }
  const [w, h] = resolution.value.split('x').map(Number)
  vpWidth.value = w; vpHeight.value = h
  emit('viewport', { w, h })
  session?.resize(w, h)
  session?.focus()
}
// 面板里的下拉用它改值：直接改 resolution 再计算，避免 v-model 依赖暴露的 ref。
function setResolution(v: string) {
  resolution.value = v
  applyResolution()
}
function toggleFiles() {
  // 文件面板会占掉右侧宽度，关掉后尺寸要重新算一次。
  showFiles.value = !showFiles.value
  if (!showFiles.value) { fitViewport(); session?.focus() }
}
function toggleFullscreen() {
  const el = wrap.value
  if (!el) return
  if (document.fullscreenElement) { document.exitFullscreen(); return }
  if (el.requestFullscreen) {
    el.requestFullscreen().catch(enterImmersive)
    return
  }
  enterImmersive()
}
function enterImmersive() {
  immersive.value = true
  nextTick(() => { fitViewport(); session?.focus() })
}
function exitImmersive() {
  immersive.value = false
  nextTick(() => { fitViewport(); session?.focus() })
}
// 全屏切换后键盘焦点会回到文档，需要重新交给远程桌面；尺寸也要等过渡结束再算。
function onFullscreenChange() {
  window.setTimeout(() => { fitViewport(); session?.focus() }, 260)
}
function sendCtrlAltDel() { session?.sendCtrlAltDel(); session?.focus() }
function closeFiles() { showFiles.value = false; session?.focus() }
function close() {
  session?.shutdown()
  session = null
  connected.value = false
  showFiles.value = false
  closeTab(props.tab.key)
}

// 会话页的悬浮面板通过这个接口操作当前标签。工具栏已从本组件移走，
// 状态仍留在这里：每个标签的会话、输入模式与分辨率都是独立的。
defineExpose({
  touch, canFile, connected, vpWidth, vpHeight, resolution,
  inputMode, keyboardOpen, showFiles,
  setMode, toggleKeyboard, sendCtrlAltDel, setResolution, toggleFiles,
  toggleFullscreen, close,
  // 触摸设备上 focus 是空操作，只有桌面浏览器会把键盘焦点还给远程桌面。
  focus: () => session?.focus(),
})

watch(() => props.active, async (v) => {
  if (v) { await nextTick(); fitViewport(); session?.focus() }
})

interface SessionTicket { session_id: number; ws_path: string }

/** 颜色深度是全局设置，下一次建立连接时生效（wasm 侧在 connect 时读取）。 */
function readColorDepth(): 16 | 32 {
  try {
    return localStorage.getItem('deskgw.rdpDepth') === '16' ? 16 : 32
  } catch { /* 隐私模式 */ }
  return 32
}

async function openSession(): Promise<RdpSession> {
  if (!canvas.value) throw new Error('画布未就绪')
  const creds = props.tab.creds
  return connectRdp({
    wsUrl: resolveWsUrl(props.tab.wsPath),
    destination: props.tab.address,
    fingerprintKey: 'host-' + props.tab.hostId,
    canvas: canvas.value,
    credentials: { username: creds.username, password: creds.password, domain: creds.domain },
    width: vpWidth.value,
    height: vpHeight.value,
    colorDepth: readColorDepth(),
    allowClipboard: state.user?.allow_clipboard !== false,
    inputMode: touch ? inputMode.value : undefined,
    onLog: addLog,
    onKeyboard: (open) => {
      keyboardOpen.value = open
      // 键盘收起后可视高度恢复，再补算一次分辨率（弹出期间是跳过的）。
      if (!open) scheduleFit()
    },
  })
}

// 远端偶发在 NLA 阶段拒绝登录（STATUS_LOGON_FAILURE）。这类拒绝多半是上一次
// 会话没干净退出、账户策略或主机刚唤醒造成的，隔一两秒重试往往就能过。票据是
// 一次性的，重试前必须重新申请，否则网关只会回「连接票据无效」。
const RETRY_DELAY = 2000
async function connectWithRetry(): Promise<RdpSession> {
  try {
    return await openSession()
  } catch (e) {
    if (!isLogonFailure(e)) throw e
    addLog('warn', '远端拒绝了本次登录，2 秒后重试一次…')
    await new Promise<void>((r) => { window.setTimeout(r, RETRY_DELAY) })
    if (unmounted) throw e
    let t: SessionTicket
    try {
      t = await post<SessionTicket>('/sessions', { host_id: props.tab.hostId })
    } catch {
      // 拿不到新票据（例如并发上限）就保持原始错误，别让 429 盖掉真正原因。
      throw e
    }
    props.tab.sessionId = t.session_id
    props.tab.wsPath = t.ws_path
    return openSession()
  }
}

// 建立会话。首次连接与之后的重连走同一条路径。
async function connect() {
  const creds = props.tab.creds
  if (!props.tab.wsPath || !creds.username || !creds.password) {
    props.tab.status = 'error'
    detail.value = '连接信息缺失，请从主机列表重新发起连接'
    return
  }
  props.tab.status = 'connecting'
  detail.value = '正在建立 RDP 隧道…'
  canReconnect.value = false
  fpMismatch.value = false
  try {
    addLog('info', '正在加载 RDP 协议组件…')
    const s = await connectWithRetry()
    // 重试期间用户可能已经关掉标签，别把会话挂在已卸载的组件上。
    if (unmounted) { s.shutdown(); return }
    session = s
    connected.value = true
    props.tab.status = 'connected'
    detail.value = '远程会话已建立'
    session.focus()
    s.terminated.then((reason) => {
      if (session === s) session = null
      connected.value = false
      if (unmounted) return
      // 远端关会话、网络中断都会走到这里。标签留着，凭据也还在内存里。
      props.tab.status = 'disconnected'
      detail.value = '会话已结束：' + reason
      canReconnect.value = true
    })
  } catch (e: unknown) {
    props.tab.status = 'error'
    detail.value = '连接失败：' + (describeError(e) || '未知错误')
    fpMismatch.value = isFingerprintMismatch(e)
    canReconnect.value = true
    addLog('error', detail.value)
  }
}

// 重连要换一张新票据：旧票据是一次性的，而且失败的那次已经收尾了。
async function reconnect() {
  if (reconnecting.value) return
  reconnecting.value = true
  try {
    const t = await post<SessionTicket>('/sessions', { host_id: props.tab.hostId })
    props.tab.sessionId = t.session_id
    props.tab.wsPath = t.ws_path
    logs.value = []
    await connect()
  } catch (e: any) {
    detail.value = '重连失败：' + (e.message || '未知错误')
  } finally {
    reconnecting.value = false
  }
}

// 信任目标机的新证书：清掉本地记录后按 TOFU 重新取指纹。
function trustCert() {
  try { localStorage.removeItem('deskgw.cert.host-' + props.tab.hostId) } catch { /* 隐私模式 */ }
  void reconnect()
}

onMounted(async () => {
  window.addEventListener('resize', scheduleFit)
  document.addEventListener('fullscreenchange', onFullscreenChange)
  await nextTick()
  fitViewport()
  await connect()
})

// SessionView 被 keep-alive 缓存：切到主机页时会 deactivate，容器宽高变成 0，
// 再切回来必须重新量一次，否则仍按离开时的尺寸显示（或停在 1280×720）。
onActivated(() => {
  void nextTick(() => scheduleFit())
})

onBeforeUnmount(() => {
  unmounted = true
  window.removeEventListener('resize', scheduleFit)
  if (fitTimer) window.clearTimeout(fitTimer)
  document.removeEventListener('fullscreenchange', onFullscreenChange)
  session?.shutdown()
  session = null
  wipeCreds(props.tab.creds)
})
</script>

<style scoped>
.rdp-canvas { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.rc-main { display: flex; flex: 1; min-height: 0; }
/* 画布按位图比例尽量铺满，留黑边而不拉伸：远端分辨率与容器比例不一致时不会变形。 */
.rc-stage { flex: 1; position: relative; overflow: hidden; background: #0f1115;
  display: flex; align-items: center; justify-content: center; }
.rc-stage.immersive { position: fixed; inset: 0; z-index: 9999; background: #000; }
canvas { display: block; max-width: 100%; max-height: 100%; width: auto; height: auto;
  outline: none; background: #000; touch-action: none; user-select: none;
  -webkit-user-select: none; -webkit-touch-callout: none; }
.rc-exit { position: absolute; top: 10px; right: 10px; z-index: 4; background: rgba(38,42,51,.82);
  color: #e5e7eb; border: 1px solid #3a3f4b; border-radius: 6px; padding: 6px 12px; font-size: 12px; }
.overlay { position: absolute; inset: 0; z-index: 3; display: grid; place-items: center; background: rgba(15,17,21,.85); }
.overlay-card { width: 420px; max-width: 90%; background: #1b1e24; color: #e5e7eb;
  border: 1px solid #343945; border-radius: 12px; padding: 22px; text-align: center; }
.overlay-card h3 { margin: 0 0 8px; font-size: 17px; }
.overlay-card .muted { color: #9ca3af; font-size: 13px; margin: 0; }
.logbox { background: #101216; border-radius: 8px; padding: 10px; max-height: 160px;
  overflow: auto; text-align: left; margin-top: 12px; }
.logline { margin: 0 0 3px; font: 12px/1.5 ui-monospace, monospace; color: #9ca3af; }
.overlay-actions { display: flex; justify-content: center; gap: 8px; margin-top: 14px; }
.overlay-actions button { padding: 7px 14px; font-size: 13px; }
</style>
