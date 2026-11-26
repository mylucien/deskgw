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
      <canvas ref="canvas" :class="{ idle: !hasFrame }" :style="{ cursor: cursorStyle }"></canvas>

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
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { perfSession, closePerf } from '../perf'
import { connectPerf } from '../perf/client'
import type { PerfConnection, PerfReady, PerfStats } from '../perf/client'
import type { HostEvent } from '../perf/messages'

type State = 'connecting' | 'ready' | 'error' | 'ended'

const router = useRouter()
const stage = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)

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
    // 1 = 显示着，用本地光标；0/2 = 已经画在画面里或者隐藏了。
    cursorStyle.value = ev.visibility === 1 ? 'default' : 'none'
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
  conn?.close()
  conn = null
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

onMounted(connect)
onBeforeUnmount(shutdown)
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
  user-select: none;
  -webkit-user-select: none;
}
.stage canvas.idle { opacity: 0; }

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
