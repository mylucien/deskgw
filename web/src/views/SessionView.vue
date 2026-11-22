<template>
  <div class="session-page">
    <div class="session-bar">
      <div class="session-title">
        <span class="logo">DG</span>
        <span>{{ hostName }}</span>
        <span class="tag" :class="statusClass">{{ statusText }}</span>
      </div>
      <div class="session-tools">
        <button @click="sendCtrlAltDel" :disabled="!session">Ctrl+Alt+Del</button>
        <select v-model="resolution" @change="applyResolution" :disabled="!session" title="分辨率">
          <option value="0">自适应</option>
          <option value="1280x720">1280 × 720</option>
          <option value="1920x1080">1920 × 1080</option>
        </select>
        <button disabled title="文件传输在 M4 提供">文件</button>
        <button @click="toggleFullscreen" :disabled="!session">全屏</button>
        <button class="danger" @click="disconnect">断开</button>
      </div>
    </div>
    <div class="canvas-wrap" ref="wrap">
      <canvas ref="canvas" :width="vpWidth" :height="vpHeight" tabindex="0"></canvas>
      <div v-if="!connected" class="overlay">
        <div class="overlay-card">
          <h3>{{ statusText }}</h3>
          <p class="muted">{{ statusDetail }}</p>
          <div v-if="logs.length" class="logbox">
            <p v-for="(l, i) in logs" :key="i" class="logline">[{{ l.level }}] {{ l.message }}</p>
          </div>
          <button v-if="failed" @click="back">返回主机列表</button>
        </div>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { connectRdp, resolveWsUrl, ensureWasm } from '../rdp'
import type { RdpSession } from '../rdp'

const route = useRoute()
const router = useRouter()
const wrap = ref<HTMLDivElement | null>(null)
const canvas = ref<HTMLCanvasElement | null>(null)

const hostName = String(route.query.name || '远程会话')
const sessionId = Number(route.query.session_id || 0)
const wsPath = String(route.query.ws || '')

// 凭据由连接弹窗通过路由 state 传入，刷新后即丢失，符合不落盘原则。
const navState = (history.state && history.state.deskgwCreds) || {}
const creds = {
  username: String(navState.username || ''),
  password: String(navState.password || ''),
  domain: String(navState.domain || ''),
}

const vpWidth = ref(1280)
const vpHeight = ref(720)
const resolution = ref('0')
const connected = ref(false)
const failed = ref(false)
const status = ref<'connecting' | 'connected' | 'disconnected' | 'error'>('connecting')
const statusDetail = ref('正在建立 RDP 隧道…')
const logs = ref<{ level: string; message: string }[]>([])
let session: RdpSession | null = null

const statusText = computed(() => ({
  connecting: '正在连接', connected: '已连接', disconnected: '已断开', error: '连接失败',
}[status.value]))
const statusClass = computed(() => ({
  connecting: 'off', connected: 'ok', disconnected: 'off', error: 'off',
}[status.value]))

function addLog(level: string, message: string) {
  logs.value.push({ level, message })
  if (logs.value.length > 40) logs.value.shift()
}

function fitViewport() {
  const el = wrap.value
  if (!el) return
  const w = el.clientWidth || vpWidth.value
  const h = el.clientHeight || vpHeight.value
  vpWidth.value = w
  vpHeight.value = h
  if (session && resolution.value === '0') session.resize(w, h)
}

function applyResolution() {
  if (resolution.value === '0') { fitViewport(); return }
  const [w, h] = resolution.value.split('x').map(Number)
  vpWidth.value = w
  vpHeight.value = h
  if (session) session.resize(w, h)
}

function toggleFullscreen() {
  const el = wrap.value
  if (!el) return
  if (document.fullscreenElement) document.exitFullscreen()
  else el.requestFullscreen?.()
}

function sendCtrlAltDel() { session?.sendCtrlAltDel() }

function disconnect() {
  session?.shutdown()
  status.value = 'disconnected'
  statusDetail.value = '会话已断开'
  connected.value = false
}

function back() { router.push({ name: 'hosts' }) }

onMounted(async () => {
  window.addEventListener('resize', fitViewport)
  fitViewport()
  if (!wsPath || !creds.username || !creds.password) {
    status.value = 'error'; failed.value = true
    statusDetail.value = '连接信息缺失，请从主机列表重新发起连接'
    return
  }
  try {
    addLog('info', '正在加载 RDP 协议组件…')
    await ensureWasm()
    addLog('info', '协议组件就绪，正在认证')
    if (!canvas.value) throw new Error('画布未就绪')
    session = await connectRdp({
      wsUrl: resolveWsUrl(wsPath),
      canvas: canvas.value,
      credentials: creds,
      width: vpWidth.value,
      height: vpHeight.value,
      onLog: addLog,
    })
    connected.value = true
    status.value = 'connected'
    statusDetail.value = '远程会话已建立'
    canvas.value?.focus()
    session.terminated.then((reason) => {
      connected.value = false
      if (status.value !== 'disconnected') {
        status.value = 'error'; failed.value = true
        statusDetail.value = '会话已结束：' + reason
      }
      session = null
    })
  } catch (e: any) {
    status.value = 'error'; failed.value = true
    statusDetail.value = '连接失败：' + (e?.message || e || '未知错误')
    addLog('error', statusDetail.value)
  } finally {
    creds.password = ''
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', fitViewport)
  session?.shutdown()
  session = null
  creds.password = ''
})
</script>

<style scoped>
.session-page { display: flex; flex-direction: column; height: 100vh; background: #0f1115; }
.session-bar { display: flex; align-items: center; gap: 16px; height: 52px; padding: 0 16px;
  background: #1b1e24; color: #e5e7eb; border-bottom: 1px solid #2a2e37; }
.session-title { display: flex; align-items: center; gap: 10px; font-size: 14px; }
.session-title .logo { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 6px;
  background: #2563eb; color: #fff; font-size: 11px; }
.session-tools { margin-left: auto; display: flex; gap: 8px; align-items: center; }
.session-tools button, .session-tools select { background: #262a33; color: #e5e7eb;
  border: 1px solid #3a3f4b; border-radius: 6px; padding: 5px 10px; font: inherit; font-size: 12px; }
.session-tools button:hover:not(:disabled) { background: #313643; }
.session-tools button:disabled { opacity: .45; }
.session-tools button.danger { color: #fca5a5; }
.canvas-wrap { flex: 1; position: relative; overflow: hidden; }
canvas { display: block; width: 100%; height: 100%; outline: none; background: #000; }
.overlay { position: absolute; inset: 0; display: grid; place-items: center;
  background: rgba(15,17,21,.85); }
.overlay-card { width: 420px; max-width: 90%; background: #1b1e24; color: #e5e7eb;
  border: 1px solid #343945; border-radius: 12px; padding: 22px; text-align: center; }
.overlay-card h3 { margin: 0 0 8px; font-size: 17px; }
.overlay-card .muted { color: #9ca3af; font-size: 13px; margin: 0 0 14px; }
.overlay-card button { margin-top: 12px; }
.logbox { background: #101216; border-radius: 8px; padding: 10px; max-height: 160px;
  overflow: auto; text-align: left; }
.logline { margin: 0 0 3px; font: 12px/1.5 ui-monospace, monospace; color: #9ca3af; }
.tag { padding: 2px 8px; border-radius: 10px; background: #343945; font-size: 11px; }
.tag.ok { background: #166534; color: #bbf7d0; }
</style>
