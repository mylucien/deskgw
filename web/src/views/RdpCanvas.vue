<template>
  <div class="rdp-canvas">
    <div class="rc-tools">
      <button @click="sendCtrlAltDel" :disabled="!session">Ctrl+Alt+Del</button>
      <select v-model="resolution" @change="applyResolution" :disabled="!session" title="分辨率">
        <option value="0">自适应</option>
        <option value="1280x720">1280 × 720</option>
        <option value="1920x1080">1920 × 1080</option>
      </select>
      <button v-if="canFile" :class="{ active: showFiles }" @click="showFiles = !showFiles" :disabled="!session">文件</button>
      <button @click="toggleFullscreen" :disabled="!session">全屏</button>
      <button class="danger" @click="close">断开</button>
    </div>
    <div class="rc-main">
      <div class="rc-stage" ref="wrap">
        <canvas ref="canvas" :width="vpWidth" :height="vpHeight" tabindex="0"></canvas>
        <div v-if="!connected" class="overlay">
          <div class="overlay-card">
            <h3>{{ statusText }}</h3>
            <p class="muted">{{ detail }}</p>
            <div v-if="logs.length" class="logbox">
              <p v-for="(l, i) in logs" :key="i" class="logline">[{{ l.level }}] {{ l.message }}</p>
            </div>
          </div>
        </div>
      </div>
      <FilePanel v-if="showFiles && canFile" :session-id="tab.sessionId" :creds="tab.creds" @close="showFiles = false" />
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { connectRdp, resolveWsUrl } from '../rdp'
import type { RdpSession } from '../rdp'
import { closeTab, wipeCreds } from '../sessionTabs'
import type { TabInfo } from '../sessionTabs'
import { state } from '../state'
import FilePanel from './FilePanel.vue'

const props = defineProps<{ tab: TabInfo; active: boolean }>()
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
let session: RdpSession | null = null

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
  const w = el.clientWidth || vpWidth.value
  const h = el.clientHeight || vpHeight.value
  vpWidth.value = w; vpHeight.value = h
  if (session && resolution.value === '0') session.resize(w, h)
}
function applyResolution() {
  if (resolution.value === '0') { fitViewport(); return }
  const [w, h] = resolution.value.split('x').map(Number)
  vpWidth.value = w; vpHeight.value = h
  session?.resize(w, h)
}
function toggleFullscreen() {
  const el = wrap.value
  if (!el) return
  if (document.fullscreenElement) document.exitFullscreen()
  else el.requestFullscreen?.()
}
function sendCtrlAltDel() { session?.sendCtrlAltDel() }
function close() {
  session?.shutdown()
  session = null
  connected.value = false
  showFiles.value = false
  closeTab(props.tab.key)
}

watch(() => props.active, async (v) => {
  if (v) { await nextTick(); fitViewport() }
})

onMounted(async () => {
  window.addEventListener('resize', fitViewport)
  await nextTick()
  fitViewport()
  const creds = props.tab.creds
  if (!props.tab.wsPath || !creds.username || !creds.password) {
    props.tab.status = 'error'
    detail.value = '连接信息缺失，请从主机列表重新发起连接'
    return
  }
  try {
    addLog('info', '正在加载 RDP 协议组件…')
    if (!canvas.value) throw new Error('画布未就绪')
    session = await connectRdp({
      wsUrl: resolveWsUrl(props.tab.wsPath),
      destination: props.tab.address,
      fingerprintKey: 'host-' + props.tab.hostId,
      canvas: canvas.value,
      credentials: { username: creds.username, password: creds.password, domain: creds.domain },
      width: vpWidth.value,
      height: vpHeight.value,
      onLog: addLog,
    })
    connected.value = true
    props.tab.status = 'connected'
    detail.value = '远程会话已建立'
    canvas.value?.focus()
    session.terminated.then((reason) => {
      connected.value = false
      if (props.tab.status !== 'disconnected') {
        props.tab.status = 'error'
        detail.value = '会话已结束：' + reason
      }
      session = null
    })
  } catch (e: any) {
    props.tab.status = 'error'
    detail.value = '连接失败：' + (e?.message || e || '未知错误')
    addLog('error', detail.value)
  }
})

onBeforeUnmount(() => {
  window.removeEventListener('resize', fitViewport)
  session?.shutdown()
  session = null
  wipeCreds(props.tab.creds)
})
</script>

<style scoped>
.rdp-canvas { display: flex; flex-direction: column; height: 100%; min-height: 0; }
.rc-tools { display: flex; align-items: center; gap: 8px; height: 44px; padding: 0 12px;
  background: #1b1e24; border-bottom: 1px solid #2a2e37; flex: none; }
.rc-tools button, .rc-tools select { background: #262a33; color: #e5e7eb; border: 1px solid #3a3f4b;
  border-radius: 6px; padding: 5px 10px; font: inherit; font-size: 12px; }
.rc-tools button:hover:not(:disabled) { background: #313643; }
.rc-tools button:disabled { opacity: .45; }
.rc-tools button.active { border-color: #2563eb; color: #93c5fd; }
.rc-tools button.danger { color: #fca5a5; }
.rc-main { display: flex; flex: 1; min-height: 0; }
.rc-stage { flex: 1; position: relative; overflow: hidden; background: #0f1115; }
canvas { display: block; width: 100%; height: 100%; outline: none; background: #000; }
.overlay { position: absolute; inset: 0; display: grid; place-items: center; background: rgba(15,17,21,.85); }
.overlay-card { width: 420px; max-width: 90%; background: #1b1e24; color: #e5e7eb;
  border: 1px solid #343945; border-radius: 12px; padding: 22px; text-align: center; }
.overlay-card h3 { margin: 0 0 8px; font-size: 17px; }
.overlay-card .muted { color: #9ca3af; font-size: 13px; margin: 0; }
.logbox { background: #101216; border-radius: 8px; padding: 10px; max-height: 160px;
  overflow: auto; text-align: left; margin-top: 12px; }
.logline { margin: 0 0 3px; font: 12px/1.5 ui-monospace, monospace; color: #9ca3af; }
</style>
