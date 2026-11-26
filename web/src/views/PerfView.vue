<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h2>性能模式</h2>
        <p class="muted">端到端加密会话：路由器只转发密文，画面密钥只在浏览器与被控端手里。</p>
      </div>
      <div class="filters">
        <button @click="leave">返回主机列表</button>
        <button v-if="state === 'ready'" class="primary" @click="hangup">断开</button>
      </div>
    </div>

    <p v-if="!perfSession.current" class="muted">
      没有待连接的性能模式会话，请从<a @click="leave">主机列表</a>重新进入。
    </p>

    <template v-else>
      <p v-if="state === 'connecting'" class="muted">正在与被控端建立端到端会话…</p>

      <div v-if="state === 'error'" class="card">
        <h3>连接失败</h3>
        <p class="error">{{ errorText }}</p>
        <p v-if="hint" class="muted small">{{ hint }}</p>
        <div class="actions">
          <button @click="leave">返回主机列表</button>
        </div>
      </div>

      <div v-if="state === 'ended'" class="card">
        <h3>会话已结束</h3>
        <p class="muted">{{ endedReason || '被控端或网关结束了这次会话。' }}</p>
        <div class="actions">
          <button @click="leave">返回主机列表</button>
        </div>
      </div>

      <div v-if="state === 'ready' && ready" class="card">
        <div class="host-head">
          <h3>{{ ready.host.name }}</h3>
          <span class="tag ok">已连接</span>
        </div>
        <dl>
          <dt>系统</dt><dd>{{ ready.host.os || '—' }}</dd>
          <dt>会话号</dt><dd><code>{{ ready.session_id }}</code></dd>
          <dt>通道密钥</dt><dd>{{ keyCount }} 组已下发（不在此显示）</dd>
        </dl>

        <div class="safety">
          <span class="muted small">安全码，与被控端托盘显示的一致才说明没有被中间人</span>
          <strong>{{ ready.safety }}</strong>
        </div>

        <div class="stats">
          <div><b>{{ stats.streams }}</b><span>下行流</span></div>
          <div><b>{{ stats.datagrams }}</b><span>下行数据报</span></div>
          <div><b>{{ sizeLabel(stats.bytes) }}</b><span>已收字节</span></div>
        </div>

        <p class="muted small note">
          画面解码与键鼠输入还没接入：这一页目前只建立并维持通道，用来确认两端握手、
          密钥与转发都正常。画面会在后续版本用 WebCodecs 解出来。
        </p>
      </div>
    </template>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { perfSession, closePerf } from '../perf'

type State = 'idle' | 'connecting' | 'ready' | 'error' | 'ended'

interface Ready {
  type: 'ready'
  session_id: number
  host: { id: number; name: string; os: string }
  safety: string
  keys: Record<string, unknown>
}

const router = useRouter()
const state = ref<State>('idle')
const ready = ref<Ready | null>(null)
const errorKind = ref('')
const errorText = ref('')
const endedReason = ref('')
const stats = reactive({ streams: 0, datagrams: 0, bytes: 0 })

let ws: WebSocket | null = null
let beat = 0

// 错误码对应的排查方向。被控端没预置配对公钥是最常见的一种。
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
const keyCount = computed(() => Object.keys(ready.value?.keys || {}).length)

function sizeLabel(n: number) {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function connect() {
  const cur = perfSession.current
  if (!cur) return
  state.value = 'connecting'
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
  const sock = new WebSocket(proto + '//' + location.host + cur.wsPath)
  sock.binaryType = 'arraybuffer'
  ws = sock

  sock.onopen = () => {
    // 第一条必须是 connect，且主机要与票据一致；网关会再核一次。
    sock.send(JSON.stringify({ type: 'connect', host: 'h' + cur.hostId }))
  }
  sock.onmessage = (ev) => {
    if (typeof ev.data === 'string') {
      let m: any
      try { m = JSON.parse(ev.data) } catch { return }
      if (m.type === 'ready') {
        ready.value = m as Ready
        state.value = 'ready'
      } else if (m.type === 'error') {
        errorKind.value = m.kind || ''
        errorText.value = m.message || '连接失败'
        state.value = 'error'
      } else if (m.type === 'ended') {
        endedReason.value = m.reason || ''
        state.value = 'ended'
      }
      return
    }
    // 二进制：0x01 下行流、0x02 下行数据报。这里只计数，解密在后续版本。
    const buf = new Uint8Array(ev.data as ArrayBuffer)
    if (!buf.length) return
    stats.bytes += buf.length
    if (buf[0] === 0x01) stats.streams++
    else if (buf[0] === 0x02) stats.datagrams++
  }
  sock.onclose = () => {
    if (state.value === 'ready' || state.value === 'connecting') state.value = 'ended'
  }

  // 与服务端 30 秒心跳对齐：空闲桌面没有画面变化时，靠它保住连接。
  window.clearInterval(beat)
  beat = window.setInterval(() => {
    if (sock.readyState === WebSocket.OPEN) sock.send(JSON.stringify({ type: 'ping' }))
  }, 30_000)
}

function shutdown() {
  window.clearInterval(beat)
  if (ws) {
    ws.onclose = null
    ws.onmessage = null
    ws.close()
    ws = null
  }
}

function hangup() {
  if (ws?.readyState === WebSocket.OPEN) ws.send(JSON.stringify({ type: 'disconnect' }))
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
.card { max-width: 560px; }
.host-head { display: flex; align-items: center; gap: 10px; }
.host-head h3 { margin: 0; }
.safety { margin: 18px 0; display: flex; flex-direction: column; gap: 4px; }
.safety strong { font-size: 30px; letter-spacing: 2px; font-variant-numeric: tabular-nums; }
.stats { display: flex; gap: 28px; margin: 4px 0 14px; }
.stats div { display: flex; flex-direction: column; }
.stats b { font-size: 18px; }
.stats span { font-size: 12px; color: var(--muted); }
.note { margin-top: 8px; line-height: 1.6; }
.actions { margin-top: 12px; }
</style>
