<template>
  <div class="workspace" ref="workspaceEl">
    <div class="ws-body">
      <p v-if="!workspace.tabs.length" class="empty">
        没有打开的会话。<a @click="goHosts">前往主机列表</a>
      </p>
      <template v-for="t in workspace.tabs" :key="t.key">
        <div v-show="t.key === workspace.active" class="ws-pane">
          <RdpCanvas :tab="t" :active="t.key === workspace.active"
            :ref="(el) => setRef(t.key, el)"
            @viewport="(s) => { sizes[t.key] = s }" />
        </div>
      </template>
    </div>

    <!-- 隐藏后留下的贴边把手，点一下把按钮放回来。 -->
    <button v-if="fabHidden && !filesOpen" class="fab-handle" :style="handleStyle"
      @click="showFab" aria-label="显示会话菜单" title="显示会话菜单"></button>

    <!-- 悬浮按钮：替代原来的标签栏。会话数用角标，连接状态用右下圆点。
         可拖动摆放，靠近左右边缘会吸附。 -->
    <button class="fab"
      :class="{ on: menuOpen, hide: filesOpen || fabHidden, drag: dragging }"
      :style="fabStyle" :aria-expanded="menuOpen"
      :title="activeName || '会话菜单'" aria-label="会话菜单"
      @pointerdown="onFabDown" @click="onFabTap">
      <span class="mark">DG</span>
      <span v-if="workspace.tabs.length > 1" class="badge">{{ workspace.tabs.length }}</span>
      <span v-if="anyConnected" class="live"></span>
    </button>

    <div class="panel" :class="{ open: menuOpen }" :style="panelStyle" :aria-hidden="!menuOpen"
      role="dialog" aria-label="会话菜单" ref="panelEl">
      <div class="p-top">
        <span class="p-cap">会话</span>
        <span class="p-ver">{{ workspace.tabs.length }} / {{ MAX_TABS }}</span>
        <button class="p-x" @click="closeMenu()" aria-label="收起">×</button>
      </div>

      <div v-if="workspace.tabs.length" class="p-tabs">
        <div v-for="t in workspace.tabs" :key="t.key" class="p-tab"
          :class="{ on: t.key === workspace.active }" @click="select(t.key)">
          <i :class="t.status"></i>
          <span class="nm">{{ t.hostName }}</span>
          <span class="sz">{{ sizeLabel(t) }}</span>
          <button class="k" title="关闭" @click.stop="close(t.key)">×</button>
        </div>
      </div>
      <p v-else class="p-empty">没有打开的会话</p>

      <button class="p-add" :disabled="workspace.tabs.length >= MAX_TABS" @click="goHosts">＋ 新建连接</button>

      <template v-if="api && workspace.tabs.length">
        <div class="p-div">当前会话</div>
        <div v-if="api.touch" class="seg">
          <button :class="{ on: api.inputMode === 'pointer' }" :disabled="!api.connected"
            @click="api.setMode('pointer')">指针</button>
          <button :class="{ on: api.inputMode === 'touch' }" :disabled="!api.connected"
            @click="api.setMode('touch')">触摸</button>
          <button :class="{ on: api.keyboardOpen }" :disabled="!api.connected"
            @click="toggleKeyboard">键盘</button>
        </div>
        <div class="p-grid">
          <button :disabled="!api.connected" @click="act(() => api?.sendCtrlAltDel())">Ctrl+Alt+Del</button>
          <select :value="api.resolution" :disabled="!api.connected" @change="onResolution">
            <option value="0">自适应</option>
            <option value="1280x720">1280 × 720</option>
            <option value="1920x1080">1920 × 1080</option>
          </select>
          <button v-if="api.canFile" :class="{ on: api.showFiles }" :disabled="!api.connected"
            @click="act(() => api?.toggleFiles(), true)">文件</button>
          <button :disabled="!api.connected" @click="act(() => api?.toggleFullscreen(), true)">全屏</button>
        </div>
        <div class="p-meta">远端 {{ api.vpWidth }} × {{ api.vpHeight }}{{ api.resolution === '0' ? ' · 自适应' : ' · 固定' }}</div>
      </template>

      <button class="p-mini" @click="hideFab">隐藏悬浮按钮</button>

      <template v-if="api && workspace.tabs.length">
        <div class="p-foot">
          <button class="p-danger" @click="act(() => api?.close(), true)">断开当前会话</button>
          <button class="p-quit" @click="exitWorkspace">退出工作区</button>
        </div>
      </template>
      <div v-else class="p-foot">
        <button class="p-quit" @click="goHosts">返回主机列表</button>
      </div>
    </div>

    <p v-if="notice" class="notice">{{ notice }}</p>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, shallowReactive } from 'vue'
import { useRouter } from 'vue-router'
import RdpCanvas from './RdpCanvas.vue'
import { workspace, closeTab, closeAllTabs, MAX_TABS } from '../sessionTabs'
import type { TabInfo } from '../sessionTabs'

// RdpCanvas 通过 defineExpose 暴露的操作面。状态仍归各标签所有，
// 这里只做转发，不把会话句柄复制一份到会话页。
interface RdpApi {
  touch: boolean
  canFile: boolean
  connected: boolean
  vpWidth: number
  vpHeight: number
  resolution: string
  inputMode: 'touch' | 'pointer'
  keyboardOpen: boolean
  showFiles: boolean
  setMode: (m: 'touch' | 'pointer') => void
  toggleKeyboard: () => void
  sendCtrlAltDel: () => void
  setResolution: (v: string) => void
  toggleFiles: () => void
  toggleFullscreen: () => void
  close: () => void
  focus: () => void
}

const router = useRouter()
const notice = ref('')
const menuOpen = ref(false)
const panelEl = ref<HTMLElement | null>(null)
const workspaceEl = ref<HTMLElement | null>(null)

// ---- 悬浮按钮的位置与显隐 ----
// 位置存的是相对工作区的像素坐标；换屏后由 clamp 拉回可见范围。
const FAB_SIZE = 46
const FAB_MARGIN = 14
const FAB_EDGE = 6            // 贴边时留的缝，太贴手不好按
const POS_KEY = 'deskgw.fabPos'
const HIDE_KEY = 'deskgw.fabHidden'

const vw = ref(window.innerWidth)
const vh = ref(window.innerHeight)
const safeBottom = ref(0)
const fabX = ref(-1)
const fabY = ref(-1)
const fabHidden = ref(localStorage.getItem(HIDE_KEY) === '1')
const dragging = ref(false)
let dragFrom: { px: number; py: number; ox: number; oy: number } | null = null
let lastDragEndAt = 0

const clamp = (v: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, v))

function maxX() { return Math.max(FAB_EDGE, vw.value - FAB_SIZE - FAB_EDGE) }
function maxY() { return Math.max(FAB_EDGE, vh.value - FAB_SIZE - FAB_EDGE - safeBottom.value) }

function savePos() {
  try {
    localStorage.setItem(POS_KEY, JSON.stringify({ x: Math.round(fabX.value), y: Math.round(fabY.value) }))
  } catch { /* 隐私模式下写不进去，位置只在本页有效 */ }
}

function measure() {
  const r = workspaceEl.value?.getBoundingClientRect()
  vw.value = Math.round(r?.width || window.innerWidth)
  vh.value = Math.round(r?.height || window.innerHeight)
  if (fabX.value < 0) {
    fabX.value = clamp(vw.value - FAB_SIZE - FAB_MARGIN, FAB_EDGE, maxX())
    fabY.value = clamp(vh.value - FAB_SIZE - FAB_MARGIN - safeBottom.value, FAB_EDGE, maxY())
  } else {
    fabX.value = clamp(fabX.value, FAB_EDGE, maxX())
    fabY.value = clamp(fabY.value, FAB_EDGE, maxY())
  }
}

// env(safe-area-inset-bottom) 在 JS 里读不到，用一个 1px 高的探针量一次。
function readSafeBottom() {
  const probe = document.createElement('div')
  probe.style.cssText =
    'position:fixed;left:0;bottom:0;width:1px;height:env(safe-area-inset-bottom,0px);visibility:hidden;pointer-events:none'
  document.body.appendChild(probe)
  safeBottom.value = Math.round(probe.getBoundingClientRect().height) || 0
  probe.remove()
}

const fabStyle = computed(() => ({
  transform: `translate3d(${Math.round(fabX.value)}px, ${Math.round(fabY.value)}px, 0)`,
}))

const handleStyle = computed(() => {
  const onLeft = fabX.value + FAB_SIZE / 2 < vw.value / 2
  return onLeft
    ? { left: '0px', top: `${Math.round(fabY.value)}px`, borderRadius: '0 10px 10px 0' }
    : { right: '0px', top: `${Math.round(fabY.value)}px`, borderRadius: '10px 0 0 10px' }
})

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

// 移动超过 6px 才算拖动，避免手抖把点击吃掉。
function onFabDown(e: PointerEvent) {
  if (e.pointerType === 'mouse' && e.button !== 0) return
  if (menuOpen.value) return   // 面板开着时按下就是收起，交给 click
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
  // 松手时贴近左右边缘就吸上去，其余位置原地保留。
  if (fabX.value < FAB_MARGIN + 12) fabX.value = FAB_EDGE
  else if (fabX.value > vw.value - FAB_SIZE - FAB_MARGIN - 12) fabX.value = maxX()
  savePos()
  // 拖动结束后浏览器仍会补一次 click；用时间窗挡掉，不用布尔标记，
  // 免得浏览器压根没发 click 时把下一次正常点击吃掉。
  lastDragEndAt = Date.now()
}

function onFabTap() {
  if (Date.now() - lastDragEndAt < 400) return
  if (menuOpen.value) closeMenu()
  else menuOpen.value = true
}

function hideFab() {
  menuOpen.value = false
  fabHidden.value = true
  try { localStorage.setItem(HIDE_KEY, '1') } catch { /* ignore */ }
}
function showFab() {
  fabHidden.value = false
  try { localStorage.removeItem(HIDE_KEY) } catch { /* ignore */ }
}

function onResize() { measure() }

// shallowReactive：只关心「哪个 key 有实例」，不能把组件代理再包一层响应式。
const canvasMap = shallowReactive<Record<string, RdpApi>>({})
const sizes = reactive<Record<string, { w: number; h: number }>>({})

function setRef(key: string, el: unknown) {
  if (el) canvasMap[key] = el as RdpApi
  else delete canvasMap[key]
}
const api = computed<RdpApi | null>(() => canvasMap[workspace.active] || null)
const activeName = computed(() => workspace.tabs.find(t => t.key === workspace.active)?.hostName || '')
const anyConnected = computed(() => workspace.tabs.some(t => t.status === 'connected'))
// 文件面板占据右侧 320px 且自带关闭按钮，此时藏起悬浮按钮，避免压住列表底部的操作。
const filesOpen = computed(() => !!api.value?.showFiles)

function sizeLabel(t: TabInfo) {
  const s = sizes[t.key]
  if (s) return `${s.w}×${s.h}`
  if (t.status === 'connecting') return '连接中'
  if (t.status === 'error') return '失败'
  return ''
}

// 面板里的一次性动作。需要看到结果的（全屏、文件、断开）顺手把面板收起。
function act(fn: () => void, close = false) {
  try { fn() } catch { /* 会话可能刚断开 */ }
  if (close) menuOpen.value = false
}
function toggleKeyboard() {
  if (!api.value) return
  const willOpen = !api.value.keyboardOpen
  act(() => api.value?.toggleKeyboard(), willOpen)
}
function onResolution(e: Event) {
  const v = (e.target as HTMLSelectElement).value
  act(() => api.value?.setResolution(v), true)
}
function select(key: string) {
  workspace.active = key
  menuOpen.value = false
}
function close(key: string) {
  closeTab(key)
  delete sizes[key]
  notice.value = ''
}
function goHosts() {
  menuOpen.value = false
  if (workspace.tabs.length >= MAX_TABS) {
    notice.value = `最多同时打开 ${MAX_TABS} 个会话，请先关闭一个标签`
    return
  }
  router.push({ name: 'hosts' })
}
// 离开工作区会卸载全部 RdpCanvas，WASM 会话与票据随之失效。
// 因此退出即结束所有会话，避免留下点开就报错的死标签。
function exitWorkspace() {
  menuOpen.value = false
  closeAllTabs()
  router.push({ name: 'hosts' })
}

// 主动收起面板时把键盘焦点还给远程桌面：面板按钮会抢走焦点，
// 桌面浏览器里不点一下画布就打不了字。触摸设备上 focus 本身是空操作。
function closeMenu() {
  menuOpen.value = false
  api.value?.focus()
}

// 点面板与按钮以外的地方收起；Esc 同样。
function onDocDown(e: PointerEvent) {
  if (!menuOpen.value) return
  const target = e.target as Element | null
  if (panelEl.value?.contains(target as Node)) return
  if (target?.closest?.('.fab')) return
  closeMenu()
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'Escape') closeMenu()
}

onMounted(() => {
  if (workspace.tabs.length >= MAX_TABS) notice.value = `最多同时打开 ${MAX_TABS} 个会话`
  readSafeBottom()
  const savedPos = localStorage.getItem(POS_KEY)
  if (savedPos) {
    try {
      const p = JSON.parse(savedPos)
      if (Number.isFinite(p?.x) && Number.isFinite(p?.y)) { fabX.value = p.x; fabY.value = p.y }
    } catch { /* 坏数据就用默认位置 */ }
  }
  measure()
  window.addEventListener('resize', onResize)
  document.addEventListener('pointerdown', onDocDown)
  document.addEventListener('keydown', onKey)
})
onBeforeUnmount(() => {
  window.removeEventListener('resize', onResize)
  window.removeEventListener('pointermove', onFabMove)
  window.removeEventListener('pointerup', onFabEnd)
  window.removeEventListener('pointercancel', onFabEnd)
  document.removeEventListener('pointerdown', onDocDown)
  document.removeEventListener('keydown', onKey)
})
</script>

<style scoped>
/* dvh 跟随移动端地址栏收缩，避免底部被浏览器工具栏盖住。 */
.workspace { position: relative; display: flex; flex-direction: column;
  height: 100vh; height: 100dvh; overflow: hidden;
  background: #0f1115; color: #e5e7eb; }
.ws-body { flex: 1; min-height: 0; position: relative; }
.ws-pane { position: absolute; inset: 0; }
.empty { position: absolute; inset: 0; display: grid; place-items: center; color: #9ca3af; }
.empty a { color: #93c5fd; cursor: pointer; margin-left: 6px; }
.notice { position: absolute; bottom: 76px; left: 50%; transform: translateX(-50%); margin: 0;
  background: #7c2d12; color: #fed7aa; padding: 8px 16px; border-radius: 8px; font-size: 12px; }

/* ---------- 悬浮按钮 ---------- */
/* 位置由 JS 算好后写进 transform，left/top 始终是 0，左右吸附只是改 x。 */
.fab { position: absolute; left: 0; top: 0;
  width: 46px; height: 46px; border-radius: 50%; padding: 0;
  display: grid; place-items: center; z-index: 30;
  border: 1px solid rgba(255, 255, 255, .14);
  background: linear-gradient(180deg, #2f3540 0%, #1b1f27 100%);
  color: #fff; cursor: pointer;
  touch-action: none; -webkit-user-select: none; user-select: none;
  -webkit-tap-highlight-color: transparent; -webkit-touch-callout: none;
  box-shadow: 0 8px 22px rgba(0, 0, 0, .5), inset 0 1px 0 rgba(255, 255, 255, .14);
  transition: transform .18s cubic-bezier(.2, .8, .3, 1), box-shadow .16s ease;
}
.fab:hover { box-shadow: 0 12px 26px rgba(0, 0, 0, .58), inset 0 1px 0 rgba(255, 255, 255, .18); }
.fab:active { filter: brightness(1.18); }
.fab.drag { transition: none; cursor: grabbing; filter: brightness(1.12);
  box-shadow: 0 16px 34px rgba(0, 0, 0, .66), inset 0 1px 0 rgba(255, 255, 255, .2); }
.fab.on { border-color: rgba(59, 130, 246, .6); }
.fab.hide { display: none; }
.fab .mark { font-size: 12px; letter-spacing: .04em; font-weight: 600; }
.fab .badge { position: absolute; top: -3px; right: -3px; min-width: 17px; height: 17px;
  padding: 0 4px; border-radius: 9px; background: #2563eb; color: #fff;
  font-size: 10px; line-height: 17px; text-align: center;
  border: 2px solid rgba(15, 17, 21, .9); }
.fab .live { position: absolute; bottom: 1px; right: 1px; width: 10px; height: 10px;
  border-radius: 50%; background: #22c55e; border: 2px solid #1b1f27; }

/* 隐藏后的贴边把手：只露一条窄边，点一下恢复按钮。 */
.fab-handle { position: absolute; z-index: 30; width: 16px; height: 46px; padding: 0;
  border: 1px solid rgba(255, 255, 255, .14);
  background: rgba(47, 53, 64, .62);
  -webkit-backdrop-filter: blur(6px); backdrop-filter: blur(6px);
  cursor: pointer; -webkit-tap-highlight-color: transparent; }
.fab-handle::before { content: ""; display: block; width: 3px; height: 16px; margin: 0 auto;
  border-radius: 2px; background: rgba(255, 255, 255, .4); }
.fab-handle:hover { background: rgba(60, 68, 82, .8); }

/* ---------- 展开面板 ---------- */
.panel { position: absolute; z-index: 29;
  display: flex; flex-direction: column; overflow-y: auto;
  background: rgba(24, 27, 33, .92);
  -webkit-backdrop-filter: blur(18px) saturate(1.3);
  backdrop-filter: blur(18px) saturate(1.3);
  border: 1px solid rgba(255, 255, 255, .1); border-radius: 12px;
  box-shadow: 0 20px 48px rgba(0, 0, 0, .6);
  opacity: 0; transform: scale(.92) translateY(8px); pointer-events: none;
  transition: opacity .13s ease, transform .13s cubic-bezier(.2, .8, .3, 1);
}
.panel.open { opacity: 1; transform: none; pointer-events: auto; }
.p-top { display: flex; align-items: center; gap: 8px; padding: 11px 12px 9px; flex: none; }
.p-cap { font-size: 10.5px; letter-spacing: .08em; color: #98a1b0; }
.p-ver { margin-left: auto; color: #5c636f; font-size: 10px; }
.p-x { width: 24px; height: 24px; border-radius: 6px; border: 0; padding: 0;
  background: transparent; color: #98a1b0; cursor: pointer; font-size: 16px; line-height: 1; }
.p-x:hover { background: rgba(255, 255, 255, .07); color: #e5e7eb; }

.p-tabs { padding: 0 8px; display: grid; gap: 3px; flex: none; }
.p-tab { display: flex; align-items: center; gap: 9px; width: 100%; min-height: 38px;
  padding: 0 8px; border-radius: 8px; border: 1px solid transparent; background: transparent;
  color: #98a1b0; font-size: 12.5px; text-align: left; cursor: pointer;
  font-family: inherit; }
.p-tab:hover { background: rgba(255, 255, 255, .05); }
.p-tab.on { background: rgba(59, 130, 246, .14); border-color: rgba(59, 130, 246, .34); color: #e5e7eb; }
.p-tab i { width: 7px; height: 7px; border-radius: 50%; background: #6b7280; flex: none; }
.p-tab i.connected { background: #22c55e; }
.p-tab i.connecting { background: #eab308; }
.p-tab i.error { background: #ef4444; }
.p-tab .nm { flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.p-tab .sz { font-size: 10.5px; color: #5c636f; flex: none; }
.p-tab .k { width: 20px; height: 20px; border-radius: 5px; border: 0; padding: 0;
  background: transparent; color: #5c636f; cursor: pointer; font-size: 14px; line-height: 1; flex: none; }
.p-tab .k:hover { background: rgba(239, 68, 68, .16); color: #fca5a5; }
.p-empty { margin: 0; padding: 10px 12px; color: #5c636f; font-size: 12px; }

.p-add { margin: 6px 8px 2px; height: 34px; border-radius: 8px; flex: none;
  border: 1px dashed #3a4150; background: transparent; color: #98a1b0;
  font-size: 12px; cursor: pointer; font-family: inherit; }
.p-add:hover:not(:disabled) { border-color: #4b5563; color: #e5e7eb; }
.p-add:disabled { opacity: .4; cursor: not-allowed; }

.p-div { display: flex; align-items: center; gap: 8px; padding: 12px 12px 7px; flex: none;
  font-size: 10.5px; letter-spacing: .06em; color: #5c636f; }
.p-div::after { content: ""; flex: 1; height: 1px; background: rgba(255, 255, 255, .07); }

.seg { display: grid; grid-auto-flow: column; gap: 3px; margin: 0 10px 8px; flex: none;
  padding: 3px; border-radius: 8px; background: rgba(0, 0, 0, .3);
  border: 1px solid rgba(255, 255, 255, .05); }
.seg button { height: 30px; border: 0; border-radius: 6px; background: transparent; padding: 0;
  color: #98a1b0; font-size: 12px; cursor: pointer; font-family: inherit; }
.seg button.on { background: #2b303a; color: #e5e7eb; box-shadow: 0 1px 2px rgba(0, 0, 0, .4); }
.seg button:disabled { opacity: .38; cursor: not-allowed; }

.p-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 6px; padding: 0 10px; flex: none; }
.p-grid button, .p-grid select { height: 34px; padding: 0 8px; border-radius: 8px;
  border: 1px solid #343a46; background: #20242c; color: #e5e7eb;
  font-size: 12px; cursor: pointer; font-family: inherit; }
.p-grid button:hover:not(:disabled) { background: #262b34; border-color: #3f4654; }
.p-grid button.on { border-color: rgba(59, 130, 246, .55); background: rgba(59, 130, 246, .16); }
.p-grid button:disabled, .p-grid select:disabled { opacity: .45; cursor: not-allowed; }

.p-meta { padding: 8px 12px 0; color: #5c636f; font-size: 10.5px; flex: none;
  font-family: ui-monospace, monospace; }

.p-mini { height: 28px; margin: 6px 10px 0; border: 0; border-radius: 6px; flex: none;
  background: transparent; color: #5c636f; font-size: 11px; cursor: pointer; font-family: inherit; }
.p-mini:hover { color: #98a1b0; background: rgba(255, 255, 255, .04); }

.p-foot { display: grid; gap: 6px; padding: 10px; margin-top: 4px; flex: none;
  border-top: 1px solid rgba(255, 255, 255, .06); }
.p-danger, .p-quit { height: 36px; border-radius: 8px; font-size: 12px; cursor: pointer;
  font-family: inherit; }
.p-danger { border: 1px solid rgba(239, 68, 68, .42); background: rgba(239, 68, 68, .12); color: #fca5a5; }
.p-danger:hover { background: rgba(239, 68, 68, .2); }
.p-quit { border: 1px solid #343a46; background: transparent; color: #98a1b0; }
.p-quit:hover { color: #e5e7eb; border-color: #4b5563; }
</style>
