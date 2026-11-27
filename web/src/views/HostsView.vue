<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h2>主机列表</h2>
        <p class="muted">可访问的局域网 Windows 主机。连接方式在后台「主机管理」中配置。</p>
      </div>
      <div class="filters">
        <input v-model="query" placeholder="搜索名称 / 地址 / 分组 / 备注" />
        <button @click="load" :disabled="loading">{{ loading ? '刷新中…' : '刷新' }}</button>
        <button v-if="workspace.tabs.length" class="primary" @click="backToWorkspace">
          返回工作区（{{ workspace.tabs.length }}）
        </button>
      </div>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-else-if="loading" class="muted">加载中…</p>
    <p v-else-if="!filtered.length" class="muted">没有可访问的主机。</p>

    <div class="grid">
      <article v-for="h in filtered" :key="h.id" class="card host">
        <div class="host-head">
          <h3>{{ h.name }}</h3>
          <span class="tag" :class="h.enabled ? 'ok' : 'off'">{{ h.enabled ? '已启用' : '已停用' }}</span>
        </div>
        <dl>
          <dt>地址</dt><dd><code>{{ h.address }}:{{ h.rdp_port }}</code></dd>
          <dt>分组</dt><dd>{{ h.group_name || '—' }}</dd>
          <dt>连接方式</dt><dd>
            <span v-for="m in modes(h.modes)" :key="m" class="tag">{{ modeName(m) }}</span>
          </dd>
          <dt>备注</dt><dd>{{ h.note || '—' }}</dd>
        </dl>
        <div class="host-actions">
          <button class="primary" :disabled="!h.enabled || !modes(h.modes).includes('rdp')"
            :title="rdpTitle(h)" @click="openDialog(h)">连接（RDP）</button>
          <button v-if="modes(h.modes).includes('perf')"
            :disabled="!h.enabled || perfBusy === h.id"
            :title="h.enabled ? '端到端加密连接，路由器看不到画面' : '主机已停用'"
            @click="startPerf(h)">{{ perfBusy === h.id ? '准备中…' : '性能模式' }}</button>
        </div>
      </article>
    </div>

    <div v-if="dialog" class="modal-mask" @click.self="closeDialog">
      <div class="modal">
        <h3>连接到 {{ target?.name }}</h3>
        <p class="muted note">凭据用于本次 NLA 认证；文件传输复用该凭据在网关内存中建立短期会话，不落盘、不写日志。</p>
        <form @submit.prevent="submit">
          <label>用户名<input v-model="form.username" required autocomplete="off" /></label>
          <label>密码<input v-model="form.password" type="password" required autocomplete="off" /></label>
          <label>域（可选）<input v-model="form.domain" placeholder="留空则使用本机账户" autocomplete="off" /></label>
          <p v-if="dialogError" class="error">{{ dialogError }}</p>
          <div class="modal-actions">
            <button type="button" @click="closeDialog">取消</button>
            <button type="submit" class="primary" :disabled="submitting">
              {{ submitting ? '连接中…' : '连接' }}
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { get, post } from '../api'
import { openTab, workspace, maxTabs } from '../sessionTabs'
import { openPerf } from '../perf'

interface Host {
  id: number; name: string; address: string; rdp_port: number
  group_name: string; note: string; enabled: boolean; modes: string
}
interface SessionTicket { ticket: string; session_id: number; ws_path: string }

const router = useRouter()
const hosts = ref<Host[]>([])
const query = ref('')
const loading = ref(true)
const error = ref('')
const dialog = ref(false)
const target = ref<Host | null>(null)
const submitting = ref(false)
const dialogError = ref('')
const form = reactive({ username: '', password: '', domain: '' })
const perfBusy = ref(0)

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return hosts.value
  return hosts.value.filter(h =>
    [h.name, h.address, h.group_name, h.note].join(' ').toLowerCase().includes(q))
})
function modes(s: string) { return s.split(',').map(x => x.trim()).filter(Boolean) }
function modeName(m: string) { return m === 'perf' ? '性能模式' : 'RDP' }
// 只有性能模式的主机没有 RDP 入口，灰掉的按钮必须说清原因。
function rdpTitle(h: Host) {
  if (!h.enabled) return '主机已停用'
  if (!modes(h.modes).includes('rdp')) return '这台主机只启用了性能模式，请用右侧按钮连接'
  return '通过网关建立 RDP 隧道'
}

function openDialog(h: Host) {
  target.value = h
  dialogError.value = ''
  form.username = ''
  form.password = ''
  form.domain = ''
  dialog.value = true
}
function closeDialog() {
  dialog.value = false
  form.password = ''
}

async function submit() {
  if (!target.value || submitting.value) return
  if (workspace.tabs.length >= maxTabs.value) {
    dialogError.value = `最多同时打开 ${maxTabs.value} 个会话，请先关闭一个标签`
    return
  }
  submitting.value = true
  dialogError.value = ''
  try {
    const t = await post<SessionTicket>('/sessions', { host_id: target.value.id })
    // 连接信息进入内存标签 store，凭据不写入 URL，也不持久存储。
    openTab({
      hostName: target.value.name,
      hostId: target.value.id,
      address: target.value.address,
      sessionId: t.session_id,
      wsPath: t.ws_path,
      creds: { ...form },
    })
    form.password = ''
    dialog.value = false
    router.push({ name: 'session' })
  } catch (e: any) {
    dialogError.value = e.message || '连接失败'
  } finally {
    submitting.value = false
  }
}

// 性能模式：签一张一次性票据，会话信息放内存里交给 /perf 页面。
async function startPerf(h: Host) {
  if (perfBusy.value) return
  perfBusy.value = h.id
  error.value = ''
  try {
    const t = await post<SessionTicket>('/perf/ticket', { host_id: h.id })
    openPerf({ hostName: h.name, hostId: h.id, sessionId: t.session_id, wsPath: t.ws_path })
    router.push({ name: 'perf' })
  } catch (e: any) {
    error.value = e.message || '无法打开性能模式'
  } finally {
    perfBusy.value = 0
  }
}

// 离开会话页只隐藏、不卸载（App.vue 对 /session 用了 keep-alive），
// 所以从主机列表回到工作区不会重连，标签仍旧可用。
function backToWorkspace() {
  router.push({ name: 'session' })
}

onMounted(async () => {
  // 空闲时预热 WASM：4.4MB 的下载与编译压在点「连接」之后会白等半秒到一秒。
  // 用动态导入，主机列表页的首屏 bundle 不必为它多背一份胶水代码；延迟 1.2s
  // 是为了不和列表请求、首屏渲染抢带宽。失败留给真正连接时再报。
  window.setTimeout(() => {
    // 省流量模式下不预热：WASM 有 4.4MB，对手机流量不是小数目。
    if ((navigator as any).connection?.saveData) return
    void import('../rdp').then((m) => m.ensureWasm()).catch(() => {})
  }, 1200)
  await load()
})

async function load() {
  loading.value = true
  try {
    hosts.value = await get<Host[]>('/hosts')
    error.value = ''
  } catch (e: any) {
    error.value = e.message
  } finally {
    loading.value = false
  }
}
</script>

<style scoped>
.modal-mask { position: fixed; inset: 0; display: grid; place-items: center;
  background: rgba(15,17,21,.5); z-index: 20; }
.modal { width: 380px; max-width: 92%; background: #fff; border-radius: 12px;
  padding: 22px; box-shadow: 0 8px 30px rgba(0,0,0,.18); }
.modal h3 { margin: 0 0 4px; font-size: 17px; }
.modal .note { font-size: 12px; margin-bottom: 16px; }
.modal form { display: flex; flex-direction: column; gap: 12px; }
.modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 6px; }
</style>
