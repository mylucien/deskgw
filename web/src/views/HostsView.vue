<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h2>主机列表</h2>
        <p class="muted">可访问的局域网 Windows 主机。连接方式在后台「主机管理」中配置。</p>
      </div>
      <div class="filters">
        <input v-model="query" placeholder="搜索名称 / 地址 / 分组" />
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
            @click="openDialog(h)">连接（RDP）</button>
          <button v-if="modes(h.modes).includes('perf')" disabled title="性能模式在 M8 提供">性能模式</button>
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
import { openTab, workspace, MAX_TABS } from '../sessionTabs'

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

const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return hosts.value
  return hosts.value.filter(h =>
    [h.name, h.address, h.group_name, h.note].join(' ').toLowerCase().includes(q))
})
function modes(s: string) { return s.split(',').map(x => x.trim()).filter(Boolean) }
function modeName(m: string) { return m === 'perf' ? '性能模式' : 'RDP' }

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
  if (workspace.tabs.length >= MAX_TABS) {
    dialogError.value = `最多同时打开 ${MAX_TABS} 个会话，请先关闭一个标签`
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

onMounted(async () => {
  try { hosts.value = await get<Host[]>('/hosts') }
  catch (e: any) { error.value = e.message }
  finally { loading.value = false }
})
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
