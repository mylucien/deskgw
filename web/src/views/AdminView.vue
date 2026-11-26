<template>
  <div class="page">
    <div class="page-head"><h2>后台管理</h2></div>
    <div class="tabs">
      <button v-for="t in tabs" :key="t.key" :class="{ active: tab === t.key }" @click="tab = t.key">
        {{ t.label }}
      </button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>

    <section v-if="tab === 'users'" class="panel">
      <div class="panel-head">
        <h3>Web 用户</h3>
        <button class="primary" @click="newUser">新增用户</button>
      </div>
      <form v-if="userForm" class="form-grid card" @submit.prevent="saveUser">
        <label>用户名<input v-model="userForm.username" required /></label>
        <label>密码（新增必填；修改留空则不改）<input v-model="userForm.password" type="password" :required="!userForm.id" /></label>
        <label>角色<select v-model="userForm.role"><option value="admin">admin</option><option value="user">user</option></select></label>
        <label>最大并发会话<input v-model.number="userForm.max_sessions" type="number" min="1" /></label>
        <label class="check"><input v-model="userForm.enabled" type="checkbox" /> 启用</label>
        <label class="check"><input v-model="userForm.allow_file" type="checkbox" /> 允许文件传输</label>
        <label class="check"><input v-model="userForm.allow_clipboard" type="checkbox" /> 允许剪贴板</label>
        <label class="full">授权主机（按住 Ctrl 多选）<select v-model="userForm.host_ids" multiple size="5">
          <option v-for="h in hosts" :key="h.id" :value="h.id">{{ h.name }}（{{ h.address }}）</option>
        </select></label>
        <div class="full actions"><button class="primary" type="submit">保存</button><button type="button" @click="userForm = null">取消</button></div>
      </form>
      <table>
        <thead><tr><th>ID</th><th>用户名</th><th>角色</th><th>授权主机</th><th>状态</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="u in users" :key="u.id">
            <td>{{ u.id }}</td><td>{{ u.username }}</td><td>{{ u.role }}</td>
            <td>{{ u.host_ids.length }}</td>
            <td>{{ u.enabled ? '启用' : '停用' }}</td>
            <td class="actions"><button @click="editUser(u)">编辑</button><button class="danger" @click="removeUser(u)">删除</button></td>
          </tr>
        </tbody>
      </table>
    </section>

    <section v-else-if="tab === 'hosts'" class="panel">
      <div class="panel-head"><h3>主机管理</h3><button class="primary" @click="newHost">新增主机</button></div>
      <form v-if="hostForm" class="form-grid card" @submit.prevent="saveHost">
        <label>主机 ID（留空自动分配）<input v-model.number="hostForm.id" type="number" min="1" max="4294967295" :disabled="hostEditing" /></label>
        <label>名称<input v-model="hostForm.name" required /></label>
        <label>私网 IP<input v-model="hostForm.address" required placeholder="192.168.1.10" /></label>
        <label>RDP 端口<input v-model.number="hostForm.rdp_port" type="number" /></label>
        <label>SMB 端口<input v-model.number="hostForm.smb_port" type="number" /></label>
        <label>分组<input v-model="hostForm.group_name" /></label>
        <label>连接方式<select v-model="hostForm.modes">
          <option value="rdp">RDP</option><option value="rdp,perf">RDP + 性能模式</option>
        </select></label>
        <label class="full">备注<input v-model="hostForm.note" /></label>
        <label class="check"><input v-model="hostForm.enabled" type="checkbox" /> 启用</label>
        <div class="full actions"><button class="primary" type="submit">保存</button><button type="button" @click="hostForm = null">取消</button></div>
      </form>
      <table>
        <thead><tr><th>ID</th><th>名称</th><th>地址</th><th>分组</th><th>模式</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="h in hosts" :key="h.id">
            <td>{{ h.id }}</td><td>{{ h.name }}</td><td><code>{{ h.address }}</code></td>
            <td>{{ h.group_name || '—' }}</td><td>{{ h.modes }}</td>
            <td class="actions"><button @click="editHost(h)">编辑</button><button class="danger" @click="removeHost(h)">删除</button></td>
          </tr>
        </tbody>
      </table>
      <p class="muted small">主机 ID 同时作为性能模式被控端的控制码，创建后不建议修改。</p>
    </section>

    <section v-else-if="tab === 'sessions'" class="panel">
      <div class="panel-head"><h3>在线会话</h3><button @click="load">刷新</button></div>
      <p class="muted small">Web 登录会话 {{ sessions.web_sessions }} 个；下方为远程桌面会话记录。</p>
      <table>
        <thead><tr><th>ID</th><th>用户</th><th>主机</th><th>来源 IP</th><th>开始</th><th>状态</th><th>详情</th><th>操作</th></tr></thead>
        <tbody>
          <tr v-for="s in sessions.sessions" :key="s.id">
            <td>{{ s.id }}</td><td>{{ s.username || '—' }}</td>
            <td>{{ s.host_name || s.host_id }}</td><td>{{ s.client_ip }}</td>
            <td>{{ new Date(s.started_at * 1000).toLocaleString() }}</td>
            <td><span class="tag" :class="s.live ? 'ok' : 'off'">{{ s.live ? '在线' : stateName(s.state) }}</span></td>
            <td class="muted small">{{ s.detail || '—' }}</td>
            <td><button v-if="s.closable" class="danger" @click="kill(s.id)">强制下线</button><span v-else>—</span></td>
          </tr>
        </tbody>
      </table>
    </section>

    <section v-else-if="tab === 'perf'" class="panel">
      <div class="panel-head"><h3>性能模式</h3><button @click="loadPerf">刷新</button></div>
      <template v-if="perf.enabled">
        <div class="card">
          <p class="muted small">被控端的 <code>config.toml</code> 里，<code>server</code> 填
            <code>{{ perfServer }}</code>，<code>server_fp</code> 填下面的指纹。</p>
          <p class="muted small">服务监听在 <code>{{ perf.listen }}</code>；如果那是 <code>0.0.0.0</code>，
            上面要换成被控端能访问到的地址（一般就是路由器的局域网 IP）。</p>
          <p>证书指纹：<code>{{ perf.fingerprint }}</code></p>
        </div>
        <div class="card">
          <p class="muted small">每台被控端的 <code>config.toml</code> 里还要预置路由器的控制端公钥，
            否则被控端会拒绝握手（回「需要配对」）：</p>
          <pre class="snippet">[[paired]]
key = "{{ perf.identity }}"
name = "deskgw"
since = 0</pre>
          <p class="muted small">对应的私钥在路由器的 <code>/etc/deskgw/perf_identity</code>（权限 600，
            首次启动自动生成）。它丢了或换了，所有被控端都要重新预置。</p>
        </div>
        <h4>待批准的被控端</h4>
        <table>
          <thead><tr><th>控制码</th><th>名称</th><th>系统</th><th>来源 IP</th><th>首次接入</th><th>最近在线</th></tr></thead>
          <tbody>
            <tr v-for="p in perf.hosts" :key="p.code">
              <td>{{ p.code }}</td><td>{{ p.name || '—' }}</td><td>{{ p.os || '—' }}</td>
              <td>{{ p.ip }}</td>
              <td>{{ new Date(p.first_seen * 1000).toLocaleString() }}</td>
              <td>{{ new Date(p.last_seen * 1000).toLocaleString() }}</td>
            </tr>
            <tr v-if="!perf.hosts.length"><td colspan="6" class="muted small">还没有被控端接入。</td></tr>
          </tbody>
        </table>
        <p class="muted small">这里只列出接入的设备，批准（核对安全码、记录被控端公钥、换成主机 id）在下一版接入。</p>
      </template>
      <p v-else class="muted small">性能模式没有启用。把 <code>/etc/config/deskgw</code> 里的
        <code>perf_enabled</code> 设为 1，重启服务后生效。</p>
    </section>

    <section v-else-if="tab === 'audit'" class="panel">
      <div class="panel-head">
        <h3>审计日志</h3>
        <input v-model="auditQuery" placeholder="按用户 / 目标 / 详情搜索" @keyup.enter="loadAudit" />
        <button @click="loadAudit">查询</button>
        <button @click="exportAudit">导出 CSV</button>
      </div>
      <p class="muted small">列表显示最近 100 条匹配记录；需要完整数据请使用「导出 CSV」。</p>
      <table>
        <thead><tr><th>时间</th><th>用户</th><th>动作</th><th>目标</th><th>详情</th><th>来源 IP</th></tr></thead>
        <tbody>
          <tr v-for="e in audit" :key="e.id">
            <td>{{ new Date(e.ts * 1000).toLocaleString() }}</td>
            <td>{{ e.username || '—' }}</td><td><code>{{ e.action }}</code></td>
            <td>{{ e.target || '—' }}</td><td>{{ e.detail || '—' }}</td><td>{{ e.client_ip }}</td>
          </tr>
        </tbody>
      </table>
    </section>

    <section v-else-if="tab === 'settings'" class="panel">
      <h3>系统设置</h3>
      <form class="form-grid card" @submit.prevent="saveSettings">
        <label>会话空闲超时（分钟）<input v-model.number="settings.session_idle_min" type="number" min="1" /></label>
        <label>单文件上传上限（MB）<input v-model.number="settings.max_upload_mb" type="number" min="1" /></label>
        <div class="full"><button class="primary" type="submit">保存</button></div>
      </form>
      <p class="muted small">保存后立即生效。未保存过时，默认值来自 UCI 配置的对应选项。性能模式的开关与监听地址在路由器的 UCI 配置里，并发上限在下一版开放。</p>
    </section>

    <section v-else class="panel">
      <h3>运行状态</h3>
      <div class="card"><pre>{{ status }}</pre></div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { get, post, put, del } from '../api'

const tabs = [
  { key: 'users', label: '用户' }, { key: 'hosts', label: '主机' },
  { key: 'sessions', label: '会话' }, { key: 'perf', label: '性能模式' },
  { key: 'audit', label: '审计' }, { key: 'settings', label: '设置' },
  { key: 'status', label: '状态' },
]
const tab = ref('users')
const error = ref('')
const users = ref<any[]>([])
const hosts = ref<any[]>([])
const audit = ref<any[]>([])
const auditQuery = ref('')
const sessions = ref<{ web_sessions: number; sessions: any[] }>({ web_sessions: 0, sessions: [] })
const status = ref('')
const perf = ref<{
  enabled: boolean; listen: string; fingerprint: string; identity: string; hosts: any[]
}>({ enabled: false, listen: '', fingerprint: '', identity: '', hosts: [] })
// 监听地址多半是 0.0.0.0:4433，被控端填这个连不上；只取端口，让管理员补一个
// 被控端真能访问到的地址。
const perfServer = computed(() => {
  const l = perf.value.listen
  const i = l.lastIndexOf(':')
  if (i < 0) return l
  const host = l.slice(0, i)
  const port = l.slice(i + 1)
  if (host === '' || host === '0.0.0.0' || host === '::' || host === '[::]') {
    return `路由器的局域网地址:${port}`
  }
  return l
})
const settings = reactive({ session_idle_min: 30, max_upload_mb: 2048 })
const userForm = ref<any>(null)
const hostForm = ref<any>(null)
// 新增与编辑分开判断：不能再用 id 是否存在来判断，
// 否则填入 ID 的新增请求会被当成 PUT 打到不存在的记录上。
const hostEditing = ref(false)

const SESSION_STATES: Record<string, string> = {
  pending: '等待连接', active: '进行中', closed: '已结束', killed: '已强制下线',
  timeout: '超时回收', stale: '重启前遗留', failed: '建立失败',
  handshake_failed: '握手失败', upgrade_failed: '升级失败',
  connect_failed: '连接失败',
}
function stateName(state: string) { return SESSION_STATES[state] || state }

function resetUser() {
  return { id: 0, username: '', password: '', role: 'user', enabled: true,
    allow_file: true, allow_clipboard: true, max_sessions: 2, host_ids: [] as number[] }
}
function resetHost() {
  return { id: 0, name: '', address: '', rdp_port: 3389, smb_port: 445,
    group_name: '', note: '', enabled: true, modes: 'rdp' }
}
function newUser() { userForm.value = resetUser() }
function editUser(u: any) { userForm.value = { ...resetUser(), ...u, password: '' } }
function newHost() { hostEditing.value = false; hostForm.value = resetHost() }
function editHost(h: any) { hostEditing.value = true; hostForm.value = { ...resetHost(), ...h } }

async function load() {
  try {
    const [us, hs, st] = await Promise.all([
      get<any[]>('/admin/users'), get<any[]>('/admin/hosts'), get<any>('/admin/sessions'),
    ])
    users.value = us; hosts.value = hs; sessions.value = st; status.value = JSON.stringify(st, null, 2)
    const cfg = await get<Record<string, string>>('/admin/settings')
    settings.session_idle_min = Number(cfg.session_idle_min || 30)
    settings.max_upload_mb = Number(cfg.max_upload_mb || 2048)
    await loadPerf()
    await loadAudit()
  } catch (e: any) { error.value = e.message }
}
async function loadPerf() {
  try {
    perf.value = await get<any>('/admin/perf')
  } catch (e: any) { error.value = e.message }
}
async function loadAudit() {
  try {
    const q = auditQuery.value.trim() ? `?q=${encodeURIComponent(auditQuery.value.trim())}` : ''
    audit.value = await get<any[]>('/admin/audit' + q)
  } catch (e: any) { error.value = e.message }
}
async function saveUser() {
  try {
    const f = userForm.value
    if (f.id) await put(`/admin/users/${f.id}`, f)
    else await post('/admin/users', f)
    userForm.value = null; error.value = ''; await load()
  } catch (e: any) { error.value = e.message }
}
async function removeUser(u: any) {
  if (!confirm(`删除用户 ${u.username}？`)) return
  try { await del(`/admin/users/${u.id}`); await load() } catch (e: any) { error.value = e.message }
}
async function saveHost() {
  try {
    const f = { ...hostForm.value }
    if (hostEditing.value) {
      await put(`/admin/hosts/${f.id}`, f)
    } else {
      // 新增时由服务端分配 ID；显式传 0 表示自动分配。
      f.id = Number(f.id) || 0
      await post('/admin/hosts', f)
    }
    hostForm.value = null; error.value = ''; await load()
  } catch (e: any) { error.value = e.message }
}
async function removeHost(h: any) {
  if (!confirm(`删除主机 ${h.name}？`)) return
  try { await del(`/admin/hosts/${h.id}`); await load() } catch (e: any) { error.value = e.message }
}
async function kill(id: number) {
  if (!confirm(`强制断开会话 ${id}？`)) return
  try { await del(`/admin/sessions/${id}`); await load() } catch (e: any) { error.value = e.message }
}
async function exportAudit() {
  try {
    const q = auditQuery.value.trim() ? `?q=${encodeURIComponent(auditQuery.value.trim())}` : ''
    const res = await fetch('/api/admin/audit/export' + q, { credentials: 'same-origin' })
    if (!res.ok) throw new Error('导出失败')
    const blob = await res.blob()
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'deskgw-audit.csv'
    a.click()
    setTimeout(() => URL.revokeObjectURL(a.href), 4000)
  } catch (e: any) { error.value = e.message }
}
async function saveSettings() {
  try {
    await put('/admin/settings', {
      session_idle_min: String(settings.session_idle_min),
      max_upload_mb: String(settings.max_upload_mb),
    })
    error.value = ''
  } catch (e: any) { error.value = e.message }
}
onMounted(load)
</script>
