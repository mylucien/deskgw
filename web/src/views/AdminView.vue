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
        <label>主机 ID（1–4294967295）<input v-model.number="hostForm.id" type="number" required /></label>
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

    <section v-else-if="tab === 'audit'" class="panel">
      <div class="panel-head">
        <h3>审计日志</h3>
        <input v-model="auditQuery" placeholder="按用户 / 目标 / 详情搜索" @keyup.enter="loadAudit" />
        <button @click="loadAudit">查询</button>
      </div>
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
      <p class="muted small">性能模式设置将在 M8 启用。</p>
    </section>

    <section v-else class="panel">
      <h3>运行状态</h3>
      <div class="card"><pre>{{ status }}</pre></div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { get, post, put, del } from '../api'

const tabs = [
  { key: 'users', label: '用户' }, { key: 'hosts', label: '主机' },
  { key: 'audit', label: '审计' }, { key: 'settings', label: '设置' },
  { key: 'status', label: '状态' },
]
const tab = ref('users')
const error = ref('')
const users = ref<any[]>([])
const hosts = ref<any[]>([])
const audit = ref<any[]>([])
const auditQuery = ref('')
const status = ref('')
const settings = reactive({ session_idle_min: 30, max_upload_mb: 2048 })
const userForm = ref<any>(null)
const hostForm = ref<any>(null)

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
function newHost() { hostForm.value = resetHost() }
function editHost(h: any) { hostForm.value = { ...resetHost(), ...h } }

async function load() {
  try {
    const [us, hs, st] = await Promise.all([
      get<any[]>('/admin/users'), get<any[]>('/admin/hosts'), get<any>('/admin/sessions'),
    ])
    users.value = us; hosts.value = hs; status.value = JSON.stringify(st, null, 2)
    const cfg = await get<Record<string, string>>('/admin/settings')
    settings.session_idle_min = Number(cfg.session_idle_min || 30)
    settings.max_upload_mb = Number(cfg.max_upload_mb || 2048)
    await loadAudit()
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
    const f = hostForm.value
    if (f.id) await put(`/admin/hosts/${f.id}`, f)
    else await post('/admin/hosts', f)
    hostForm.value = null; error.value = ''; await load()
  } catch (e: any) { error.value = e.message }
}
async function removeHost(h: any) {
  if (!confirm(`删除主机 ${h.name}？`)) return
  try { await del(`/admin/hosts/${h.id}`); await load() } catch (e: any) { error.value = e.message }
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
