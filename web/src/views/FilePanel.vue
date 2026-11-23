<template>
  <aside class="file-panel">
    <div class="fp-head">
      <span>文件传输</span>
      <button class="icon" @click="$emit('close')" title="关闭">×</button>
    </div>

    <div v-if="!token" class="fp-body">
      <p class="muted small">首次打开需验证文件访问权限，将使用本次会话的 Windows 凭据。</p>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary" :disabled="busy" @click="acquire">{{ busy ? '验证中…' : '启用文件传输' }}</button>
    </div>

    <div v-else class="fp-body">
      <div class="fp-path">
        <input v-model="share" @change="reload" title="共享名，默认 C$" />
        <span>\</span>
        <code>{{ displayPath }}</code>
      </div>
      <div class="fp-toolbar">
        <button @click="goUp" :disabled="!path">上级</button>
        <button @click="reload">刷新</button>
        <button @click="newFolder">新建文件夹</button>
        <label class="upload">上传<input type="file" multiple @change="onFiles" /></label>
      </div>
      <p v-if="error" class="error">{{ error }}</p>

      <div class="fp-list">
        <div class="fp-row head"><span>名称</span><span>大小</span><span>操作</span></div>
        <div v-for="e in entries" :key="e.name" class="fp-row" @dblclick="openEntry(e)">
          <span class="fp-name" :title="e.name">{{ e.is_dir ? '[目录] ' : '' }}{{ e.name }}</span>
          <span class="fp-size">{{ e.is_dir ? '—' : fmtSize(e.size) }}</span>
          <span class="fp-ops">
            <button v-if="!e.is_dir" @click.stop="download(e)">下载</button>
            <button @click.stop="renameEntry(e)">重命名</button>
            <button class="danger" @click.stop="deleteEntry(e)">删除</button>
          </span>
        </div>
        <p v-if="!entries.length && !busy" class="muted small">此目录为空。</p>
      </div>

      <div v-if="transfers.length" class="fp-transfers">
        <div v-for="t in transfers" :key="t.id" class="fp-transfer">
          <span class="ft-name">{{ t.name }}</span>
          <span class="ft-state">{{ t.state }}</span>
          <div class="ft-bar"><div :style="{ width: t.pct + '%' }"></div></div>
        </div>
      </div>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue'
import { post, get, uploadChunk } from '../api'
import type { Credentials } from '../rdp'

const props = defineProps<{ sessionId: number; creds: Credentials }>()
defineEmits(['close'])

interface Entry { name: string; is_dir: boolean; size: number; mtime: number }
interface Transfer { id: number; name: string; state: string; pct: number }

const token = ref('')
const share = ref('C$')
const path = ref('')
const entries = ref<Entry[]>([])
const error = ref('')
const busy = ref(false)
const transfers = ref<Transfer[]>([])
let tid = 0

const displayPath = ref('\\')
const h = () => ({ 'X-File-Token': token.value })

async function acquire() {
  busy.value = true; error.value = ''
  try {
    const r = await post<{ token: string }>('/files/token', {
      session_id: props.sessionId,
      username: props.creds.username,
      password: props.creds.password,
      domain: props.creds.domain,
    })
    token.value = r.token
    await reload()
  } catch (e: any) { error.value = e.message || '验证失败' }
  finally { busy.value = false }
}

async function reload() {
  if (!token.value) return
  busy.value = true; error.value = ''
  try {
    entries.value = await get<Entry[]>('/files/list?share=' + encodeURIComponent(share.value) +
      '&path=' + encodeURIComponent(path.value), h())
    displayPath.value = '\\' + path.value.replace(/\//g, '\\')
  } catch (e: any) { error.value = e.message || '列目录失败' }
  finally { busy.value = false }
}

function openEntry(e: Entry) {
  if (e.is_dir) { path.value = path.value ? path.value + '\\' + e.name : e.name; reload() }
}
function goUp() {
  const i = path.value.lastIndexOf('\\')
  path.value = i < 0 ? '' : path.value.slice(0, i)
  reload()
}
function fullPath(name: string) { return path.value ? path.value + '\\' + name : name }

async function onFiles(ev: Event) {
  const input = ev.target as HTMLInputElement
  const files = Array.from(input.files || [])
  input.value = ''
  const chunkSize = 4 * 1024 * 1024
  for (const file of files) {
    const tr: Transfer = { id: ++tid, name: file.name, state: '上传中', pct: 0 }
    transfers.value.push(tr)
    let uploadId = ''
    try {
      // 整条上传复用一条 SMB 连接：分片之间不再重复 NTLM 认证。
      const b = await post<{ upload_id: string }>('/files/upload/begin', {
        share: share.value, path: fullPath(file.name), size: file.size,
      }, h())
      uploadId = b.upload_id
      // 零字节文件也要走一次 begin/finish，否则远端不会创建文件。
      for (let offset = 0; offset < file.size; offset += chunkSize) {
        const chunk = file.slice(offset, Math.min(offset + chunkSize, file.size))
        const q = '/files/upload/chunk?upload_id=' + encodeURIComponent(uploadId) + '&offset=' + offset
        const r = await uploadChunk<{ offset: number }>(q, chunk, h())
        tr.pct = Math.min(100, Math.round(r.offset * 100 / (file.size || 1)))
      }
      await post('/files/upload/finish', {
        upload_id: uploadId, share: share.value, path: fullPath(file.name),
      }, h())
      tr.state = '完成'; tr.pct = 100
    } catch (e: any) {
      tr.state = '失败：' + (e.message || '上传错误')
      if (uploadId) {
        try { await post('/files/upload/abort', { upload_id: uploadId }, h()) } catch { /* ignore */ }
      }
    }
    setTimeout(() => { transfers.value = transfers.value.filter(x => x.id !== tr.id) }, 8000)
  }
  reload()
}

function download(e: Entry) {
  // 交给浏览器原生下载：流式写盘，不把整个文件读进内存。
  // 下载接口额外接受 ?ft= 令牌，因为 <a download> 无法附加请求头。
  const q = '/api/files/download?share=' + encodeURIComponent(share.value) +
    '&path=' + encodeURIComponent(fullPath(e.name)) +
    '&ft=' + encodeURIComponent(token.value)
  const a = document.createElement('a')
  a.href = q
  a.download = e.name
  document.body.appendChild(a)
  a.click()
  a.remove()
}

async function newFolder() {
  const name = window.prompt('新文件夹名称')
  if (!name) return
  try {
    await post('/files/mkdir', { share: share.value, path: fullPath(name) }, h())
    reload()
  } catch (e: any) { error.value = e.message || '创建失败' }
}
async function renameEntry(e: Entry) {
  const name = window.prompt('新名称', e.name)
  if (!name || name === e.name) return
  try {
    await post('/files/rename', { share: share.value, path: fullPath(e.name), new_path: fullPath(name) }, h())
    reload()
  } catch (err: any) { error.value = err.message || '重命名失败' }
}
async function deleteEntry(e: Entry) {
  if (!window.confirm(`删除 ${e.name}？`)) return
  try {
    await post('/files/delete', { share: share.value, path: fullPath(e.name) }, h())
    reload()
  } catch (err: any) { error.value = err.message || '删除失败' }
}

function fmtSize(n: number) {
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

onBeforeUnmount(() => { token.value = ''; entries.value = [] })
</script>

<style scoped>
.file-panel { width: 320px; flex: none; display: flex; flex-direction: column; height: 100%;
  background: #1b1e24; color: #e5e7eb; border-left: 1px solid #2a2e37; }
.fp-head { display: flex; align-items: center; padding: 12px 14px; font-size: 13px;
  border-bottom: 1px solid #2a2e37; }
.fp-head .icon { margin-left: auto; background: none; border: none; color: #9ca3af; font-size: 18px; cursor: pointer; }
.fp-body { flex: 1; min-height: 0; display: flex; flex-direction: column; gap: 10px; padding: 12px; overflow: auto; }
.fp-body .muted { color: #9ca3af; }
.fp-body .small { font-size: 12px; }
.fp-body .error { color: #fca5a5; font-size: 12px; margin: 0; }
.fp-path { display: flex; align-items: center; gap: 6px; font-size: 12px; }
.fp-path input { width: 64px; padding: 4px 6px; font: inherit; font-size: 12px;
  background: #262a33; color: #e5e7eb; border: 1px solid #3a3f4b; border-radius: 4px; }
.fp-path code { color: #9ca3af; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fp-toolbar { display: flex; flex-wrap: wrap; gap: 6px; }
.fp-toolbar button, .upload { padding: 4px 8px; font: inherit; font-size: 12px; cursor: pointer;
  background: #262a33; color: #e5e7eb; border: 1px solid #3a3f4b; border-radius: 5px; }
.fp-toolbar button:disabled { opacity: .45; }
.upload input { display: none; }
.fp-list { flex: 1; min-height: 80px; overflow: auto; }
.fp-row { display: grid; grid-template-columns: 1fr 60px 100px; gap: 4px; align-items: center;
  padding: 6px 2px; font-size: 12px; border-bottom: 1px solid #262a33; }
.fp-row.head { color: #9ca3af; }
.fp-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fp-size { color: #9ca3af; text-align: right; }
.fp-ops { display: flex; gap: 3px; justify-content: flex-end; }
.fp-ops button { padding: 1px 4px; font: inherit; font-size: 11px; cursor: pointer;
  background: #262a33; color: #e5e7eb; border: 1px solid #3a3f4b; border-radius: 4px; }
.fp-ops button.danger { color: #fca5a5; }
.fp-transfers { border-top: 1px solid #2a2e37; padding-top: 8px; display: flex; flex-direction: column; gap: 6px; }
.fp-transfer { font-size: 11px; }
.ft-name { display: inline-block; max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ft-state { float: right; color: #9ca3af; }
.ft-bar { height: 3px; background: #343945; border-radius: 2px; margin-top: 3px; }
.ft-bar > div { height: 3px; background: #2563eb; border-radius: 2px; }
</style>
