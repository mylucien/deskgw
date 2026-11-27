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
        <input v-model="share" list="fp-shares" title="共享名，默认 C$" @change="onShareChange" />
        <datalist id="fp-shares">
          <option v-for="s in COMMON_SHARES" :key="s" :value="s" />
        </datalist>
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
        <!-- 单击进入目录：原来只认双击，触屏和手机浏览器几乎打不开子目录。 -->
        <div v-for="e in sorted" :key="e.name" class="fp-row" @click="openEntry(e)" @dblclick="openEntry(e)">
          <span class="fp-name" :title="e.name">
            <span class="fp-kind">{{ e.is_dir ? '📁' : '📄' }}</span>{{ e.name }}
          </span>
          <span class="fp-size">{{ e.is_dir ? '—' : fmtSize(e.size) }}</span>
          <span class="fp-ops">
            <button v-if="!e.is_dir" @click.stop="download(e)">下载</button>
            <button @click.stop="renameEntry(e)">重命名</button>
            <button class="danger" @click.stop="deleteEntry(e)">删除</button>
          </span>
        </div>
        <p v-if="!sorted.length && !busy" class="muted small">此目录为空。</p>
      </div>

      <div v-if="transfers.length" class="fp-transfers">
        <div v-for="t in transfers" :key="t.id" class="fp-transfer">
          <span class="ft-name">{{ t.name }}</span>
          <span class="ft-state">{{ t.state }}</span>
          <button v-if="t.cancellable" class="ft-x" @click="cancelTransfer(t)" title="取消">×</button>
          <button v-else class="ft-x" @click="dismissTransfer(t)" title="清除">×</button>
          <div class="ft-bar"><div :style="{ width: t.pct + '%' }"></div></div>
        </div>
      </div>
    </div>
  </aside>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, ref } from 'vue'
import { post, get, uploadChunk } from '../api'
import type { Credentials } from '../rdp'

const props = defineProps<{ sessionId: number; creds: Credentials }>()
defineEmits(['close'])

interface Entry { name: string; is_dir: boolean; size: number; mtime: number }
interface Transfer {
  id: number; name: string; state: string; pct: number
  /** 正在上传，可以取消。 */
  cancellable: boolean
  /** 已被用户取消，上传循环看到后尽快退出。 */
  cancelled: boolean
}

// 常见共享名给个下拉，省得用户猜；默认 C$ 对普通域账号往往不可用。
const COMMON_SHARES = ['C$', 'D$', 'E$', 'ADMIN$', 'Users', 'Public', 'Share']

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

// 目录在前，其余按名称排序（中文按拼音，数字按数值）。
const sorted = computed(() => [...entries.value].sort((a, b) => {
  if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
  return a.name.localeCompare(b.name, 'zh-Hans-CN', { numeric: true, sensitivity: 'base' })
}))

// 令牌失效（过期或会话结束）后就地退回「启用文件传输」，不整页跳登录。
function tokenExpired(e: any): boolean {
  return e?.code === 'fileToken' || e?.code === 'session'
}
function fail(e: any, fallback: string) {
  if (tokenExpired(e)) {
    // 还在跑的上传一并停掉：继续发分片只会一律 403。
    for (const t of transfers.value) if (t.cancellable) { t.cancelled = true; t.state = '已取消' }
    token.value = ''
    error.value = '文件会话已失效，请重新点击「启用文件传输」'
    return
  }
  error.value = e?.message || fallback
}

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

// 快速连点「刷新」时，先发的请求可能后到，把新目录内容覆盖成旧目录的。
// 只接受最后一次请求的结果。
let reloadSeq = 0
async function reload() {
  if (!token.value) return
  const my = ++reloadSeq
  busy.value = true; error.value = ''
  try {
    const list = await get<Entry[]>('/files/list?share=' + encodeURIComponent(share.value) +
      '&path=' + encodeURIComponent(path.value), h())
    if (my !== reloadSeq) return
    entries.value = list
    displayPath.value = '\\' + path.value.replace(/\//g, '\\')
  } catch (e: any) {
    if (my !== reloadSeq) return
    fail(e, '列目录失败')
  } finally {
    if (my === reloadSeq) busy.value = false
  }
}

function onShareChange() {
  // 换共享名后原路径多半不存在，直接回根目录。
  path.value = ''
  entries.value = []
  reload()
}

function openEntry(e: Entry) {
  if (!e.is_dir) return
  path.value = path.value ? path.value + '\\' + e.name : e.name
  reload()
}
function goUp() {
  const i = path.value.lastIndexOf('\\')
  path.value = i < 0 ? '' : path.value.slice(0, i)
  reload()
}
function join(dir: string, name: string) { return dir ? dir + '\\' + name : name }
const fullPath = (name: string) => join(path.value, name)

async function onFiles(ev: Event) {
  const input = ev.target as HTMLInputElement
  const files = Array.from(input.files || [])
  input.value = ''
  if (!files.length) return
  // 目录必须在循环外快照：中途切目录时，后面的文件会跟着传到新目录去。
  const dir = path.value
  const shareAtStart = share.value
  const chunkSize = 4 * 1024 * 1024

  for (const file of files) {
    const tr: Transfer = {
      id: ++tid, name: file.name, state: '上传中', pct: 0,
      cancellable: true, cancelled: false,
    }
    transfers.value.push(tr)
    let uploadId = ''
    try {
      const begin = (overwrite = false) => post<{ upload_id: string }>('/files/upload/begin', {
        share: shareAtStart, path: join(dir, file.name), size: file.size, overwrite,
      }, h())

      let b: { upload_id: string }
      try {
        // 整条上传复用一条 SMB 连接：分片之间不再重复 NTLM 认证。
        b = await begin(false)
      } catch (e: any) {
        if (e?.code !== 'exists') throw e
        // 同名文件不再静默覆盖：先问一句。
        if (!window.confirm(`目标目录已有「${file.name}」，覆盖吗？`)) {
          tr.state = '已取消'; tr.pct = 0
          continue
        }
        b = await begin(true)
      }
      uploadId = b.upload_id
      // 零字节文件也要走一次 begin/finish，否则远端不会创建文件。
      let offset = 0
      while (offset < file.size) {
        if (tr.cancelled) throw new Error('已取消')
        const end = Math.min(offset + chunkSize, file.size)
        const q = '/files/upload/chunk?upload_id=' + encodeURIComponent(uploadId) + '&offset=' + offset
        try {
          const r = await uploadChunk<{ offset: number }>(q, file.slice(offset, end), h())
          offset = r.offset
        } catch (e: any) {
          // 服务端偏移和本地不一致（上一次分片其实写成功了）：从它给的
          // 位置继续，不要把整条上传作废。
          if (e?.code === 'uploadOffset' && typeof e?.data?.offset === 'number') {
            offset = e.data.offset
            continue
          }
          throw e
        }
        tr.pct = Math.min(100, Math.round(offset * 100 / (file.size || 1)))
      }
      if (tr.cancelled) throw new Error('已取消')
      await post('/files/upload/finish', { upload_id: uploadId }, h())
      tr.state = '完成'; tr.pct = 100
    } catch (e: any) {
      tr.state = '失败：' + (e?.message || '上传错误')
      if (uploadId) {
        try { await post('/files/upload/abort', { upload_id: uploadId }, h()) } catch { /* ignore */ }
      }
      if (tokenExpired(e)) fail(e, '上传失败')
    } finally {
      tr.cancellable = false
    }
  }
  void reload()
}

function cancelTransfer(t: Transfer) {
  if (!t.cancellable) return
  t.cancelled = true
  t.state = '取消中…'
}
function dismissTransfer(t: Transfer) {
  transfers.value = transfers.value.filter(x => x.id !== t.id)
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
  // 原生下载没有回调，给一条可见反馈，几秒后自动消失。
  const tr: Transfer = {
    id: ++tid, name: e.name, state: '已开始下载', pct: 100, cancellable: false, cancelled: false,
  }
  transfers.value.push(tr)
  window.setTimeout(() => dismissTransfer(tr), 4000)
}

async function newFolder() {
  const name = window.prompt('新文件夹名称')
  if (!name) return
  try {
    await post('/files/mkdir', { share: share.value, path: fullPath(name) }, h())
    reload()
  } catch (e: any) { fail(e, '创建失败') }
}
async function renameEntry(e: Entry) {
  const name = window.prompt('新名称', e.name)
  if (!name || name === e.name) return
  try {
    await post('/files/rename', { share: share.value, path: fullPath(e.name), new_path: fullPath(name) }, h())
    reload()
  } catch (err: any) { fail(err, '重命名失败') }
}
async function deleteEntry(e: Entry) {
  if (!window.confirm(`删除 ${e.name}？`)) return
  try {
    await post('/files/delete', { share: share.value, path: fullPath(e.name) }, h())
    reload()
  } catch (err: any) { fail(err, '删除失败') }
}

function fmtSize(n: number) {
  if (n < 1024) return n + ' B'
  if (n < 1048576) return (n / 1024).toFixed(1) + ' KB'
  if (n < 1073741824) return (n / 1048576).toFixed(1) + ' MB'
  return (n / 1073741824).toFixed(2) + ' GB'
}

onBeforeUnmount(() => {
  // 关面板就停掉还在跑的上传：否则分片请求会继续打到已经清空的令牌上。
  for (const t of transfers.value) if (t.cancellable) t.cancelled = true
  token.value = ''
  entries.value = []
})
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
  padding: 6px 2px; font-size: 12px; border-bottom: 1px solid #262a33; cursor: default; }
.fp-row.head { color: #9ca3af; cursor: default; }
.fp-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.fp-kind { margin-right: 4px; font-size: 11px; }
.fp-size { color: #9ca3af; text-align: right; }
.fp-ops { display: flex; gap: 3px; justify-content: flex-end; }
.fp-ops button { padding: 1px 4px; font: inherit; font-size: 11px; cursor: pointer;
  background: #262a33; color: #e5e7eb; border: 1px solid #3a3f4b; border-radius: 4px; }
.fp-ops button.danger { color: #fca5a5; }
.fp-transfers { border-top: 1px solid #2a2e37; padding-top: 8px; display: flex; flex-direction: column; gap: 6px; }
.fp-transfer { font-size: 11px; display: grid; grid-template-columns: 1fr auto auto; gap: 4px; align-items: center; }
.ft-name { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.ft-state { color: #9ca3af; }
.ft-x { width: 16px; height: 16px; padding: 0; line-height: 1; font-size: 12px;
  background: transparent; border: 0; color: #9ca3af; cursor: pointer; }
.ft-x:hover { color: #fca5a5; }
.ft-bar { grid-column: 1 / -1; height: 3px; background: #343945; border-radius: 2px; }
.ft-bar > div { height: 3px; background: #2563eb; border-radius: 2px; }
</style>
