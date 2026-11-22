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
          <button disabled title="M2 实现">连接（RDP）</button>
          <button v-if="modes(h.modes).includes('perf')" disabled title="M8 实现">性能模式</button>
        </div>
      </article>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { get } from '../api'

interface Host {
  id: number; name: string; address: string; rdp_port: number
  group_name: string; note: string; enabled: boolean; modes: string
}
const hosts = ref<Host[]>([])
const query = ref('')
const loading = ref(true)
const error = ref('')
const filtered = computed(() => {
  const q = query.value.trim().toLowerCase()
  if (!q) return hosts.value
  return hosts.value.filter(h =>
    [h.name, h.address, h.group_name, h.note].join(' ').toLowerCase().includes(q))
})
function modes(s: string) { return s.split(',').map(x => x.trim()).filter(Boolean) }
function modeName(m: string) { return m === 'perf' ? '性能模式' : 'RDP' }

onMounted(async () => {
  try { hosts.value = await get<Host[]>('/hosts') }
  catch (e: any) { error.value = e.message }
  finally { loading.value = false }
})
</script>
