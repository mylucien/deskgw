<template>
  <div class="workspace">
    <div class="ws-top">
      <span class="logo">DG</span>
      <div class="tabs">
        <div v-for="t in workspace.tabs" :key="t.key" class="tab"
          :class="{ active: t.key === workspace.active }" @click="workspace.active = t.key">
          <span class="dot" :class="t.status"></span>
          <span class="tab-name">{{ t.hostName }}</span>
          <button class="tab-x" @click.stop="close(t.key)" title="关闭">×</button>
        </div>
        <button class="add-tab" @click="goHosts" :disabled="workspace.tabs.length >= MAX_TABS" title="新建连接">+</button>
      </div>
      <button class="exit" @click="exitWorkspace">退出</button>
    </div>
    <div class="ws-body">
      <p v-if="!workspace.tabs.length" class="empty">没有打开的会话。<a @click="goHosts">前往主机列表</a></p>
      <template v-for="t in workspace.tabs" :key="t.key">
        <div v-show="t.key === workspace.active" class="ws-pane">
          <RdpCanvas :tab="t" :active="t.key === workspace.active" />
        </div>
      </template>
    </div>
    <p v-if="notice" class="notice">{{ notice }}</p>
  </div>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import RdpCanvas from './RdpCanvas.vue'
import { workspace, closeTab, MAX_TABS } from '../sessionTabs'

const router = useRouter()
const notice = ref('')

function close(key: string) { closeTab(key); notice.value = '' }
function goHosts() {
  if (workspace.tabs.length >= MAX_TABS) {
    notice.value = `最多同时打开 ${MAX_TABS} 个会话，请先关闭一个标签`
    return
  }
  router.push({ name: 'hosts' })
}
function exitWorkspace() { router.push({ name: 'hosts' }) }

onMounted(() => {
  if (workspace.tabs.length >= MAX_TABS) notice.value = `最多同时打开 ${MAX_TABS} 个会话`
})
</script>

<style scoped>
.workspace { display: flex; flex-direction: column; height: 100vh; background: #0f1115; color: #e5e7eb; }
.ws-top { display: flex; align-items: center; gap: 12px; height: 46px; padding: 0 12px;
  background: #16181d; border-bottom: 1px solid #2a2e37; flex: none; }
.ws-top .logo { display: grid; place-items: center; width: 26px; height: 26px; border-radius: 6px;
  background: #2563eb; color: #fff; font-size: 11px; flex: none; }
.tabs { display: flex; align-items: center; gap: 4px; flex: 1; min-width: 0; overflow-x: auto; }
.tab { display: flex; align-items: center; gap: 6px; padding: 6px 8px 6px 10px; cursor: pointer;
  font-size: 12px; color: #9ca3af; border: 1px solid transparent; border-radius: 6px 6px 0 0; white-space: nowrap; }
.tab.active { color: #e5e7eb; background: #1b1e24; border-color: #2a2e37; }
.tab .dot { width: 7px; height: 7px; border-radius: 50%; background: #6b7280; flex: none; }
.tab .dot.connected { background: #22c55e; }
.tab .dot.error { background: #ef4444; }
.tab .dot.connecting { background: #eab308; }
.tab-name { max-width: 140px; overflow: hidden; text-overflow: ellipsis; }
.tab-x { background: none; border: none; color: #6b7280; cursor: pointer; font-size: 15px; line-height: 1; padding: 0 2px; }
.tab-x:hover { color: #fca5a5; }
.add-tab { background: none; border: 1px dashed #3a3f4b; color: #9ca3af; border-radius: 6px;
  cursor: pointer; font-size: 15px; width: 26px; height: 26px; flex: none; }
.add-tab:disabled { opacity: .4; }
.exit { background: none; border: 1px solid #3a3f4b; color: #9ca3af; border-radius: 6px;
  cursor: pointer; font: inherit; font-size: 12px; padding: 4px 10px; flex: none; }
.ws-body { flex: 1; min-height: 0; position: relative; }
.ws-pane { position: absolute; inset: 0; }
.empty { position: absolute; inset: 0; display: grid; place-items: center; color: #9ca3af; }
.empty a { color: #93c5fd; cursor: pointer; margin-left: 6px; }
.notice { position: absolute; bottom: 16px; left: 50%; transform: translateX(-50%); margin: 0;
  background: #7c2d12; color: #fed7aa; padding: 8px 16px; border-radius: 8px; font-size: 12px; }
</style>
