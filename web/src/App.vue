<template>
  <div class="shell">
    <header v-if="state.user && !hideChrome" class="topbar">
      <div class="brand">
        <span class="logo">DG</span>
        <span>deskgw <small>远程桌面网关</small></span>
      </div>
      <nav>
        <router-link to="/">主机</router-link>
        <router-link v-if="state.user.role === 'admin'" to="/admin">管理</router-link>
      </nav>
      <div class="user">
        <span>{{ state.user.username }}</span>
        <span class="tag">{{ state.user.role }}</span>
        <button class="link" @click="openPassword">改密码</button>
        <button class="link" @click="logout">退出</button>
      </div>
    </header>
    <main>
      <router-view v-slot="{ Component }">
        <!-- 会话页必须保活：离开时卸载会关掉 WASM 会话、擦掉凭据，
             「新建连接」就会把正在用的标签变成一串点不开的死标签。 -->
        <keep-alive :include="['SessionView']">
          <component :is="Component" />
        </keep-alive>
      </router-view>
    </main>

    <div v-if="pwdOpen" class="pwd-mask" @click.self="closePassword">
      <form class="pwd-card card" @submit.prevent="savePassword">
        <h3>修改密码</h3>
        <p class="muted small">修改后其他设备上的登录会失效，当前这台保持在线。</p>
        <label>当前密码<input v-model="pwd.old" type="password" autocomplete="current-password" required /></label>
        <label>新密码（至少 8 位）<input v-model="pwd.next" type="password" autocomplete="new-password" required /></label>
        <label>确认新密码<input v-model="pwd.confirm" type="password" autocomplete="new-password" required /></label>
        <p v-if="pwdError" class="error">{{ pwdError }}</p>
        <div class="pwd-actions">
          <button type="button" @click="closePassword">取消</button>
          <button type="submit" class="primary" :disabled="pwdBusy">{{ pwdBusy ? '保存中…' : '保存' }}</button>
        </div>
      </form>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { state, applyMe } from './state'
import { get, post } from './api'
import { setMaxTabs, workspace } from './sessionTabs'
import { perfSession } from './perf'
import { pwdOpen, openPasswordDialog, closePasswordDialog, logoutNow } from './account'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
// 会话页与性能模式都是「整屏远程画面」：顶部状态条让位给画面，其中的导航、
// 账号与退出都挪进了各自的悬浮面板（性能模式在 PerfView 的面板里）。
const hideChrome = computed(() => route.name === 'session' || route.name === 'perf')

// 标签上限跟随服务端配额。
watch(() => state.limits.max_sessions, (n) => setMaxTabs(n), { immediate: true })

// 登录态是滑动的：只有 HTTP 请求才会续期。在 RDP 里连续用半小时以上，
// 服务端会话就过期了，下一次点文件面板或返回列表直接被踢回登录页。
// 每 4 分钟碰一次 /api/me，既续期也顺带同步配额变化。
//
// 后台标签页不能停：原来 hidden 就直接跳过，于是 RDP 标签挂后台半小时后
// 会话过期，切回来那一次 /me 拿 401，整页跳登录，所有会话和标签一起丢。
// 后台定时器会被浏览器降频到约每分钟一次，4 分钟的间隔照样成立；没有会话的
// 纯浏览页才跳过，省得白耗。
let heartbeat: number | undefined
function beat() {
  if (!state.user) return
  const busy = workspace.tabs.length > 0 || perfSession.current !== null
  if (document.visibilityState === 'hidden' && !busy) return
  get<{ user: any; limits: any }>('/me')
    .then((r) => { if (state.user) applyMe(r) })
    .catch(() => { /* 真的过期时 api.ts 会统一跳登录页 */ })
}
// 回到前台立刻补一次，避免手机锁屏后回来已经过期。
function onVisible() {
  if (document.visibilityState === 'visible') beat()
}

onMounted(() => {
  heartbeat = window.setInterval(beat, 4 * 60 * 1000)
  document.addEventListener('visibilitychange', onVisible)
})
onBeforeUnmount(() => {
  if (heartbeat) window.clearInterval(heartbeat)
  document.removeEventListener('visibilitychange', onVisible)
})

// ---- 自助改密 ----
// 弹窗开在 App 里，但「改密码」的入口散落在各页（顶栏、性能模式的悬浮面板），
// 所以开关放在 account.ts 里共享。
const pwdBusy = ref(false)
const pwdError = ref('')
const pwd = reactive({ old: '', next: '', confirm: '' })
function resetPwd() {
  pwd.old = ''; pwd.next = ''; pwd.confirm = ''; pwdError.value = ''
}
// 从别的页面打开的也要清成空白，不能带上一次没输完的内容。
watch(pwdOpen, (v) => { if (v) resetPwd() })
function openPassword() {
  resetPwd()
  openPasswordDialog()
}
function closePassword() {
  closePasswordDialog()
  resetPwd()
}
async function savePassword() {
  pwdError.value = ''
  if (pwd.next !== pwd.confirm) { pwdError.value = '两次输入的新密码不一致'; return }
  if (pwd.next.length < 8) { pwdError.value = '新密码至少 8 位'; return }
  pwdBusy.value = true
  try {
    await post('/password', { old_password: pwd.old, new_password: pwd.next })
    closePassword()
  } catch (e: any) {
    pwdError.value = e.message || '修改失败'
  } finally {
    pwdBusy.value = false
  }
}

async function logout() {
  await logoutNow()
  router.push({ name: 'login' })
}
</script>

<style scoped>
.pwd-mask { position: fixed; inset: 0; z-index: 40; display: grid; place-items: center;
  background: rgba(15, 17, 21, .45); }
.pwd-card { width: 340px; max-width: 92%; display: flex; flex-direction: column; gap: 12px; }
.pwd-card h3 { margin: 0; }
.pwd-card .error { margin: 0; font-size: 12px; }
.pwd-actions { display: flex; justify-content: flex-end; gap: 8px; }
</style>
