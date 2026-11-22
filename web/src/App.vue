<template>
  <div class="shell">
    <header v-if="state.user && !inSession" class="topbar">
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
        <button class="link" @click="logout">退出</button>
      </div>
    </header>
    <main><router-view /></main>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { state } from './state'
import { post } from './api'
import { useRouter, useRoute } from 'vue-router'

const router = useRouter()
const route = useRoute()
const inSession = computed(() => route.name === 'session')
async function logout() {
  try { await post('/logout') } catch { /* ignore */ }
  state.user = null
  router.push({ name: 'login' })
}
</script>
