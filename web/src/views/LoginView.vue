<template>
  <div class="login-wrap">
    <form class="card login-card" @submit.prevent="submit">
      <h1>deskgw</h1>
      <p class="muted">OpenWrt Web 远程桌面网关</p>
      <label>用户名<input v-model="username" autocomplete="username" required autofocus /></label>
      <label>密码<input v-model="password" type="password" autocomplete="current-password" required /></label>
      <p v-if="error" class="error">{{ error }}</p>
      <button class="primary" :disabled="busy" type="submit">{{ busy ? '登录中…' : '登录' }}</button>
      <p class="muted small">凭据仅用于本网关身份认证。Windows 账户在建立远程会话时另行输入。</p>
    </form>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { post } from '../api'
import { state } from '../state'

const username = ref('')
const password = ref('')
const error = ref('')
const busy = ref(false)
const router = useRouter()

async function submit() {
  error.value = ''
  busy.value = true
  try {
    const { user } = await post<{ user: any }>('/login', {
      username: username.value, password: password.value,
    })
    password.value = ''
    state.user = user
    router.push({ name: 'hosts' })
  } catch (e: any) {
    error.value = e.message || '登录失败'
  } finally {
    busy.value = false
  }
}
</script>
