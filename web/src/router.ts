import { createRouter, createWebHistory } from 'vue-router'
import { state, refreshMe } from './state'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/login', name: 'login', component: () => import('./views/LoginView.vue') },
    { path: '/', name: 'hosts', component: () => import('./views/HostsView.vue') },
    { path: '/session', name: 'session', component: () => import('./views/SessionView.vue') },
    { path: '/perf', name: 'perf', component: () => import('./views/PerfView.vue') },
    { path: '/admin', name: 'admin', component: () => import('./views/AdminView.vue') },
  ],
})

router.beforeEach(async (to) => {
  if (!state.ready) await refreshMe()
  if (!state.user && to.name !== 'login') return { name: 'login' }
  if (state.user && to.name === 'login') return { name: 'hosts' }
  if (to.name === 'admin' && state.user?.role !== 'admin') return { name: 'hosts' }
  return true
})
