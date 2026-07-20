<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { LogOut } from 'lucide-vue-next'
import { useAuth } from '@/stores/auth'
import { proxyGet } from '@/lib/api'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import { locale } from '@/i18n'

const route = useRoute()
const router = useRouter()
const auth = useAuth()
const healthOk = ref<boolean | null>(null)
const now = ref(new Date())
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'
let timer: number | undefined

const items = [
  ['/dashboard', '概览'], ['/metrics', '指标'], ['/records', '记录'],
  ['/batches', '批次'], ['/global-tree', '全局树'], ['/settings', '系统设置'],
] as const
const time = computed(() => now.value.toLocaleTimeString(locale.value, { hour12: false }))

async function ping() {
  if (demoMode) { healthOk.value = true; return }
  try { const response = await proxyGet('/healthz'); healthOk.value = response.ok } catch { healthOk.value = false }
}
async function logout() { await auth.logout(); await router.push('/login') }
function active(path: string) { return route.path === path || (path === '/batches' && route.path.startsWith('/batches/')) }

onMounted(() => { ping(); timer = window.setInterval(() => { now.value = new Date() }, 1000) })
onUnmounted(() => { if (timer) window.clearInterval(timer) })
</script>

<template>
  <header class="wa-header">
    <RouterLink class="wa-brand" to="/dashboard"><strong>TRUSTDB</strong><span>ADMIN</span></RouterLink>
    <nav aria-label="管理端导航"><RouterLink v-for="item in items" :key="item[0]" :to="item[0]" :class="{ active: active(item[0]) }">{{ item[1] }}</RouterLink></nav>
    <div class="wa-header__actions">
      <LanguageSwitcher compact />
      <div class="wa-header__status">
        <span><i :class="{ offline: healthOk === false }" />{{ healthOk === false ? '服务不可达' : '服务在线' }}</span>
        <em>12 ms</em><b />
        <time>{{ time }}</time>
        <button type="button" title="退出登录" @click="logout"><LogOut :size="15" /></button>
      </div>
    </div>
  </header>
</template>
