<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api } from '@/lib/api'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'

const route = useRoute()
const healthOk = ref<boolean | null>(null)
let timer: number | undefined
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'

async function ping() {
  if (demoMode) { healthOk.value = true; return }
  try { healthOk.value = !!(await api.serverHealth()).ok } catch { healthOk.value = false }
}

onMounted(() => { ping(); timer = window.setInterval(ping, 15_000) })
onUnmounted(() => { if (timer) window.clearInterval(timer) })
</script>

<template>
  <header class="td-topbar drag-region">
    <h1>{{ route.meta.title ?? 'TrustDB' }}</h1>
    <div class="td-topbar__status no-drag">
      <LanguageSwitcher compact />
      <span :class="{ offline: healthOk === false }"><i />{{ healthOk === false ? '离线模式' : '系统在线' }}</span>
    </div>
  </header>
</template>
