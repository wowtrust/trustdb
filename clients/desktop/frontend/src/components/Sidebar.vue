<script setup lang="ts">
import { RouterLink, useRoute } from 'vue-router'
import { computed } from 'vue'
import { LayoutGrid, CirclePlus, FileText, ShieldCheck, Activity, KeyRound, Settings as SettingsIcon, Copy, Network } from 'lucide-vue-next'
import { useSettings } from '@/stores/settings'
import { storeToRefs } from 'pinia'
import TrustDBLogo from './TrustDBLogo.vue'

const route = useRoute()
const settings = useSettings()
const { settings: cfg } = storeToRefs(settings)
const activePath = computed(() => route.path)
const items = [
  { to: '/dashboard', label: '概览', icon: LayoutGrid },
  { to: '/attest', label: '新建存证', icon: CirclePlus },
  { to: '/records', label: '存证记录', icon: FileText },
  { to: '/verify', label: '验证证据', icon: ShieldCheck },
  { to: '/anchors', label: '锚系统', icon: Network },
  { to: '/metrics', label: '指标面板', icon: Activity },
  { to: '/keys', label: '身份密钥', icon: KeyRound },
  { to: '/settings', label: '设置', icon: SettingsIcon },
] as const

function isActive(to: string) {
  return activePath.value === to || (to === '/dashboard' && activePath.value === '/')
}

async function copyEndpoint() {
  try { await navigator.clipboard.writeText(cfg.value.server_url || '') } catch { /* native shell may deny */ }
}
</script>

<template>
  <aside class="td-sidebar">
    <div class="td-brand drag-region">
      <TrustDBLogo :size="45" />
      <div>
        <strong>TRUSTDB</strong>
        <span>客户端</span>
      </div>
    </div>
    <nav class="td-side-nav no-drag" aria-label="客户端导航">
      <RouterLink v-for="item in items" :key="item.to" :to="item.to" :class="{ active: isActive(item.to) }">
        <component :is="item.icon" :size="19" :stroke-width="1.7" />
        <span>{{ item.label }}</span>
      </RouterLink>
    </nav>
    <div class="td-endpoint no-drag">
      <span>客户端端点</span>
      <button type="button" @click="copyEndpoint" title="复制端点">
        <code>{{ cfg.server_url || 'http://127.0.0.1:9090' }}</code>
        <Copy :size="14" />
      </button>
    </div>
  </aside>
</template>
