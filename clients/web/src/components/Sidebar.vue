<script setup lang="ts">
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { LayoutDashboard, Activity, ScrollText, Settings as SettingsIcon, LogOut, GitBranch, Network } from 'lucide-vue-next'
import { computed } from 'vue'
import TrustDBLogo from './TrustDBLogo.vue'
import { useAuth } from '@/stores/auth'

const route = useRoute()
const router = useRouter()
const auth = useAuth()

const navGroups = [
  {
    label: '运维',
    items: [
      { to: '/dashboard', label: '概览', icon: LayoutDashboard },
      { to: '/metrics', label: '指标', icon: Activity },
      { to: '/records', label: '记录', icon: ScrollText },
      { to: '/batches', label: '批次', icon: GitBranch },
      { to: '/global-tree', label: '全局树', icon: Network },
      { to: '/settings', label: '系统设置', icon: SettingsIcon },
    ],
  },
] as const

const activePath = computed(() => route.path)

function isActive(to: string): boolean {
  return activePath.value === to || (to === '/dashboard' && activePath.value === '/') || (to === '/batches' && activePath.value.startsWith('/batches/'))
}

async function doLogout() {
  await auth.logout()
  await router.push('/login')
}
</script>

<template>
  <aside class="relative z-[2] w-[244px] h-full flex flex-col glass hairline-r overflow-hidden">
    <div class="h-[74px] hairline-b flex items-center px-4">
      <div class="flex items-center gap-3">
        <div class="brand-logo-shell" aria-hidden="true">
          <TrustDBLogo :size="50" />
        </div>
        <div class="leading-none">
          <div class="font-display text-[22px] font-black uppercase tracking-[-0.055em] text-ink-50">TrustDB</div>
          <div class="mt-1 text-[9px] text-accent uppercase tracking-[0.26em]">Admin Console</div>
        </div>
      </div>
    </div>

    <nav class="flex-1 overflow-y-auto px-3 py-5">
      <div v-for="group in navGroups" :key="group.label" class="mb-6">
        <div class="kicker px-2 mb-2 text-[10px] font-bold">{{ group.label }}</div>
        <ul class="space-y-1">
          <li v-for="item in group.items" :key="item.to">
            <RouterLink
              :to="item.to"
              class="group relative flex items-center gap-2.5 h-10 px-3 rounded-[13px] text-[12.5px] transition overflow-hidden"
              :class="[
                isActive(item.to)
                  ? 'bg-accent shadow-acid'
                  : 'hover:bg-white/5 hover:text-ink-50'
              ]"
            >
              <span
                class="absolute left-0 top-2 bottom-2 w-[3px] rounded-full transition"
                :class="isActive(item.to) ? 'bg-[#031004]' : 'bg-accent/0 group-hover:bg-accent'"
              ></span>
              <component
                :is="item.icon"
                :size="15"
                class="shrink-0 transition"
                :class="isActive(item.to) ? 'text-[#031004] opacity-100' : 'text-ink-300 opacity-90 group-hover:text-ink-50'"
              />
              <span
                class="font-semibold transition"
                :class="isActive(item.to) ? 'text-[#031004]' : 'text-ink-300 group-hover:text-ink-50'"
              >{{ item.label }}</span>
            </RouterLink>
          </li>
        </ul>
      </div>
    </nav>

    <footer class="px-4 py-4 hairline-t">
      <div class="rounded-[16px] border border-white/10 bg-[#070807]/70 p-3">
        <div class="kicker text-[9px] font-bold">Session</div>
        <div class="mt-1 font-mono text-[11px] text-accent truncate">{{ auth.username || '—' }}</div>
        <div class="mt-1 text-[9px] text-ink-500 truncate">{{ auth.principal?.roles.join(' · ') || '—' }}</div>
        <button
          type="button"
          class="mt-3 w-full inline-flex items-center justify-center gap-2 rounded-[12px] border border-white/10 bg-white/5 px-3 py-2 text-[11px] font-semibold text-ink-200 hover:border-accent/40 hover:text-accent transition"
          @click="doLogout"
        >
          <LogOut :size="14" /> 退出
        </button>
      </div>
    </footer>
  </aside>
</template>

<style scoped>
.brand-logo-shell {
  position: relative;
  isolation: isolate;
  display: grid;
  place-items: center;
}

.brand-logo-shell::before {
  content: "";
  position: absolute;
  inset: -9px;
  z-index: -1;
  border-radius: 24px;
  background:
    radial-gradient(circle at 50% 50%, rgba(0, 255, 34, .32), transparent 56%),
    conic-gradient(from 120deg, transparent, rgba(0, 255, 34, .26), transparent 42%);
  filter: blur(9px);
  opacity: .46;
  animation: trustdb-brand-halo 4600ms ease-in-out infinite;
}

.brand-logo-shell::after {
  content: "";
  position: absolute;
  inset: -3px;
  z-index: -1;
  border-radius: 20px;
  border: 1px solid rgba(0, 255, 34, .14);
  opacity: .78;
}

.brand-logo-shell :deep(.trustdb-logo-mark) {
  position: relative;
  z-index: 1;
}

@keyframes trustdb-brand-halo {
  0%, 100% {
    opacity: .3;
    transform: scale(.96) rotate(0deg);
  }
  50% {
    opacity: .72;
    transform: scale(1.04) rotate(16deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .brand-logo-shell::before {
    animation: none;
  }
}
</style>
