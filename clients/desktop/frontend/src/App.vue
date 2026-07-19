<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Sidebar from '@/components/Sidebar.vue'
import TopBar from '@/components/TopBar.vue'
import ToastHost from '@/components/ToastHost.vue'
import Onboarding from '@/components/Onboarding.vue'
import { useSettings } from '@/stores/settings'
import { useIdentity } from '@/stores/identity'
import { useRecords } from '@/stores/records'

const settings = useSettings()
const identity = useIdentity()
const records = useRecords()
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'

const showOnboarding = ref(false)

onMounted(async () => {
  // Load persistent state in parallel so the UI gets painted once,
  // not three separate times as each individual store resolves.
  // The native Wails bridge is not present when the UI is reviewed in a
  // regular browser. Keep the shell usable there while native builds still
  // hydrate every store normally.
  await Promise.allSettled([settings.load(), identity.load(), records.load()])

  // Trigger the first-run wizard when this machine clearly hasn't
  // been set up yet — no signing identity loaded and the user has
  // never dismissed the wizard before. Using localStorage instead of
  // a server-side flag keeps the check purely UI state and avoids
  // another Settings struct migration.
  const dismissed = (() => {
    try { return !!localStorage.getItem('trustdb.onboarded') } catch { return false }
  })()
  if (!demoMode && !identity.identity && !dismissed) {
    showOnboarding.value = true
  }
})

// Called from the wizard when the user closes/finishes. We do NOT
// require a fresh identity here — a user who knows they'll import
// one later can still close the wizard without being trapped.
function closeOnboarding() {
  showOnboarding.value = false
}

// Re-expose a manual trigger on the window object so the Settings
// page (or a future menu item) can relaunch the wizard. Cheaper than
// introducing a dedicated event bus for a single call site.
declare global {
  interface Window { trustdbOpenOnboarding?: () => void }
}
if (typeof window !== 'undefined') {
  window.trustdbOpenOnboarding = () => { showOnboarding.value = true }
}
</script>

<template>
  <div class="app-shell td-app h-full w-full flex overflow-hidden">
    <div class="ambient-orb one"></div>
    <div class="ambient-orb two"></div>
    <Sidebar />
    <main class="relative z-[1] flex-1 h-full flex flex-col min-w-0">
      <TopBar />
      <div class="td-route flex-1 overflow-y-auto min-w-0">
        <router-view v-slot="{ Component, route }">
          <transition name="page" mode="out-in">
            <component :is="Component" :key="route.fullPath" />
          </transition>
        </router-view>
      </div>
    </main>
    <ToastHost />
    <Onboarding v-if="showOnboarding" @close="closeOnboarding" />
  </div>
</template>

<style>
.page-enter-active, .page-leave-active { transition: all .24s cubic-bezier(.2,.9,.2,1); }
.page-enter-from { opacity: 0; transform: translateY(14px) scale(.985); }
.page-leave-to   { opacity: 0; transform: translateY(-8px) scale(.99); }
</style>
