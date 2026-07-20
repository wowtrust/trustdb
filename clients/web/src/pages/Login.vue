<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import TrustDBLogo from '@/components/TrustDBLogo.vue'
import { useAuth } from '@/stores/auth'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'

const route = useRoute()
const router = useRouter()
const auth = useAuth()

const username = ref('')
const password = ref('')
const err = ref('')
const busy = ref(false)

async function submit() {
  err.value = ''
  busy.value = true
  try {
    await auth.login(username.value.trim(), password.value)
    const redir = typeof route.query.redirect === 'string' ? route.query.redirect : '/dashboard'
    await router.replace(redir || '/dashboard')
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="min-h-full flex items-center justify-center px-6 py-16">
    <div class="ambient-orb one"></div>
    <div class="ambient-orb two"></div>
    <section class="relative z-[1] w-full max-w-[420px] glass rounded-[28px] p-8 shadow-soft">
      <div class="absolute right-5 top-5"><LanguageSwitcher /></div>
      <div class="flex flex-col items-center gap-3">
        <div class="brand-logo-shell">
          <TrustDBLogo :size="56" />
        </div>
        <div class="text-center">
          <div class="font-display text-[26px] font-black uppercase tracking-[-0.04em] text-ink-50">TrustDB</div>
          <div class="kicker mt-1 text-[10px] font-bold">Admin Console</div>
        </div>
      </div>
      <form class="mt-8 space-y-4" @submit.prevent="submit">
        <Field label="用户名">
          <Input v-model="username" autocomplete="username" />
        </Field>
        <Field label="密码">
          <Input v-model="password" type="password" autocomplete="current-password" />
        </Field>
        <p v-if="err" class="text-[12px] text-danger">{{ err }}</p>
        <Button type="submit" class="w-full" :loading="busy">登录</Button>
      </form>
    </section>
  </div>
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
  inset: -8px;
  z-index: -1;
  border-radius: 22px;
  background: radial-gradient(circle at 50% 50%, rgba(0, 255, 34, .28), transparent 55%);
  filter: blur(8px);
  opacity: .5;
}
</style>
