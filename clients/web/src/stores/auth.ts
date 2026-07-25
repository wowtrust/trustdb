import { defineStore } from 'pinia'
import { ref } from 'vue'
import { getSession, login as apiLogin, logout as apiLogout, type AdminPrincipal } from '@/lib/api'

export const useAuth = defineStore('auth', () => {
  const ok = ref(false)
  const username = ref<string | null>(null)
  const principal = ref<AdminPrincipal | null>(null)
  const loading = ref(false)

  async function refresh() {
    loading.value = true
    try {
      const s = await getSession()
      ok.value = !!s.ok
      principal.value = s.principal ?? null
      username.value = s.principal?.username ?? null
    } catch {
      ok.value = false
      username.value = null
      principal.value = null
    } finally {
      loading.value = false
    }
  }

  async function login(user: string, password: string, mfaCode = '', emergencyReason = '') {
    await apiLogin(user, password, mfaCode, emergencyReason)
    await refresh()
  }

  async function logout() {
    await apiLogout()
    ok.value = false
    username.value = null
    principal.value = null
  }

  function hasPermission(permission: string): boolean {
    return principal.value?.permissions.includes(permission) ?? false
  }

  return { ok, username, principal, loading, refresh, login, logout, hasPermission }
})
