import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, Settings } from '@/lib/api'

const defaultSettings: Settings = {
  server_url: 'http://127.0.0.1:8080',
  server_transport: 'http',
  server_ca_file: '',
  server_name: '',
  server_ca_pins_sha256: '',
  client_tls_cert_file: '',
  client_tls_key_file: '',
  tls_reload_interval: '1m',
  server_public_key_b64: '',
  anchor_plugin_command: '',
  anchor_plugin_args_text: '',
  anchor_plugin_start_timeout: '10s',
  anchor_plugin_rpc_timeout: '30s',
  default_media_type: 'application/octet-stream',
  default_event_type: 'file.snapshot',
  theme: 'dark',
}

export const useSettings = defineStore('settings', () => {
  const settings = ref<Settings>({ ...defaultSettings })
  const loading = ref(false)

  async function load() {
    loading.value = true
    try {
      const s = await api.getSettings()
      settings.value = { ...defaultSettings, ...(s ?? {}) }
      applyTheme(settings.value.theme)
    } finally {
      loading.value = false
    }
  }

  async function save(partial: Partial<Settings>) {
    const next = { ...defaultSettings, ...settings.value, ...partial } as Settings
    await api.saveSettings(next)
    settings.value = next
    applyTheme(next.theme)
  }

  function applyTheme(theme: string) {
    const root = document.documentElement
    const prefersDark = window.matchMedia?.('(prefers-color-scheme: dark)').matches
    // The redesigned client is dark-first. Auto now biases toward the
    // Loki-inspired command surface, while explicit light remains possible.
    const dark = theme === 'dark' || theme === 'auto' || (theme === '' && prefersDark)
    root.classList.toggle('dark', !!dark)
  }

  return { settings, loading, load, save }
})
