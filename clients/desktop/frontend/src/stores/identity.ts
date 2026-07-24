import { defineStore } from 'pinia'
import { ref } from 'vue'
import {
  api,
  GenerateIdentityRequest,
  IdentityView,
  ImportIdentityRequest,
  ReferenceIdentityRequest,
  RotateIdentityRequest,
} from '@/lib/api'

export const useIdentity = defineStore('identity', () => {
  const identity = ref<IdentityView | null>(null)
  const loading = ref(false)

  async function load() {
    loading.value = true
    try {
      identity.value = (await api.getIdentity()) ?? null
    } finally {
      loading.value = false
    }
  }

  async function generate(request: GenerateIdentityRequest) {
    identity.value = await api.generateIdentity(request)
  }

  async function rotate(request: RotateIdentityRequest) {
    identity.value = await api.rotateIdentity(request)
  }

  async function importKey(request: ImportIdentityRequest) {
    identity.value = await api.importIdentity(request)
  }

  async function reference(request: ReferenceIdentityRequest) {
    identity.value = await api.referenceIdentity(request)
  }

  async function unlock(passphrase: string) {
    identity.value = await api.unlockIdentity(passphrase)
  }

  async function lock() {
    await api.lockIdentity()
    await load()
  }

  async function clear() {
    await api.clearIdentity()
    identity.value = null
  }

  return { identity, loading, load, generate, rotate, importKey, reference, unlock, lock, clear }
})
