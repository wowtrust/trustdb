import { defineStore } from 'pinia'
import { ref, computed } from 'vue'
import { api, hasNativeBridge, LocalRecord, RecordPage, RecordPageOptions } from '@/lib/api'

const DEFAULT_PAGE_SIZE = 50
const REFRESH_CONCURRENCY = 4

export const useRecords = defineStore('records', () => {
  const records = ref<LocalRecord[]>([])
  const loading = ref(false)
  const page = ref<RecordPage>({
    items: [],
    total: 0,
    limit: DEFAULT_PAGE_SIZE,
    offset: 0,
    has_more: false,
    source: 'server',
    total_exact: false,
  })
  const currentQuery = ref('')
  const currentLevel = ref('')
  const source = ref<'server' | 'local'>('server')
  const listError = ref('')
  const cursorByOffset = ref<Record<number, string>>({ 0: '' })

  const pending = computed(() => records.value.filter((r) => r.proof_level !== 'L5'))
  const canUseRemote = computed(() => source.value === 'server')

  function canRemoteQuery(_query: string, _level: string) {
    return true
  }

  async function loadPage(opts: Partial<RecordPageOptions> = {}) {
    loading.value = true
    try {
      if (!hasNativeBridge()) {
        records.value = []
        source.value = 'local'
        listError.value = '当前为浏览器预览；打开 TrustDB 桌面客户端后会连接本地存证与服务端分页。'
        page.value = {
          items: [],
          total: 0,
          limit: opts.limit ?? DEFAULT_PAGE_SIZE,
          offset: 0,
          has_more: false,
          source: 'local',
          total_exact: true,
        }
        return
      }

      const prevQuery = currentQuery.value
      const prevLevel = currentLevel.value
      const req: RecordPageOptions = {
        limit: opts.limit ?? page.value.limit ?? DEFAULT_PAGE_SIZE,
        offset: opts.offset ?? page.value.offset ?? 0,
        query: opts.query ?? currentQuery.value,
        level: opts.level ?? currentLevel.value,
      }
      currentQuery.value = req.query || ''
      currentLevel.value = req.level || ''

      if (req.offset === 0 || prevQuery !== currentQuery.value || prevLevel !== currentLevel.value) {
        cursorByOffset.value = { 0: '' }
      }

      if (canRemoteQuery(currentQuery.value, currentLevel.value)) {
        const cursor = req.offset === 0 ? '' : cursorByOffset.value[req.offset || 0]
        if ((req.offset || 0) === 0 || cursor !== undefined) {
          try {
            const next = await api.listRemoteRecordsPage({
              ...req,
              cursor,
              direction: 'desc',
            })
            page.value = next
            records.value = next.items ?? []
            source.value = 'server'
            listError.value = ''
            if (next.next_cursor) {
              cursorByOffset.value[(next.offset || 0) + (next.limit || DEFAULT_PAGE_SIZE)] = next.next_cursor
            }
            return
          } catch (e: any) {
            listError.value = `服务端分页不可用，已切回本地缓存：${String(e?.message ?? e)}`
          }
        }
      }

      const localCursor = req.offset === 0 ? '' : cursorByOffset.value[req.offset || 0]
      const next = await api.listRecordsPage({
        ...req,
        cursor: localCursor ?? '',
        direction: 'desc',
      })
      page.value = next
      records.value = next.items ?? []
      source.value = 'local'
      if (next.next_cursor) {
        cursorByOffset.value[(next.offset || 0) + (next.limit || DEFAULT_PAGE_SIZE)] = next.next_cursor
      }
    } finally {
      loading.value = false
    }
  }

  async function load() {
    await loadPage({ offset: 0, limit: DEFAULT_PAGE_SIZE, query: '', level: '' })
  }

  function upsert(rec: LocalRecord) {
    const idx = records.value.findIndex((r) => r.record_id === rec.record_id)
    if (idx >= 0) records.value[idx] = rec
    else records.value = [rec, ...records.value].slice(0, page.value.limit || DEFAULT_PAGE_SIZE)
  }

  async function refresh(recordID: string) {
    const rec = await api.refreshRecord(recordID)
    if (rec) upsert(rec)
    return rec
  }

  async function remove(recordID: string) {
    await api.deleteRecord(recordID)
    records.value = records.value.filter((r) => r.record_id !== recordID)
    page.value = { ...page.value, total: Math.max(0, page.value.total - 1) }
  }

  async function refreshAllPending(maxItems = 32) {
    const queue = pending.value.slice(0, maxItems)
    let cursor = 0
    async function worker() {
      while (cursor < queue.length) {
        const item = queue[cursor++]
        try { await refresh(item.record_id) } catch (_) { /* keep going */ }
      }
    }
    const workers = Array.from(
      { length: Math.min(REFRESH_CONCURRENCY, queue.length) },
      () => worker(),
    )
    await Promise.all(workers)
  }

  return {
    records,
    loading,
    page,
    source,
    listError,
    canUseRemote,
    pending,
    load,
    loadPage,
    upsert,
    refresh,
    remove,
    refreshAllPending,
  }
})
