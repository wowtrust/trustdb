<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from 'vue'
import { storeToRefs } from 'pinia'
import { useRecords } from '@/stores/records'
import { useToasts } from '@/stores/toasts'
import { api, LocalRecord } from '@/lib/api'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Drawer from '@/components/Drawer.vue'
import LevelBadge from '@/components/LevelBadge.vue'
import HashChip from '@/components/HashChip.vue'
import EmptyState from '@/components/EmptyState.vue'
import StatusDot from '@/components/StatusDot.vue'
import KV from '@/components/KV.vue'
import {
  RefreshCcw, Download, Trash2, Search, FolderOpen, FileText, Anchor, XCircle,
} from 'lucide-vue-next'
import { bytesToBase64, bytesToHex, coerceBytes, formatTime, humanSize, nanoToDate, relativeTime } from '@/lib/format'
import { decodeOtsProof, otsAcceptedCount, type OtsAnchorProof } from '@/lib/anchor'
import type { OtsUpgradeSummary } from '@/lib/api'

const records = useRecords()
const toasts = useToasts()
const { records: recs, page, source, listError } = storeToRefs(records)

const query = ref('')
const levelFilter = ref<'' | 'L1' | 'L2' | 'L3' | 'L4' | 'L5'>('')

const filtered = computed<LocalRecord[]>(() => recs.value)
const pageStart = computed(() => page.value.total === 0 ? 0 : page.value.offset + 1)
const pageEnd = computed(() => Math.min(page.value.offset + filtered.value.length, page.value.total))
const pageTotalLabel = computed(() => {
  if (page.value.total_exact) return `${page.value.total}`
  return page.value.has_more ? `${Math.max(pageEnd.value, page.value.total - 1)}+` : `${page.value.total}`
})

let filterTimer: number | undefined
watch([query, levelFilter], () => {
  if (filterTimer) window.clearTimeout(filterTimer)
  filterTimer = window.setTimeout(() => {
    records.loadPage({ offset: 0, query: query.value, level: levelFilter.value }).catch(() => {})
  }, 180)
})

async function gotoPage(offset: number) {
  await records.loadPage({
    offset: Math.max(0, offset),
    query: query.value,
    level: levelFilter.value,
  })
}

// Background polling: every 15s we refresh anything still pending
// so L2 receipts grow into L3/L4/L5 without forcing the user to click
// the refresh icon on every row.
let timer: number | undefined
onMounted(async () => {
  await records.loadPage({ offset: 0, query: query.value, level: levelFilter.value }).catch(() => {})
  if (source.value === 'local') records.refreshAllPending().catch(() => {})
  timer = window.setInterval(() => {
    if (source.value === 'local' && records.pending.length) records.refreshAllPending().catch(() => {})
  }, 15_000)
})
onUnmounted(() => { if (timer) window.clearInterval(timer) })

const refreshingIds = ref<Set<string>>(new Set())
async function refreshOne(r: LocalRecord) {
  if (refreshingIds.value.has(r.record_id)) return
  refreshingIds.value.add(r.record_id)
  try {
    await records.refresh(r.record_id)
  } catch (e: any) {
    toasts.error('刷新失败', String(e?.message ?? e))
  } finally {
    refreshingIds.value.delete(r.record_id)
  }
}

async function refreshAll() {
  const n = records.pending.length
  if (!n) { toasts.info('没有待刷新的记录'); return }
  try {
    await records.refreshAllPending()
    toasts.success(`已检查 ${n} 条待定记录`)
  } catch (e: any) {
    toasts.error('批量刷新失败', String(e?.message ?? e))
  }
}

async function removeOne(r: LocalRecord) {
  if (!confirm(`确认从本地移除 ${r.file_name} 的存证记录？服务端数据不会被删除。`)) return
  try {
    await records.remove(r.record_id)
    if (selected.value?.record_id === r.record_id) selected.value = null
    toasts.success('已从本地移除')
  } catch (e: any) {
    toasts.error('删除失败', String(e?.message ?? e))
  }
}

async function exportProof(r: LocalRecord) {
  const p = await api.chooseSavePath('导出 ProofBundle', `${r.file_name}.tdproof`)
  if (!p) return
  try {
    await api.exportProofBundle(r.record_id, p)
    toasts.success('已导出 .tdproof', p)
  } catch (e: any) {
    toasts.error('导出失败', String(e?.message ?? e))
  }
}

async function exportGlobalProof(r: LocalRecord) {
  const p = await api.chooseSavePath('导出 GlobalLogProof', `${r.batch_id || r.record_id}.tdgproof`)
  if (!p) return
  try {
    await api.exportGlobalProof(r.record_id, p)
    toasts.success('已导出 .tdgproof', p)
  } catch (e: any) {
    toasts.error('导出失败', String(e?.message ?? e))
  }
}

async function exportAnchor(r: LocalRecord) {
  const treeSize = r.anchor_result?.tree_size || r.global_proof?.sth?.tree_size
  const base = treeSize ? `sth-${treeSize}` : (r.batch_id || r.record_id)
  const p = await api.chooseSavePath('导出 STHAnchorResult', `${base}.tdanchor-result`)
  if (!p) return
  try {
    await api.exportAnchorResult(r.record_id, p)
    toasts.success('已导出 .tdanchor-result', p)
  } catch (e: any) {
    toasts.error('导出失败', String(e?.message ?? e))
  }
}

async function exportSingleProof(r: LocalRecord) {
  const p = await api.chooseSavePath('导出 .sproof 单文件证明', `${r.file_name}.sproof`)
  if (!p) return
  try {
    await api.exportSingleProof(r.record_id, p)
    await records.refresh(r.record_id).catch(() => {})
    toasts.success('已导出 .sproof', '包含当前可用的 ProofBundle / GlobalLogProof / STHAnchorResult。')
  } catch (e: any) {
    toasts.error('导出失败', String(e?.message ?? e))
  }
}

// Keep the drawer in sync with the live store so polling updates
// the detail view without reopening it.
const selected = ref<LocalRecord | null>(null)
const advancedExport = ref<LocalRecord | null>(null)
watch(recs, (list) => {
  if (selected.value) {
    const fresh = list.find((x) => x.record_id === selected.value!.record_id)
    if (fresh) selected.value = fresh
  }
  if (advancedExport.value) {
    const advancedFresh = list.find((x) => x.record_id === advancedExport.value!.record_id)
    if (advancedFresh) advancedExport.value = advancedFresh
  }
}, { deep: true })

function open(r: LocalRecord) {
  selected.value = r
  if (source.value === 'server' && !r.global_proof && !refreshingIds.value.has(r.record_id)) {
    refreshOne(r).catch(() => {})
  }
}
function close() { selected.value = null }
function openAdvancedExport(r: LocalRecord) { advancedExport.value = r }
function closeAdvancedExport() { advancedExport.value = null }

const counts = computed(() => ({
  all: page.value.total,
  L1: recs.value.filter((r) => r.proof_level === 'L1').length,
  L2: recs.value.filter((r) => r.proof_level === 'L2').length,
  L3: recs.value.filter((r) => r.proof_level === 'L3').length,
  L4: recs.value.filter((r) => r.proof_level === 'L4').length,
  L5: recs.value.filter((r) => r.proof_level === 'L5').length,
}))

function healthStatus(r: LocalRecord): 'ok' | 'warn' | 'bad' | 'idle' {
  if (r.last_error) return 'bad'
  if (r.proof_level === 'L5') return 'ok'
  if (r.proof_level === 'L4') return 'ok'
  if (r.proof_level === 'L3') return 'ok'
  if (r.proof_level === 'L2') return 'warn'
  return 'idle'
}

// Parse the OpenTimestamps proof envelope (when sink=ots). We only
// know how to render this one today; other sinks fall back to the
// generic "<N>-byte proof" blurb in the template.
const otsProof = computed<OtsAnchorProof | null>(() => {
  const ar = selected.value?.anchor_result
  if (!ar || ar.sink_name !== 'ots') return null
  return decodeOtsProof(ar.proof)
})
const otsAccepted = computed(() => otsProof.value ? otsAcceptedCount(otsProof.value) : 0)
const otsTotal = computed(() => otsProof.value?.calendars.length ?? 0)
// Short hostname for the calendar URL so the table stays narrow on
// small drawers while the full URL is still copyable via title.
function calendarHost(u: string): string {
  try {
    const url = new URL(u)
    return url.host
  } catch {
    return u
  }
}
function rawTimestampSummary(raw: any): string {
  const arr = coerceBytes(raw)
  if (arr.length === 0) return '—'
  const b64 = bytesToBase64(arr)
  const head = b64.slice(0, 18)
  return `${arr.length} B · ${head}${b64.length > 18 ? '…' : ''}`
}

// proofByteLength gives the *byte* length of an STHAnchorResult.Proof
// regardless of whether Wails handed us a number[] or a base64
// string. Plain `.length` would conflate string chars with bytes.
function proofByteLength(proof: any): number {
  return coerceBytes(proof).length
}

// One-shot client-side OTS upgrade. We only keep the most recent
// summary in component state — this is a live "last attempt" panel,
// not a full history log.
const upgradeBusy = ref(false)
const lastUpgrade = ref<OtsUpgradeSummary | null>(null)
async function upgradeOts(r: LocalRecord) {
  if (upgradeBusy.value) return
  upgradeBusy.value = true
  try {
    const summary = await api.upgradeOtsAnchor(r.record_id)
    lastUpgrade.value = summary
    if (summary.changed) {
      // Re-fetch records so the decoded envelope below reflects the
      // newly-persisted raw_timestamp bytes.
      await records.refresh(r.record_id).catch(() => {})
      const upgraded = summary.calendars.filter((c) => c.changed).length
      toasts.success(
        `已升级 ${upgraded} 个 calendar`,
        `从 ${summary.calendars.length} 个 calendar 中拉到了更新的证明字节。`,
      )
    } else {
      toasts.info('暂无新证明', '所有 calendar 都还没把这次承诺写进 Bitcoin block，稍后再试。')
    }
  } catch (e: any) {
    toasts.error('升级失败', String(e?.message ?? e))
  } finally {
    upgradeBusy.value = false
  }
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1200px] mx-auto">
    <Card dense>
      <template #title>
        <h3 class="text-[14px] font-semibold tracking-[-0.01em] text-ink-800 dark:text-ink-100">存证记录</h3>
      </template>
      <template #actions>
        <Button size="sm" variant="subtle" @click="refreshAll">
          <RefreshCcw :size="13" /> 刷新待定
        </Button>
      </template>

      <div class="px-4 pt-4 pb-3 flex items-center gap-3 flex-wrap">
        <div class="relative flex-1 min-w-[240px]">
          <Search :size="14" class="absolute left-2.5 top-1/2 -translate-y-1/2 text-ink-400 pointer-events-none z-10" />
          <Input v-model="query" :leading-icon="true" placeholder="服务端支持 record_id / batch_id；本地缓存支持文件名 / sha256" />
        </div>
        <div class="inline-flex items-center gap-1 p-1 rounded-lg hairline border bg-white/50 dark:bg-ink-800/50">
          <button
            v-for="opt in [
              { v: '',   label: '全部', n: counts.all },
              { v: 'L2', label: 'L2', n: counts.L2 },
              { v: 'L3', label: 'L3', n: counts.L3 },
              { v: 'L4', label: 'L4', n: counts.L4 },
              { v: 'L5', label: 'L5', n: counts.L5 },
            ]"
            :key="opt.v"
            type="button"
            class="px-2.5 h-7 rounded-md text-[12px] transition-all duration-150 ease-ios"
            :class="levelFilter === opt.v
              ? 'bg-white dark:bg-ink-700 text-ink-800 dark:text-ink-100 shadow-soft-sm'
              : 'text-ink-500 hover:text-ink-700'"
            @click="levelFilter = opt.v as any"
          >
            {{ opt.label }}
            <span class="ml-1 text-ink-400 num">{{ opt.n }}</span>
          </button>
        </div>
      </div>
      <div class="px-4 pb-3 flex flex-wrap items-center gap-2 text-[11.5px] text-ink-500">
        <span class="rounded-full border border-accent/20 bg-accent/10 px-2.5 py-1 text-accent">
          {{ source === 'server' ? '服务端分页 · /v1/records' : '本地缓存' }}
        </span>
        <span v-if="listError" class="text-warn">
          {{ listError }}
        </span>
      </div>

      <div>
        <div v-if="filtered.length" class="px-4 pb-4 space-y-2">
          <article
            v-for="r in filtered"
            :key="r.record_id"
            class="group surface-tile cursor-pointer rounded-[22px] p-3.5 transition hover:border-accent/35 hover:bg-accent/5"
            @click="open(r)"
          >
            <div class="flex flex-col gap-3 min-[980px]:flex-row min-[980px]:items-center">
              <div class="flex items-start gap-3 min-w-0 flex-1">
                <div class="pt-1">
                  <StatusDot :state="healthStatus(r)" />
                </div>
                <div class="min-w-0 flex-1">
                  <div class="flex flex-wrap items-center gap-2">
                    <div class="text-[14px] font-semibold text-ink-50 truncate max-w-full">
                      {{ r.file_name }}
                    </div>
                    <LevelBadge :level="r.proof_level" size="sm" />
                  </div>
                  <div class="mt-1 text-[11px] text-ink-500 truncate">
                    {{ r.file_path }}
                  </div>
                </div>
              </div>

              <div class="flex flex-wrap items-center gap-2 min-[980px]:justify-end" @click.stop>
                <div class="min-w-[118px]">
                  <div class="meta-label mb-1 text-[9px] font-bold">record_id</div>
                  <HashChip :value="r.record_id" :head="6" :tail="6" />
                </div>
                <div class="min-w-[118px]">
                  <div class="meta-label mb-1 text-[9px] font-bold">batch_id</div>
                  <HashChip v-if="r.batch_id" :value="r.batch_id" :head="6" :tail="6" />
                  <span v-else class="text-ink-500">—</span>
                </div>
                <div class="min-w-[74px]">
                  <div class="meta-label mb-1 text-[9px] font-bold">提交</div>
                  <div class="text-[12px] text-ink-200" :title="formatTime(r.submitted_at)">
                    {{ relativeTime(r.submitted_at) }}
                  </div>
                </div>
                <div class="min-w-[62px]">
                  <div class="meta-label mb-1 text-[9px] font-bold">大小</div>
                  <div class="text-[12px] text-ink-200 num">{{ humanSize(r.content_length) }}</div>
                </div>
                <div class="ml-auto flex items-center gap-1 rounded-full border border-white/10 bg-black/20 px-1.5 py-1 min-[980px]:ml-0">
                  <button
                    class="text-ink-400 hover:text-accent transition p-1.5 disabled:opacity-50"
                    :title="refreshingIds.has(r.record_id) ? '刷新中' : '刷新状态'"
                    :disabled="refreshingIds.has(r.record_id)"
                    @click="refreshOne(r)"
                  >
                    <RefreshCcw :size="14" :class="refreshingIds.has(r.record_id) ? 'animate-spin' : ''" />
                  </button>
                  <button
                    class="text-ink-400 hover:text-accent transition p-1.5"
                    title="导出 .sproof 单文件证明"
                    @click="exportSingleProof(r)"
                  >
                    <Download :size="14" />
                  </button>
                  <button
                    class="text-ink-400 hover:text-danger transition p-1.5"
                    title="从本地移除"
                    @click="removeOne(r)"
                  >
                    <Trash2 :size="14" />
                  </button>
                </div>
              </div>
            </div>
          </article>
          <div class="flex flex-wrap items-center justify-between gap-3 rounded-[18px] border border-white/10 bg-black/15 px-3 py-2 text-[12px] text-ink-400">
            <span class="num">Showing {{ pageStart }}-{{ pageEnd }} / {{ pageTotalLabel }}</span>
            <div class="flex items-center gap-2">
              <Button size="sm" variant="subtle" :disabled="page.offset <= 0 || records.loading" @click="gotoPage(page.offset - page.limit)">
                Previous
              </Button>
              <Button size="sm" variant="subtle" :disabled="!page.has_more || records.loading" @click="gotoPage(page.offset + page.limit)">
                Next
              </Button>
            </div>
          </div>
        </div>
        <div v-else class="px-4">
          <EmptyState
            v-if="!recs.length"
            title="暂无存证记录"
            hint="前往「新建存证」提交第一份文件，这里就会列出全部本地记录。"
            :icon="FolderOpen"
          />
          <EmptyState
            v-else
            title="没有匹配的记录"
            hint="试着清空搜索词或切换级别筛选。"
            :icon="Search"
          />
        </div>
      </div>
    </Card>

    <Drawer :open="!!selected" :title="selected?.file_name" width="560px" @close="close">
      <template v-if="selected">
        <div class="flex items-center gap-2 mb-3">
          <LevelBadge :level="selected.proof_level" />
          <StatusDot :state="healthStatus(selected)" />
          <span class="text-[12px] text-ink-500">{{ humanSize(selected.content_length) }} · {{ selected.media_type || 'unknown' }}</span>
        </div>

        <div v-if="selected.last_error" class="rounded-lg bg-danger/10 text-danger p-3 text-[12px] flex items-start gap-2 mb-3">
          <XCircle :size="14" class="shrink-0 mt-0.5" />
          <span>{{ selected.last_error }}</span>
        </div>

        <section class="space-y-3">
          <KV label="record_id"><HashChip :value="selected.record_id" :head="14" :tail="10" /></KV>
          <KV label="idempotency_key"><HashChip :value="selected.idempotency_key" :head="10" :tail="8" /></KV>
          <KV label="sha256"><HashChip :value="selected.content_hash_hex" :head="12" :tail="10" label="sha256" /></KV>
          <KV label="file_path">
            <span class="text-[12px] break-all font-mono text-ink-700 dark:text-ink-200">{{ selected.file_path }}</span>
          </KV>
          <KV label="submitted_at">{{ formatTime(selected.submitted_at) }}</KV>
          <KV label="client / tenant">
            <span class="font-mono text-[12px] text-ink-700 dark:text-ink-200">{{ selected.client_id }} @ {{ selected.tenant_id }}</span>
          </KV>
          <KV label="event_type">{{ selected.event_type || '—' }}</KV>
          <KV label="source">{{ selected.source || '—' }}</KV>
        </section>

        <section v-if="selected.accepted_receipt" class="mt-5">
          <h4 class="flex items-center gap-1.5 text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-2">
            <FileText :size="13" class="text-accent" />
            L2 · 服务端受理
          </h4>
          <div class="rounded-lg hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
            <KV label="server_id" :inline="true">
              <span class="font-mono text-[11.5px]">{{ selected.accepted_receipt.server_id }}</span>
            </KV>
            <KV label="received_at" :inline="true">
              {{ formatTime(nanoToDate(selected.accepted_receipt.server_received_at_unix_nano)) }}
            </KV>
            <KV label="wal" :inline="true">
              <span class="font-mono text-[11.5px]">
                seg {{ selected.accepted_receipt.wal.segment_id }} · off {{ selected.accepted_receipt.wal.offset }} · seq {{ selected.accepted_receipt.wal.sequence }}
              </span>
            </KV>
          </div>
        </section>

        <section v-if="selected.committed_receipt" class="mt-4">
          <h4 class="flex items-center gap-1.5 text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-2">
            <FileText :size="13" class="text-accent" />
            L3 · 批次已承诺
          </h4>
          <div class="rounded-lg hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
            <KV label="batch_id" :inline="true"><HashChip :value="selected.committed_receipt.batch_id" :head="10" :tail="8" /></KV>
            <KV label="leaf_index" :inline="true">
              <span class="num">{{ selected.committed_receipt.leaf_index }}</span>
            </KV>
            <KV label="batch_root" :inline="true"><HashChip :value="bytesToHex(selected.committed_receipt.batch_root)" :head="10" :tail="10" /></KV>
            <KV label="closed_at" :inline="true">
              {{ formatTime(nanoToDate(selected.committed_receipt.batch_closed_at_unix_nano)) }}
            </KV>
          </div>
        </section>

        <section v-if="selected.global_proof" class="mt-4">
          <h4 class="flex items-center gap-1.5 text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-2">
            <FileText :size="13" class="text-success" />
            L4 · 已进入 Global Log
          </h4>
          <div class="rounded-lg hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
            <KV label="sth_tree_size" :inline="true">
              <span class="num">{{ selected.global_proof.sth.tree_size }}</span>
            </KV>
            <KV label="global_root" :inline="true">
              <HashChip :value="bytesToHex(selected.global_proof.sth.root_hash)" :head="12" :tail="10" />
            </KV>
            <KV label="global_leaf" :inline="true">
              <span class="num">#{{ selected.global_proof.leaf_index }}</span>
              <span class="ml-2 text-ink-500">inclusion path {{ selected.global_proof.inclusion_path?.length ?? 0 }}</span>
            </KV>
            <KV label="sth_time" :inline="true">
              {{ formatTime(nanoToDate(selected.global_proof.sth.timestamp_unix_nano)) }}
            </KV>
          </div>
        </section>

        <section v-if="selected.anchor_result" class="mt-4">
          <h4 class="flex items-center gap-1.5 text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-2">
            <Anchor :size="13" class="text-success" />
            L5 · STH 已外部锚定
          </h4>
          <div class="rounded-lg hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
            <KV label="sth_tree_size" :inline="true">
              <span class="num">{{ selected.anchor_result.tree_size }}</span>
            </KV>
            <KV label="sink" :inline="true">
              <span class="font-mono text-[11.5px]">{{ selected.anchor_result.sink_name }}</span>
              <span
                v-if="selected.anchor_result.sink_name === 'ots'"
                class="ml-2 text-[11px] text-ink-500"
              >
                OpenTimestamps · 待比特币主链纳入后可升级
              </span>
            </KV>
            <KV label="anchor_id" :inline="true"><HashChip :value="selected.anchor_result.anchor_id" :head="12" :tail="10" /></KV>
            <KV label="published_at" :inline="true">
              {{ formatTime(nanoToDate(selected.anchor_result.published_at_unix_nano)) }}
            </KV>
          </div>

          <div v-if="otsProof" class="mt-3 rounded-lg hairline border bg-white/50 dark:bg-ink-800/40 p-3">
            <div class="flex items-center justify-between mb-2">
              <div class="text-[12px] font-semibold text-ink-700 dark:text-ink-100">
                OTS calendar 结果
                <span class="ml-1 text-ink-500 font-normal">
                  {{ otsAccepted }} / {{ otsTotal }} accepted
                </span>
              </div>
              <span class="text-[11px] text-ink-500">
                digest {{ bytesToHex(otsProof.digest).slice(0, 10) }}…
              </span>
            </div>

            <div class="overflow-x-auto">
              <table class="w-full text-[11.5px]">
                <thead class="text-ink-500">
                  <tr class="text-left">
                    <th class="font-normal py-1.5 pr-2">calendar</th>
                    <th class="font-normal py-1.5 px-2">状态</th>
                    <th class="font-normal py-1.5 px-2">耗时</th>
                    <th class="font-normal py-1.5 pl-2">raw_timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    v-for="c in otsProof.calendars"
                    :key="c.url"
                    class="border-t border-[var(--hairline)] align-top"
                  >
                    <td class="py-1.5 pr-2">
                      <span :title="c.url" class="font-mono text-ink-700 dark:text-ink-200">
                        {{ calendarHost(c.url) }}
                      </span>
                    </td>
                    <td class="py-1.5 px-2">
                      <span
                        class="inline-flex items-center gap-1 px-1.5 h-5 rounded-md text-[11px]"
                        :class="c.accepted
                          ? 'bg-success/10 text-success'
                          : 'bg-danger/10 text-danger'"
                      >
                        {{ c.accepted ? 'accepted' : 'failed' }}
                        <span v-if="c.status_code" class="text-ink-500 num">
                          · {{ c.status_code }}
                        </span>
                      </span>
                      <div
                        v-if="!c.accepted && c.error"
                        class="mt-1 text-[10.5px] text-danger leading-snug break-all"
                        :title="c.error"
                      >
                        {{ c.error }}
                      </div>
                    </td>
                    <td class="py-1.5 px-2 text-ink-600 dark:text-ink-200 num">
                      <template v-if="c.elapsed_ms != null">{{ c.elapsed_ms }} ms</template>
                      <template v-else>—</template>
                    </td>
                    <td class="py-1.5 pl-2 font-mono text-[10.5px] text-ink-600 dark:text-ink-200 break-all">
                      {{ rawTimestampSummary(c.raw_timestamp) }}
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>

            <div class="mt-3 flex items-center justify-between gap-3">
              <p class="flex-1 text-[11px] text-ink-500 leading-snug">
                每个 calendar 返回的是 "pending" 时间戳；完整的比特币区块 attestation
                通常需要等 1-6 小时后用 <span class="font-mono">trustdb anchor upgrade</span>
                拉一次升级。原始字节会保留在导出的 <span class="font-mono">.tdanchor-result</span> 里，
                可供离线验证工具使用。
              </p>
              <Button
                size="sm"
                variant="subtle"
                :disabled="upgradeBusy"
                :title="'向所有 accepted 的 calendar 再 GET 一次 /timestamp/<digest>，把升级后的字节写回本地记录'"
                @click="upgradeOts(selected!)"
              >
                <RefreshCcw :size="13" :class="upgradeBusy ? 'animate-spin' : ''" />
                {{ upgradeBusy ? '升级中…' : '尝试升级' }}
              </Button>
            </div>

            <div
              v-if="lastUpgrade"
              class="mt-3 rounded-md bg-ink-100/60 dark:bg-ink-800/60 p-2.5 text-[11px]"
            >
              <div class="flex items-center justify-between">
                <span
                  :class="lastUpgrade.changed ? 'text-success' : 'text-ink-500'"
                  class="font-medium"
                >
                  {{ lastUpgrade.changed ? '升级成功' : '暂无新证明' }}
                </span>
                <span class="text-ink-500">
                  {{ formatTime(nanoToDate(lastUpgrade.inspected_at_unix_nano)) }}
                </span>
              </div>
              <ul class="mt-1.5 space-y-1">
                <li
                  v-for="c in lastUpgrade.calendars"
                  :key="c.url"
                  class="flex items-center justify-between gap-2"
                >
                  <span class="font-mono text-ink-600 dark:text-ink-300 truncate" :title="c.url">
                    {{ calendarHost(c.url) }}
                  </span>
                  <span
                    v-if="c.changed"
                    class="text-success shrink-0"
                  >
                    {{ c.old_length ?? 0 }} → {{ c.new_length ?? 0 }} bytes
                  </span>
                  <span
                    v-else-if="c.error"
                    class="text-ink-500 shrink-0 truncate max-w-[60%]"
                    :title="c.error"
                  >
                    {{ c.error }}
                  </span>
                  <span v-else class="text-ink-500 shrink-0">未变化</span>
                </li>
              </ul>
            </div>
          </div>

          <div
            v-else-if="proofByteLength(selected.anchor_result.proof) > 0"
            class="mt-3 rounded-lg hairline border bg-white/40 dark:bg-ink-800/30 p-3 text-[11.5px] text-ink-500"
          >
            <span class="font-mono">{{ selected.anchor_result.sink_name }}</span>
            sink 返回了
            <span class="num">{{ proofByteLength(selected.anchor_result.proof) }}</span>
            字节的不透明证明，导出 <span class="font-mono">.tdanchor-result</span>
            后可配合对应工具解析。
          </div>
        </section>
      </template>

      <template #footer>
        <Button size="sm" variant="subtle" @click="refreshOne(selected!)">
          <RefreshCcw :size="13" /> 刷新状态
        </Button>
        <Button size="sm" @click="exportSingleProof(selected!)">
          <Download :size="13" /> 导出 .sproof
        </Button>
        <Button size="sm" variant="ghost" @click="openAdvancedExport(selected!)">
          分布式导出
        </Button>
      </template>
    </Drawer>

    <Drawer :open="!!advancedExport" title="分布式证明导出" width="430px" @close="closeAdvancedExport">
      <template v-if="advancedExport">
        <div class="rounded-[18px] hairline border bg-white/50 dark:bg-ink-800/40 p-4">
          <div class="text-[13px] font-semibold text-ink-100 truncate">
            {{ advancedExport.file_name }}
          </div>
          <p class="mt-2 text-[12px] leading-relaxed text-ink-500">
            这里保留底层拆分文件导出，适合逐级审计或和旧工具链对接。日常分享和验证建议优先使用
            <span class="font-mono">.sproof</span> 单文件证明。
          </p>
        </div>

        <div class="mt-4 space-y-3">
          <button
            type="button"
            class="w-full rounded-[18px] hairline border bg-white/50 dark:bg-ink-800/40 p-4 text-left transition hover:border-accent/35 hover:bg-accent/5"
            @click="exportProof(advancedExport)"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-display text-[12px] font-bold uppercase tracking-[0.12em] text-ink-50">.tdproof</div>
                <p class="mt-1 text-[11.5px] text-ink-500">L1-L3：claim、receipt、batch Merkle proof。</p>
              </div>
              <Download :size="16" class="text-accent shrink-0" />
            </div>
          </button>

          <button
            type="button"
            class="w-full rounded-[18px] hairline border bg-white/50 dark:bg-ink-800/40 p-4 text-left transition hover:border-accent/35 hover:bg-accent/5"
            @click="exportGlobalProof(advancedExport)"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-display text-[12px] font-bold uppercase tracking-[0.12em] text-ink-50">.tdgproof</div>
                <p class="mt-1 text-[11.5px] text-ink-500">L4：BatchRoot → SignedTreeHead inclusion proof。</p>
              </div>
              <Download :size="16" class="text-accent shrink-0" />
            </div>
          </button>

          <button
            type="button"
            class="w-full rounded-[18px] hairline border bg-white/50 dark:bg-ink-800/40 p-4 text-left transition hover:border-accent/35 hover:bg-accent/5"
            @click="exportAnchor(advancedExport)"
          >
            <div class="flex items-center justify-between gap-3">
              <div>
                <div class="font-display text-[12px] font-bold uppercase tracking-[0.12em] text-ink-50">.tdanchor-result</div>
                <p class="mt-1 text-[11.5px] text-ink-500">L5：STH/global root 的外部锚定结果。</p>
              </div>
              <Download :size="16" class="text-accent shrink-0" />
            </div>
          </button>
        </div>
      </template>
    </Drawer>
  </div>
</template>
