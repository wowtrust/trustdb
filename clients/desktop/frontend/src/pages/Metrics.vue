<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { api, Metric } from '@/lib/api'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Sparkline from '@/components/Sparkline.vue'
import EmptyState from '@/components/EmptyState.vue'
import StatusDot from '@/components/StatusDot.vue'
import { Activity, Pause, Play, RefreshCcw, Gauge } from 'lucide-vue-next'

const metrics = ref<Metric[]>([])
const loading = ref(false)
const lastError = ref<string | null>(null)
const lastPollAt = ref<Date | null>(null)

// Rolling history buffer of fixed length per metric name. We use a
// plain object keyed by metric name because arrays of objects get
// really heavy very quickly when the user leaves the page open.
const HISTORY_LEN = 60
const history = ref<Record<string, number[]>>({})

type MetricSource = { name: string; labels?: Record<string, string> }
type Highlight = { key: string; label: string; desc: string; fmt: 'int' | 'float'; sources: MetricSource[] }

const HIGHLIGHTS: Highlight[] = [
  { key: 'ingest-accepted', label: 'claims accepted', desc: '累计已受理 claim', fmt: 'int', sources: [{ name: 'trustdb_ingest_requests_total', labels: { result: 'accepted' } }, { name: 'trustdb_ingest_accepted_total' }] },
  { key: 'ingest-rejected', label: 'claims rejected', desc: '累计拒绝 claim', fmt: 'int', sources: [{ name: 'trustdb_ingest_rejected_total' }] },
  { key: 'batches-committed', label: 'batches committed', desc: '累计已承诺批次', fmt: 'int', sources: [{ name: 'trustdb_batch_commit_latency_seconds_count' }, { name: 'trustdb_batch_size_records_count' }, { name: 'trustdb_batch_committed_total' }] },
  { key: 'batch-pending', label: 'batch pending', desc: '待承诺批次数量', fmt: 'int', sources: [{ name: 'trustdb_queue_depth', labels: { queue: 'batch' } }, { name: 'trustdb_batch_pending' }] },
  { key: 'anchors-published', label: 'anchors published', desc: '累计已发布锚点', fmt: 'int', sources: [{ name: 'trustdb_anchor_published_total' }] },
  { key: 'anchor-pending', label: 'anchor pending', desc: '待锚定批次数量', fmt: 'int', sources: [{ name: 'trustdb_anchor_pending_total' }, { name: 'trustdb_anchor_pending' }] },
]

function sourceValue(source: MetricSource): number | undefined {
  const samples = metrics.value.filter((metric) => metric.name === source.name && (!source.labels || Object.entries(source.labels).every(([key, value]) => metric.labels?.[key] === value)))
  if (!samples.length) return undefined
  return samples.reduce((total, metric) => total + metric.value, 0)
}

function highlightValue(highlight: Highlight): number {
  for (const source of highlight.sources) {
    const value = sourceValue(source)
    if (value !== undefined) return value
  }
  return 0
}

function fmt(v: number, kind: 'int' | 'float'): string {
  if (!Number.isFinite(v)) return '—'
  if (kind === 'int') return Math.round(v).toLocaleString()
  return v.toFixed(2)
}

const autoRefresh = ref(true)
const intervalMs = 3000
let timer: number | undefined

async function fetchMetrics() {
  if (loading.value) return
  loading.value = true
  try {
    metrics.value = (await api.serverMetrics()) ?? []
    lastError.value = null
    lastPollAt.value = new Date()
    // Append to each highlight's history buffer.
    for (const h of HIGHLIGHTS) {
      const buf = history.value[h.key] ?? []
      buf.push(highlightValue(h))
      while (buf.length > HISTORY_LEN) buf.shift()
      history.value[h.key] = buf
    }
  } catch (e: any) {
    lastError.value = String(e?.message ?? e)
  } finally {
    loading.value = false
  }
}

onMounted(() => {
  fetchMetrics()
  timer = window.setInterval(() => { if (autoRefresh.value) fetchMetrics() }, intervalMs)
})
onUnmounted(() => { if (timer) window.clearInterval(timer) })

function toggleAuto() { autoRefresh.value = !autoRefresh.value }

// Secondary: show every other metric as a plain table, grouped by
// name. Useful for power-users who want to see everything the
// server emits without leaving the app.
const grouped = computed(() => {
  const map = new Map<string, Metric[]>()
  for (const m of metrics.value) {
    if (!map.has(m.name)) map.set(m.name, [])
    map.get(m.name)!.push(m)
  }
  // Drop the ones we already highlight on cards to avoid duplication.
  for (const h of HIGHLIGHTS) h.sources.forEach((source) => map.delete(source.name))
  return Array.from(map.entries()).sort((a, b) => a[0].localeCompare(b[0]))
})

function labelString(m: Metric): string {
  if (!m.labels) return ''
  const entries = Object.entries(m.labels)
  if (!entries.length) return ''
  return entries.map(([k, v]) => `${k}="${v}"`).join(', ')
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1200px] mx-auto">
    <!-- Header bar -->
    <Card dense>
      <template #title>
        <div class="flex items-center gap-2">
          <Gauge :size="15" class="text-accent" />
          <h3 class="text-[14px] font-semibold tracking-[-0.01em] text-ink-800 dark:text-ink-100">服务指标</h3>
        </div>
      </template>
      <template #actions>
        <div class="flex items-center gap-2">
          <span class="flex items-center gap-1.5 text-[11.5px] text-ink-500">
            <StatusDot :state="lastError ? 'bad' : loading ? 'warn' : 'ok'" />
            <span v-if="lastError">{{ lastError }}</span>
            <span v-else-if="lastPollAt">{{ lastPollAt.toLocaleTimeString() }}</span>
            <span v-else>—</span>
          </span>
          <Button size="sm" variant="subtle" @click="toggleAuto">
            <component :is="autoRefresh ? Pause : Play" :size="12" />
            {{ autoRefresh ? '暂停' : '继续' }}
          </Button>
          <Button size="sm" variant="subtle" :loading="loading" @click="fetchMetrics">
            <RefreshCcw :size="12" /> 立即刷新
          </Button>
        </div>
      </template>

      <!-- Cards row -->
      <div class="px-4 pt-4 pb-5 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
        <div
          v-for="h in HIGHLIGHTS"
          :key="h.key"
          class="rounded-xl hairline border bg-white/60 dark:bg-ink-800/50 p-3 flex flex-col gap-2"
        >
          <div class="flex items-center justify-between">
            <div>
              <div class="text-[10.5px] uppercase tracking-[0.08em] text-ink-500">{{ h.label }}</div>
              <div class="text-[11px] text-ink-400">{{ h.desc }}</div>
            </div>
            <div class="text-accent"><Activity :size="13" /></div>
          </div>
          <div class="flex items-end justify-between gap-2">
            <div class="text-[22px] num font-semibold leading-none text-ink-800 dark:text-ink-100">
              {{ fmt(highlightValue(h), h.fmt) }}
            </div>
            <div class="text-accent flex-1 max-w-[160px]">
              <Sparkline :values="history[h.key] ?? []" :height="28" />
            </div>
          </div>
        </div>
      </div>
    </Card>

    <!-- Raw table -->
    <Card title="全部指标" :subtitle="`共 ${grouped.length} 个（已去除上方高亮指标）`" dense>
      <div v-if="!metrics.length" class="px-4">
        <EmptyState
          title="暂无指标数据"
          :hint="lastError || '服务器未返回 /metrics，稍后重试。'"
          :icon="Activity"
        />
      </div>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-[12px]">
          <thead class="text-ink-500 text-left">
            <tr>
              <th class="pl-5 pr-3 py-2 font-normal">name</th>
              <th class="px-3 py-2 font-normal">labels</th>
              <th class="px-3 py-2 font-normal">type</th>
              <th class="pr-5 pl-3 py-2 font-normal text-right">value</th>
            </tr>
          </thead>
          <tbody>
            <template v-for="[name, items] in grouped" :key="name">
              <tr
                v-for="(m, i) in items"
                :key="name + i"
                class="border-t border-[var(--hairline)]"
              >
                <td class="pl-5 pr-3 py-2 font-mono text-[11.5px] text-ink-700 dark:text-ink-200">
                  <span v-if="i === 0">{{ name }}</span>
                </td>
                <td class="px-3 py-2 font-mono text-[11px] text-ink-500">{{ labelString(m) || '—' }}</td>
                <td class="px-3 py-2 text-ink-500">{{ m.type || '—' }}</td>
                <td class="pr-5 pl-3 py-2 text-right num text-ink-700 dark:text-ink-100">{{ fmt(m.value, 'float') }}</td>
              </tr>
            </template>
          </tbody>
        </table>
      </div>
    </Card>
  </div>
</template>
