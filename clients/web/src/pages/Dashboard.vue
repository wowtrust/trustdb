<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import gsap from 'gsap'
import { getBatches, getMetrics, getRecords, type BatchRoot, type Metric, type RecordIndex } from '@/lib/api'
import { bytesToHex, nanoToDate, shortHash } from '@/lib/format'
import { ArrowRight, Download, Activity, Layers3, Anchor, Share2, TriangleAlert, Copy, ChevronUp, CircleCheckBig } from 'lucide-vue-next'
import { locale, t } from '@/i18n'

type PipelineNode = {
  name: string
  icon: unknown
  value: string
  unit: string
  label: string
  latency: string
  pending?: string
  attention?: boolean
}

type BatchRow = {
  time: string
  batchID: string
  status: string
  level: string
  leafRange: string
  size: string
  latency: string
  route: string
}

const root = ref<HTMLElement | null>(null)
const busy = ref(false)
const healthy = ref(true)
const loadError = ref('')
const lastUpdated = ref<Date | null>(null)
const metrics = ref<Metric[]>([])
const batches = ref<BatchRoot[]>([])
const records = ref<RecordIndex[]>([])
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'
let animationContext: ReturnType<typeof gsap.context> | undefined
let timer: number | undefined

const demoPipeline: PipelineNode[] = [
  { name: 'INGEST', icon: Download, value: '12,486', unit: '/s', label: '吞吐量', latency: '8 ms' },
  { name: 'WAL', icon: Activity, value: '12,482', unit: '/s', label: '吞吐量', latency: '11 ms' },
  { name: 'BATCH', icon: Layers3, value: '1,248', unit: '/min', label: '吞吐量', latency: '142 ms', pending: '3', attention: true },
  { name: 'GLOBAL LOG', icon: Share2, value: '1,248', unit: '/min', label: '吞吐量', latency: '186 ms' },
  { name: 'ANCHOR', icon: Anchor, value: '1,186', unit: '/min', label: '吞吐量', latency: '512 ms' },
]

const demoRows: BatchRow[] = [
  { time: '10:48:15', batchID: 'batch-1777_000001', status: '待锚定', level: 'L4', leafRange: '#3,718,401', size: '1', latency: '142 ms', route: '/batches/batch-1777_000001' },
  { time: '10:48:00', batchID: 'batch-1776_00ff10', status: '已锚定', level: 'L5', leafRange: '#3,716,161 - #3,718,400', size: '2,240', latency: '138 ms', route: '/batches/batch-1776_00ff10' },
  { time: '10:47:00', batchID: 'batch-1775_00fe20', status: '已锚定', level: 'L5', leafRange: '#3,713,921 - #3,716,160', size: '2,240', latency: '131 ms', route: '/batches/batch-1775_00fe20' },
  { time: '10:46:00', batchID: 'batch-1774_00fd30', status: '已锚定', level: 'L5', leafRange: '#3,711,681 - #3,713,920', size: '2,240', latency: '127 ms', route: '/batches/batch-1774_00fd30' },
  { time: '10:45:00', batchID: 'batch-1773_00fc40', status: '已锚定', level: 'L5', leafRange: '#3,709,441 - #3,711,680', size: '2,240', latency: '118 ms', route: '/batches/batch-1773_00fc40' },
]

function metricSamples(name: string, labels?: Record<string, string>) {
  return metrics.value.filter((metric) => metric.name === name && (!labels || Object.entries(labels).every(([key, value]) => metric.labels?.[key] === value)))
}

function metricValue(name: string, labels?: Record<string, string>): number | undefined {
  const samples = metricSamples(name, labels)
  if (!samples.length) return undefined
  return samples.reduce((total, sample) => total + sample.value, 0)
}

function firstMetric(names: string[], labels?: Record<string, string>) {
  for (const name of names) {
    const value = metricValue(name, labels)
    if (value !== undefined) return value
  }
  return undefined
}

function histogramP95(baseName: string): number | undefined {
  const buckets = metricSamples(`${baseName}_bucket`)
    .map((metric) => ({ boundary: Number(metric.labels?.le), count: metric.value }))
    .filter((bucket) => Number.isFinite(bucket.boundary))
    .sort((a, b) => a.boundary - b.boundary)
  const total = metricValue(`${baseName}_count`)
  if (!buckets.length || !total) return undefined
  const target = total * .95
  const bucket = buckets.find((entry) => entry.count >= target) ?? buckets[buckets.length - 1]
  return bucket.boundary * 1000
}

function formatCount(value: number | undefined) {
  return value === undefined ? '—' : Math.round(value).toLocaleString('zh-CN')
}

function formatLatency(value: number | undefined) {
  if (value === undefined || !Number.isFinite(value)) return '—'
  if (value < 1) return `${Math.round(value * 1000)} µs`
  return `${value < 10 ? value.toFixed(1) : Math.round(value)} ms`
}

const ingestAccepted = computed(() => firstMetric(['trustdb_ingest_requests_total'], { result: 'accepted' }) ?? firstMetric(['trustdb_ingest_accepted_total']))
const walSequence = computed(() => firstMetric(['trustdb_wal_checkpoint_last_sequence']))
const batchCount = computed(() => firstMetric(['trustdb_batch_commit_latency_seconds_count', 'trustdb_batch_size_records_count']) ?? batches.value.length)
const globalCount = computed(() => firstMetric(['trustdb_global_log_published_roots_total']))
const anchorPublished = computed(() => firstMetric(['trustdb_anchor_published_total']))
const batchPending = computed(() => firstMetric(['trustdb_queue_depth'], { queue: 'batch' }) ?? firstMetric(['trustdb_batch_pending']) ?? 0)
const anchorPending = computed(() => firstMetric(['trustdb_anchor_pending_total', 'trustdb_anchor_pending']) ?? 0)

const attention = computed(() => {
  if (demoMode) return { stage: 'BATCH', title: '待锚定队列', type: '批次等待外部锚定', count: 3, severity: '中' }
  if (loadError.value) return { stage: 'INGEST', title: '数据源不可用', type: loadError.value, count: 0, severity: '高' }
  if (anchorPending.value > 0) return { stage: 'ANCHOR', title: '待锚定队列', type: '批次等待外部锚定', count: anchorPending.value, severity: anchorPending.value > 10 ? '中' : '低' }
  if (batchPending.value > 0) return { stage: 'BATCH', title: '待提交队列', type: '记录等待批次提交', count: batchPending.value, severity: batchPending.value > 100 ? '中' : '低' }
  return null
})

const pipeline = computed<PipelineNode[]>(() => {
  if (demoMode) return demoPipeline
  const nodes: PipelineNode[] = [
    { name: 'INGEST', icon: Download, value: formatCount(ingestAccepted.value), unit: '', label: '累计接收', latency: formatLatency(undefined) },
    { name: 'WAL', icon: Activity, value: formatCount(walSequence.value), unit: '', label: '检查点序号', latency: formatLatency(histogramP95('trustdb_wal_append_latency_seconds')) },
    { name: 'BATCH', icon: Layers3, value: formatCount(batchCount.value), unit: '', label: '累计批次', latency: formatLatency(histogramP95('trustdb_batch_commit_latency_seconds')), pending: batchPending.value ? formatCount(batchPending.value) : undefined },
    { name: 'GLOBAL LOG', icon: Share2, value: formatCount(globalCount.value), unit: '', label: '已发布根', latency: formatLatency(histogramP95('trustdb_global_log_batch_latency_seconds')) },
    { name: 'ANCHOR', icon: Anchor, value: formatCount(anchorPublished.value), unit: '', label: '已发布锚点', latency: formatLatency(histogramP95('trustdb_anchor_latency_seconds')), pending: anchorPending.value ? formatCount(anchorPending.value) : undefined },
  ]
  return nodes.map((node) => ({ ...node, attention: attention.value?.stage === node.name }))
})

function timeOnly(root: BatchRoot) {
  const value = nanoToDate(root.closed_at_unix_nano)
  return value ? value.toLocaleTimeString('zh-CN', { hour12: false }) : '—'
}

const rows = computed<BatchRow[]>(() => {
  if (demoMode) return demoRows
  const latency = formatLatency(histogramP95('trustdb_batch_commit_latency_seconds'))
  return batches.value.slice(0, 5).map((batch) => ({
    time: timeOnly(batch),
    batchID: batch.batch_id,
    status: '已提交',
    level: 'L3',
    leafRange: batch.tree_size > 1 ? `#0 - #${batch.tree_size - 1}` : '#0',
    size: batch.tree_size.toLocaleString('zh-CN'),
    latency,
    route: `/batches/${encodeURIComponent(batch.batch_id)}`,
  }))
})

const proofBars = computed(() => {
  if (demoMode) return [['L5', 92.5, '1,776'], ['L4', 6.1, '118'], ['L3', 1.1, '22'], ['L2', .2, '3'], ['L1', 0, '0']] as [string, number, string][]
  const total = records.value.length
  return ['L5', 'L4', 'L3', 'L2', 'L1'].map((level) => {
    const count = records.value.filter((record) => record.proof_level === level).length
    return [level, total ? Number(((count / total) * 100).toFixed(1)) : 0, count.toLocaleString('zh-CN')] as [string, number, string]
  })
})

const selectedBatch = computed(() => batches.value[0] ?? null)
const selectedRoot = computed(() => selectedBatch.value ? bytesToHex(selectedBatch.value.batch_root) : '')
const selectedRootShort = computed(() => shortHash(selectedRoot.value, 12, 10) || '—')

async function load() {
  if (busy.value) return
  if (demoMode) {
    healthy.value = true
    loadError.value = ''
    lastUpdated.value = new Date()
    return
  }
  busy.value = true
  const [metricResult, batchResult, recordResult] = await Promise.allSettled([
    getMetrics(),
    getBatches({ limit: 5 }),
    getRecords({ limit: 100 }),
  ])
  const errors: string[] = []
  if (metricResult.status === 'fulfilled') metrics.value = metricResult.value
  else errors.push(metricResult.reason instanceof Error ? metricResult.reason.message : String(metricResult.reason))
  if (batchResult.status === 'fulfilled') batches.value = batchResult.value.roots ?? []
  else errors.push(batchResult.reason instanceof Error ? batchResult.reason.message : String(batchResult.reason))
  if (recordResult.status === 'fulfilled') records.value = recordResult.value.records ?? []
  else errors.push(recordResult.reason instanceof Error ? recordResult.reason.message : String(recordResult.reason))
  loadError.value = errors.join('；')
  healthy.value = errors.length === 0
  lastUpdated.value = new Date()
  busy.value = false
}

async function copyRoot() {
  if (!selectedRoot.value) return
  try { await navigator.clipboard.writeText(selectedRoot.value) } catch { /* browser policy may deny clipboard access */ }
}

onMounted(() => {
  void load()
  timer = window.setInterval(load, 15_000)
  animationContext = gsap.context(() => {
    const reducedMotion = typeof window.matchMedia === 'function' && window.matchMedia('(prefers-reduced-motion: reduce)').matches
    if (!reducedMotion) {
      gsap.timeline({ defaults: { ease: 'power3.out' } })
        .from('.wa-mast > *', { y: 24, autoAlpha: 0, duration: .62, stagger: .08 })
        .from('.wa-pipeline-node', { y: 26, autoAlpha: 0, scale: .86, duration: .58, stagger: .1 }, '-=.28')
        .from('.wa-anomaly, .wa-lower > *', { y: 22, autoAlpha: 0, duration: .6, stagger: .1 }, '-=.24')
      const track = root.value?.querySelector<HTMLElement>('.wa-live-track')
      const signal = root.value?.querySelector<HTMLElement>('.wa-live-signal')
      if (track && signal) {
        gsap.to(signal, { x: () => track.clientWidth - signal.clientWidth, duration: 2.8, repeat: -1, repeatRefresh: true, ease: 'none' })
      }
      gsap.to('.wa-pipeline-node.anomaly .wa-node-ring', { scale: 1.28, autoAlpha: 0, duration: 1.5, repeat: -1, ease: 'power1.out' })
    }
  }, root.value ?? undefined)
})

onUnmounted(() => {
  if (timer) window.clearInterval(timer)
  animationContext?.revert()
})
</script>

<template>
  <div ref="root" class="wa-dashboard">
    <section class="wa-overview">
      <div class="wa-mast">
        <div><p>TrustDB proof operations</p><h1>ALL SYSTEMS PROVABLE</h1><span :class="{ offline: !healthy }"><i />{{ healthy ? '系统运行正常' : '部分数据不可用' }} <em>{{ t('最后更新：{time}', { time: lastUpdated?.toLocaleTimeString(locale, { hour12: false }) || '—' }) }}</em></span></div>
        <div class="wa-mast__actions"><button type="button" :disabled="busy" @click="load">{{ busy ? '刷新中' : '刷新数据' }} <ArrowRight :size="17" /></button><RouterLink to="/global-tree">查看全局树</RouterLink></div>
      </div>

      <div class="wa-pipeline-title"><h2>实时证明流水线</h2><span v-if="attention"><TriangleAlert :size="14" />{{ attention.title }} · {{ attention.count }}</span><span v-else class="ok"><CircleCheckBig :size="14" />全部阶段正常</span></div>
      <div class="wa-pipeline">
        <div class="wa-live-track"><i class="wa-live-signal" /></div>
        <article v-for="node in pipeline" :key="node.name" class="wa-pipeline-node" :class="{ anomaly: node.attention }">
          <div v-if="node.attention" class="wa-node-alert"><TriangleAlert :size="12" />关注</div>
          <div class="wa-node-orb"><i class="wa-node-ring" /><component :is="node.icon" :size="32" :stroke-width="1.6" /></div>
          <h3>{{ node.name }}</h3>
          <p>{{ node.label }}</p><strong>{{ node.value }} <small>{{ node.unit }}</small></strong>
          <p>P95 延迟</p><strong>{{ node.latency }}</strong>
          <p v-if="node.pending">待处理</p><strong v-if="node.pending">{{ node.pending }}</strong>
        </article>
      </div>
    </section>

    <aside class="wa-anomaly">
      <header><h2>运行关注</h2><ChevronUp :size="16" /></header>
      <div v-if="attention" class="wa-anomaly__body">
        <span>当前关注项</span><h3>{{ attention.title }} <b>{{ attention.severity }}</b></h3>
        <dl>
          <div><dt>检测时间</dt><dd>{{ lastUpdated?.toLocaleTimeString('zh-CN', { hour12: false }) || '—' }}</dd></div><div><dt>类型</dt><dd>{{ attention.type }}</dd></div>
          <div><dt>待处理数量</dt><dd>{{ attention.count }}</dd></div><div><dt>严重程度</dt><dd>{{ attention.severity }}</dd></div>
        </dl>
        <h4>最新批次</h4>
        <dl class="mono">
          <div><dt>BATCH_ID</dt><dd>{{ selectedBatch?.batch_id || '—' }}</dd></div>
          <div><dt>BATCH_ROOT (SHA256)</dt><dd>{{ selectedRootShort }} <button v-if="selectedRoot" type="button" @click="copyRoot" aria-label="复制批次根"><Copy :size="12" /></button></dd></div>
          <div><dt>TREE_SIZE</dt><dd>{{ selectedBatch?.tree_size ?? '—' }}</dd></div>
          <div><dt>CLOSED</dt><dd>{{ selectedBatch ? nanoToDate(selectedBatch.closed_at_unix_nano)?.toLocaleString('zh-CN', { hour12: false }) : '—' }}</dd></div>
          <div><dt>状态</dt><dd class="warn">{{ attention.title }} · {{ attention.count }}</dd></div>
        </dl>
        <RouterLink :to="selectedBatch ? `/batches/${encodeURIComponent(selectedBatch.batch_id)}` : '/metrics'">查看运行详情 <ArrowRight :size="15" /></RouterLink>
      </div>
      <div v-else class="wa-anomaly__clear">
        <CircleCheckBig :size="30" />
        <h3>没有需要处理的异常</h3>
        <p>证明流水线与锚定队列均处于正常范围。</p>
        <RouterLink to="/metrics">查看完整指标 <ArrowRight :size="15" /></RouterLink>
      </div>
    </aside>

    <section class="wa-lower">
      <div class="wa-latest">
        <header><h2>最新批次</h2><RouterLink to="/batches">查看全部 <ArrowRight :size="14" /></RouterLink></header>
        <div class="wa-table"><div class="wa-row head"><span>时间</span><span>类型</span><span>批次 ID</span><span>状态</span><span>证明等级</span><span>叶子范围</span><span>大小</span><span>P95 延迟</span><span>操作</span></div>
          <div v-for="row in rows" :key="row.batchID" class="wa-row"><span><i />{{ row.time }}</span><span>BATCH</span><span>{{ row.batchID }}</span><span><b :class="{ warn: row.status !== '已提交' && row.status !== '已锚定' }">{{ row.status }}</b></span><span class="green">{{ row.level }}</span><span>{{ row.leafRange }}</span><span>{{ row.size }}</span><span>{{ row.latency }}</span><RouterLink :to="row.route">查看</RouterLink></div>
          <div v-if="!rows.length" class="wa-table-empty">还没有已提交批次，数据生成后会自动出现在这里。</div>
        </div>
      </div>
      <div class="wa-proof-bars">
        <h2>{{ t('证明等级 · 最近 {count} 条', { count: records.length || (demoMode ? 1919 : 0) }) }}</h2>
        <div class="wa-bar-head"><span /><span>分布</span><span>记录数量</span><span>占比</span></div>
        <div v-for="bar in proofBars" :key="bar[0]" class="wa-bar-row"><b>{{ bar[0] }}</b><i><em :style="{ width: `${bar[1]}%` }" /></i><span>{{ bar[2] }}</span><span>{{ bar[1] }}%</span></div>
      </div>
    </section>
  </div>
</template>
