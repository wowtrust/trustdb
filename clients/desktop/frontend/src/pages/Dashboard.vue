<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { storeToRefs } from 'pinia'
import gsap from 'gsap'
import { useRecords } from '@/stores/records'
import { useIdentity } from '@/stores/identity'
import { api, LocalRecord, Metric } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import { PenLine, ReceiptText, GitFork, Globe2, Anchor, Check, FileText, Copy, ArrowUpRight, Plus, ShieldCheck, Activity } from 'lucide-vue-next'

const root = ref<HTMLElement | null>(null)
let animationContext: ReturnType<typeof gsap.context> | undefined
const records = useRecords()
const identity = useIdentity()
const { records: storedRecords } = storeToRefs(records)
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'

const demoRecords = [
  { record_id: 'tr13g7...bond2q', file_name: '测试存证.txt', content_length: 1240, submitted_at: '2026-04-29T10:48:15Z', proof_level: 'L4' },
  { record_id: 'tr72ab...19fe80', file_name: '合同条款.pdf', content_length: 320110, submitted_at: '2026-04-29T09:21:44Z', proof_level: 'L5' },
  { record_id: 'tr9c24...70cffa', file_name: '会议纪要.md', content_length: 18770, submitted_at: '2026-04-29T08:05:12Z', proof_level: 'L5' },
  { record_id: 'tr833e...05fa1c', file_name: '设计规范_v2.pdf', content_length: 4520000, submitted_at: '2026-04-28T17:36:09Z', proof_level: 'L2' },
  { record_id: 'tr121a...a07dc3', file_name: '报价单.xlsx', content_length: 62330, submitted_at: '2026-04-28T15:10:33Z', proof_level: 'L4' },
] as Partial<LocalRecord>[]

const recent = computed<Partial<LocalRecord>[]>(() => (demoMode ? demoRecords : storedRecords.value).slice(0, 5))
const selectedRecordID = ref(demoMode ? demoRecords[0].record_id || '' : '')
const selected = computed(() => recent.value.find((record) => record.record_id === selectedRecordID.value) ?? recent.value[0] ?? null)
const deviceName = computed(() => (identity.identity?.client_id || (demoMode ? 'DESKTOP-1' : '未命名客户端')).toUpperCase())
const health = ref<{ ok?: boolean; rtt_millis?: number; error?: string } | null>(demoMode ? { ok: true, rtt_millis: 12 } : null)
const metrics = ref<Metric[]>([])

const levels = [
  { key: 'L1', label: '签名', complete: '本地签名已完成', pending: '等待本地签名', icon: PenLine },
  { key: 'L2', label: '收据', complete: '持久化收据已生成', pending: '等待服务端收据', icon: ReceiptText },
  { key: 'L3', label: 'MERKLE', complete: '已加入默克尔树', pending: '等待批次提交', icon: GitFork },
  { key: 'L4', label: 'GLOBAL', complete: '已写入全球透明日志', pending: '等待透明日志发布', icon: Globe2 },
  { key: 'L5', label: '外部锚定', complete: '外部锚定已完成', pending: '等待外部锚定', icon: Anchor },
]
const levelIndex = computed(() => levels.findIndex((item) => item.key === selected.value?.proof_level))

function levelState(index: number) {
  if (levelIndex.value < 0) return 'pending'
  if (index < levelIndex.value || (index === levelIndex.value && selected.value?.proof_level === 'L5')) return 'done'
  if (index === levelIndex.value) return 'active'
  return 'pending'
}

function levelNote(index: number) {
  return levelState(index) === 'pending' ? levels[index].pending : levels[index].complete
}

function formatBytes(value = 0) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`
  return `${(value / 1024 / 1024).toFixed(2)} MB`
}

function metricValue(name: string, labels?: Record<string, string>): number | undefined {
  const matches = metrics.value.filter((metric) => metric.name === name && (!labels || Object.entries(labels).every(([key, value]) => metric.labels?.[key] === value)))
  if (!matches.length) return undefined
  return matches.reduce((total, metric) => total + metric.value, 0)
}

function firstMetric(names: string[], labels?: Record<string, string>) {
  for (const name of names) {
    const value = metricValue(name, labels)
    if (value !== undefined) return value
  }
  return undefined
}

function formatCount(value: number | undefined) {
  return value === undefined ? '—' : Math.round(value).toLocaleString('zh-CN')
}

const acceptedTotal = computed(() => firstMetric(['trustdb_ingest_requests_total'], { result: 'accepted' }) ?? firstMetric(['trustdb_ingest_accepted_total']))
const queueDepth = computed(() => firstMetric(['trustdb_queue_depth', 'trustdb_batch_pending']))
const anchorPending = computed(() => firstMetric(['trustdb_anchor_pending_total', 'trustdb_anchor_pending']))
const healthStats = computed(() => [
  { label: '服务连接', value: health.value?.ok ? '在线' : health.value ? '不可达' : '检测中' },
  { label: 'API 延迟', value: health.value?.ok && health.value.rtt_millis !== undefined ? `${health.value.rtt_millis} ms` : '—' },
  { label: '已接收记录', value: formatCount(acceptedTotal.value ?? (recent.value.length || undefined)) },
  { label: '待处理队列', value: formatCount(queueDepth.value) },
  { label: '待锚定批次', value: formatCount(anchorPending.value) },
])

const eventCopy = computed(() => {
  const level = selected.value?.proof_level
  if (level === 'L5') return ['外部锚定已完成', '证据链已达到最高等级']
  if (level === 'L4') return ['已写入全球透明日志', '等待外部锚定']
  if (level === 'L3') return ['批次默克尔证明已生成', '等待写入全球透明日志']
  if (level === 'L2') return ['持久化收据已生成', '等待进入默克尔批次']
  return ['本地签名已完成', '等待服务端接收']
})

function choose(record: Partial<LocalRecord>) { selectedRecordID.value = record.record_id || '' }
async function copyRecordId() {
  if (!selected.value?.record_id) return
  try { await navigator.clipboard.writeText(selected.value.record_id) } catch { /* native shell may deny clipboard access */ }
}

async function loadServer() {
  if (demoMode) {
    metrics.value = [
      { name: 'trustdb_ingest_requests_total', labels: { result: 'accepted' }, value: 12_486 },
      { name: 'trustdb_queue_depth', labels: { queue: 'ingest' }, value: 3 },
      { name: 'trustdb_wal_segments_total', value: 5 },
      { name: 'trustdb_anchor_pending_total', value: 3 },
    ] as Metric[]
    return
  }
  const [healthResult, metricResult] = await Promise.allSettled([api.serverHealth(), api.serverMetrics()])
  health.value = healthResult.status === 'fulfilled'
    ? healthResult.value
    : { ok: false, error: healthResult.reason instanceof Error ? healthResult.reason.message : String(healthResult.reason) }
  metrics.value = metricResult.status === 'fulfilled' ? (metricResult.value ?? []) : []
}

onMounted(() => {
  animationContext = gsap.context(() => {
    if (document.visibilityState === 'visible') {
      gsap.timeline({ defaults: { ease: 'power3.out' } })
        .from('.td-dashboard__mast > *', { y: 24, autoAlpha: 0, duration: .6, stagger: .08 })
        .from('.td-proof-node', { scale: .72, autoAlpha: 0, duration: .55, stagger: .09 }, '-=.25')
        .from('.td-data-section, .td-inspector', { y: 26, autoAlpha: 0, duration: .6, stagger: .1 }, '-=.3')
    }
    const track = root.value?.querySelector<HTMLElement>('.td-proof-track')
    const signal = root.value?.querySelector<HTMLElement>('.td-proof-signal')
    if (track && signal) {
      gsap.to(signal, { x: () => track.clientWidth - signal.clientWidth, duration: 3.2, repeat: -1, repeatRefresh: true, ease: 'none' })
    }
    gsap.to('.td-proof-node.is-current .td-proof-ring', { scale: 1.28, autoAlpha: 0, duration: 1.6, repeat: -1, ease: 'power1.out' })
  }, root.value ?? undefined)
  void Promise.allSettled([records.refreshAllPending(), loadServer()]).then(() => {
    if (!selectedRecordID.value && recent.value[0]?.record_id) selectedRecordID.value = recent.value[0].record_id
  })
})

onUnmounted(() => animationContext?.revert())
</script>

<template>
  <div ref="root" class="td-dashboard">
    <section class="td-dashboard__main">
      <div class="td-dashboard__mast">
        <div>
          <h2>{{ deviceName }}</h2>
        </div>
        <div class="td-mast-actions">
          <RouterLink class="td-primary" to="/attest">新建存证 <Plus :size="17" /></RouterLink>
          <RouterLink class="td-secondary" to="/verify">验证证据 <ArrowUpRight :size="17" /></RouterLink>
        </div>
      </div>

      <section class="td-proof-section">
        <div class="td-section-title"><i />证明链 <span>Proof journey</span></div>
        <div class="td-proof-rail">
          <div class="td-proof-track"><i class="td-proof-signal" /></div>
          <article v-for="(level, index) in levels" :key="level.key" class="td-proof-node" :class="{ 'is-complete': levelState(index) === 'done', 'is-current': levelState(index) === 'active', 'is-pending': levelState(index) === 'pending' }">
            <div class="td-proof-node__label">{{ level.key }} <span>{{ level.label }}</span></div>
            <div class="td-proof-node__orb">
              <i class="td-proof-ring" />
              <component :is="level.icon" :size="31" :stroke-width="1.55" />
            </div>
            <div class="td-proof-node__check"><Check v-if="levelState(index) !== 'pending'" :size="12" :stroke-width="3" /></div>
            <strong>{{ levelState(index) === 'done' ? '已完成' : levelState(index) === 'active' ? '进行中' : '待执行' }}</strong>
            <p>{{ levelNote(index) }}</p>
          </article>
        </div>
      </section>

      <section class="td-data-section">
        <div class="td-section-title"><i />最近存证 <span>{{ recent.length }} records</span></div>
        <div class="td-record-table">
          <div class="td-record-row td-record-head"><span>文件名</span><span>大小</span><span>创建时间</span><span>证明链状态</span><span>操作</span></div>
          <button v-for="record in recent" :key="record.record_id" type="button" class="td-record-row" :class="{ selected: selected?.record_id === record.record_id }" @click="choose(record)">
            <span class="td-file"><FileText :size="17" /><i />{{ record.file_name || '未命名存证' }}</span>
            <span>{{ formatBytes(record.content_length) }}</span>
            <span>{{ record.submitted_at ? new Date(record.submitted_at).toLocaleString('zh-CN', { hour12: false }) : '—' }}</span>
            <span class="td-level"><i :class="{ warn: record.proof_level === 'L2' }" />{{ record.proof_level || '—' }} {{ record.proof_level === 'L5' ? '已完成' : '进行中' }}</span>
            <span class="td-view">查看详情 <ArrowUpRight :size="14" /></span>
          </button>
          <div v-if="!recent.length" class="td-record-empty">
            <FileText :size="24" />
            <span><strong>还没有存证记录</strong><small>提交第一个文件后，真实证明链会显示在这里。</small></span>
            <RouterLink to="/attest">新建存证 <ArrowUpRight :size="14" /></RouterLink>
          </div>
        </div>
      </section>

      <section class="td-health-strip">
        <div class="td-health-title"><Activity :size="27" /><strong>系统健康</strong></div>
        <div v-for="stat in healthStats" :key="stat.label"><span>{{ stat.label }}</span><strong>{{ stat.value }}</strong></div>
      </section>
    </section>

    <aside class="td-inspector">
      <template v-if="selected">
        <p class="td-kicker">当前存证详情</p>
        <div class="td-inspector__file"><FileText :size="24" /><div><strong>{{ selected.file_name || '未命名存证' }}</strong><span>{{ formatBytes(selected.content_length) }}</span></div></div>
        <dl>
          <div><dt>存证 ID</dt><dd><code>{{ selected.record_id }}</code><button type="button" @click="copyRecordId" aria-label="复制存证 ID"><Copy :size="13" /></button></dd></div>
          <div><dt>创建时间</dt><dd>{{ selected.submitted_at ? new Date(selected.submitted_at).toLocaleString('zh-CN', { hour12: false }) : '—' }}</dd></div>
          <div><dt>证明链状态</dt><dd class="td-active-status"><i />{{ selected.proof_level || '—' }} {{ selected.proof_level === 'L5' ? '已完成' : '进行中' }}</dd></div>
        </dl>
        <div class="td-inspector__timeline">
          <div v-for="(level, index) in levels" :key="level.key" :class="{ active: levelState(index) === 'active', done: levelState(index) === 'done' }">
            <i><Check v-if="levelState(index) === 'done'" :size="11" /></i>
            <span><strong>{{ level.key }} {{ level.label }}</strong><small>{{ levelState(index) === 'done' ? '已完成' : levelState(index) === 'active' ? '进行中' : '待执行' }}</small></span>
          </div>
        </div>
        <div class="td-inspector__events"><span>最新事件</span><p><i />{{ eventCopy[0] }} <small>{{ relativeTime(selected.submitted_at || '') }}</small></p><p class="muted"><i />{{ eventCopy[1] }}</p></div>
        <RouterLink class="td-inspector__link" to="/records"><ShieldCheck :size="16" />查看完整证明链 <ArrowUpRight :size="15" /></RouterLink>
      </template>
      <div v-else class="td-inspector__empty">
        <ShieldCheck :size="30" />
        <p>选择一条真实存证后，这里会显示完整证明链。</p>
        <RouterLink to="/attest">创建第一条存证</RouterLink>
      </div>
    </aside>
  </div>
</template>
