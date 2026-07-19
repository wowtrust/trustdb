<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import { storeToRefs } from 'pinia'
import gsap from 'gsap'
import { useRecords } from '@/stores/records'
import { LocalRecord } from '@/lib/api'
import { relativeTime } from '@/lib/format'
import { PenLine, ReceiptText, GitFork, Globe2, Anchor, Check, FileText, Copy, ArrowUpRight, Plus, ShieldCheck, Activity } from 'lucide-vue-next'

const root = ref<HTMLElement | null>(null)
let animationContext: ReturnType<typeof gsap.context> | undefined
const records = useRecords()
const { records: storedRecords } = storeToRefs(records)

const demoRecords = [
  { record_id: 'tr13g7...bond2q', file_name: '测试存证.txt', content_length: 1240, submitted_at: '2026-04-29T10:48:15Z', proof_level: 'L4' },
  { record_id: 'tr72ab...19fe80', file_name: '合同条款.pdf', content_length: 320110, submitted_at: '2026-04-29T09:21:44Z', proof_level: 'L5' },
  { record_id: 'tr9c24...70cffa', file_name: '会议纪要.md', content_length: 18770, submitted_at: '2026-04-29T08:05:12Z', proof_level: 'L5' },
  { record_id: 'tr833e...05fa1c', file_name: '设计规范_v2.pdf', content_length: 4520000, submitted_at: '2026-04-28T17:36:09Z', proof_level: 'L2' },
  { record_id: 'tr121a...a07dc3', file_name: '报价单.xlsx', content_length: 62330, submitted_at: '2026-04-28T15:10:33Z', proof_level: 'L4' },
] as Partial<LocalRecord>[]

const recent = computed(() => (storedRecords.value.length ? storedRecords.value.slice(0, 5) : demoRecords))
const selected = ref<Partial<LocalRecord>>(demoRecords[0])
const levels = [
  { key: 'L1', label: '签名', note: '已签名', icon: PenLine },
  { key: 'L2', label: '收据', note: '收据已生成', icon: ReceiptText },
  { key: 'L3', label: 'MERKLE', note: '已加入默克尔树', icon: GitFork },
  { key: 'L4', label: 'GLOBAL', note: '已写入全球透明日志', icon: Globe2 },
  { key: 'L5', label: '外部锚定', note: '等待外部锚定', icon: Anchor },
]
const levelIndex = computed(() => Math.max(0, levels.findIndex((item) => item.key === (selected.value.proof_level || 'L4'))))

function levelState(index: number) {
  if (index < levelIndex.value || (index === levelIndex.value && selected.value.proof_level === 'L5')) return 'done'
  if (index === levelIndex.value) return 'active'
  return 'pending'
}

function formatBytes(value = 0) {
  if (value < 1024) return `${value} B`
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(2)} KB`
  return `${(value / 1024 / 1024).toFixed(2)} MB`
}

function choose(record: Partial<LocalRecord>) { selected.value = record }
async function copyRecordId() { try { await navigator.clipboard.writeText(selected.value.record_id || '') } catch { /* ignore */ } }

onMounted(async () => {
  try { await records.refreshAllPending() } catch { /* keep cached records */ }
  if (storedRecords.value.length) selected.value = storedRecords.value[0]
  animationContext = gsap.context(() => {
    // Background browser tabs throttle animation frames. Skip only the intro
    // reveal in that state so the interface never gets stranded at opacity 0.
    if (document.visibilityState === 'visible') {
      gsap.timeline({ defaults: { ease: 'power3.out' } })
        .from('.td-dashboard__mast > *', { y: 24, opacity: 0, duration: .6, stagger: .08 })
        .from('.td-proof-node', { scale: .72, opacity: 0, duration: .55, stagger: .09 }, '-=.25')
        .from('.td-data-section, .td-inspector', { y: 26, opacity: 0, duration: .6, stagger: .1 }, '-=.3')
    }
    gsap.to('.td-proof-signal', { left: '100%', duration: 3.2, repeat: -1, ease: 'none' })
    gsap.to('.td-proof-node.is-current .td-proof-ring', { scale: 1.28, opacity: 0, duration: 1.6, repeat: -1, ease: 'power1.out' })
  }, root.value ?? undefined)
})

onUnmounted(() => animationContext?.revert())
</script>

<template>
  <div ref="root" class="td-dashboard">
    <section class="td-dashboard__main">
      <div class="td-dashboard__mast">
        <div>
          <h2>DESKTOP-1</h2>
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
            <p>{{ level.note }}</p>
          </article>
        </div>
      </section>

      <section class="td-data-section">
        <div class="td-section-title"><i />最近存证 <span>{{ recent.length }} records</span></div>
        <div class="td-record-table">
          <div class="td-record-row td-record-head"><span>文件名</span><span>大小</span><span>创建时间</span><span>证明链状态</span><span>操作</span></div>
          <button v-for="record in recent" :key="record.record_id" type="button" class="td-record-row" :class="{ selected: selected.record_id === record.record_id }" @click="choose(record)">
            <span class="td-file"><FileText :size="17" /><i />{{ record.file_name }}</span>
            <span>{{ formatBytes(record.content_length) }}</span>
            <span>{{ record.submitted_at ? new Date(record.submitted_at).toLocaleString('zh-CN', { hour12: false }) : '—' }}</span>
            <span class="td-level"><i :class="{ warn: record.proof_level === 'L2' }" />{{ record.proof_level }} {{ record.proof_level === 'L5' ? '已完成' : '进行中' }}</span>
            <span class="td-view">查看详情 <ArrowUpRight :size="14" /></span>
          </button>
        </div>
      </section>

      <section class="td-health-strip">
        <div class="td-health-title"><Activity :size="27" /><strong>系统健康</strong></div>
        <div><span>节点连接</span><strong>5 / 5 正常</strong></div>
        <div><span>日志延迟</span><strong>1.2s</strong></div>
        <div><span>可用性</span><strong>99.99%</strong></div>
        <div><span>本地存储</span><strong>2.14 TB 可用</strong></div>
        <div><span>运行时间</span><strong>12 天 07:41:22</strong></div>
      </section>
    </section>

    <aside class="td-inspector">
      <p class="td-kicker">当前存证详情</p>
      <div class="td-inspector__file"><FileText :size="24" /><div><strong>{{ selected.file_name }}</strong><span>{{ formatBytes(selected.content_length) }}</span></div></div>
      <dl>
        <div><dt>存证 ID</dt><dd><code>{{ selected.record_id }}</code><button type="button" @click="copyRecordId"><Copy :size="13" /></button></dd></div>
        <div><dt>创建时间</dt><dd>{{ selected.submitted_at ? new Date(selected.submitted_at).toLocaleString('zh-CN', { hour12: false }) : '—' }}</dd></div>
        <div><dt>证明链状态</dt><dd class="td-active-status"><i />{{ selected.proof_level }} {{ selected.proof_level === 'L5' ? '已完成' : '进行中' }}</dd></div>
      </dl>
      <div class="td-inspector__timeline">
        <div v-for="(level, index) in levels" :key="level.key" :class="{ active: levelState(index) === 'active', done: levelState(index) === 'done' }">
          <i><Check v-if="levelState(index) === 'done'" :size="11" /></i>
          <span><strong>{{ level.key }} {{ level.label }}</strong><small>{{ levelState(index) === 'done' ? '已完成' : levelState(index) === 'active' ? '进行中' : '待执行' }}</small></span>
        </div>
      </div>
      <div class="td-inspector__events"><span>最新事件</span><p><i />已写入全球透明日志 <small>{{ relativeTime(selected.submitted_at || '') }}</small></p><p class="muted"><i />等待外部锚定</p></div>
      <RouterLink class="td-inspector__link" to="/records"><ShieldCheck :size="16" />查看完整证明链 <ArrowUpRight :size="15" /></RouterLink>
    </aside>
  </div>
</template>
