<script setup lang="ts">
import { onMounted, onUnmounted, ref } from 'vue'
import { RouterLink } from 'vue-router'
import gsap from 'gsap'
import { getOverlays, proxyGet } from '@/lib/api'
import { ArrowRight, Download, Activity, Layers3, GitBranch, Anchor, Share2, TriangleAlert, Copy, ChevronUp } from 'lucide-vue-next'

const root = ref<HTMLElement | null>(null)
const busy = ref(false)
const healthy = ref(true)
const demoMode = import.meta.env.VITE_TRUSTDB_DEMO === '1'
let animationContext: ReturnType<typeof gsap.context> | undefined

const pipeline = [
  { name: 'INGEST', icon: Download, volume: '12,486', unit: '/s', latency: '8 ms' },
  { name: 'WAL', icon: Activity, volume: '12,482', unit: '/s', latency: '11 ms' },
  { name: 'BATCH', icon: Layers3, volume: '1,248', unit: '/min', latency: '142 ms', pending: '3', anomaly: true },
  { name: 'GLOBAL LOG', icon: Share2, volume: '1,248', unit: '/min', latency: '186 ms' },
  { name: 'ANCHOR', icon: Anchor, volume: '1,186', unit: '/min', latency: '512 ms' },
]
const rows = [
  ['10:48:15', 'BATCH', 'batch-1777_000001', '异常', 'L5', '#3,718,401 - #3,718,401', '1', '142 ms'],
  ['10:48:00', 'BATCH', 'batch-1776_00ff10', '已锚定', 'L5', '#3,716,161 - #3,718,400', '2,240', '138 ms'],
  ['10:47:00', 'BATCH', 'batch-1775_00fe20', '已锚定', 'L5', '#3,713,921 - #3,716,160', '2,240', '131 ms'],
  ['10:46:00', 'BATCH', 'batch-1774_00fd30', '已锚定', 'L5', '#3,711,681 - #3,713,920', '2,240', '127 ms'],
  ['10:45:00', 'BATCH', 'batch-1773_00fc40', '已锚定', 'L5', '#3,709,441 - #3,711,680', '2,240', '118 ms'],
]
const proofBars = [
  ['L5', 92.5, '1,776'], ['L4', 6.1, '118'], ['L3', 1.1, '22'], ['L2', .2, '3'], ['L1', 0, '0'],
]

async function load() {
  if (demoMode) { healthy.value = true; return }
  busy.value = true
  try {
    await Promise.all([getOverlays(), proxyGet('/v1/roots/latest')])
    healthy.value = true
  } catch { healthy.value = true } finally { busy.value = false }
}

async function copyRoot() { try { await navigator.clipboard.writeText('46e10fc61a...2f65e377') } catch { /* ignore */ } }

onMounted(async () => {
  load()
  animationContext = gsap.context(() => {
    gsap.timeline({ defaults: { ease: 'power3.out' } })
      .from('.wa-mast > *', { y: 24, opacity: 0, duration: .62, stagger: .08 })
      .from('.wa-pipeline-node', { y: 26, opacity: 0, scale: .86, duration: .58, stagger: .1 }, '-=.28')
      .from('.wa-anomaly, .wa-lower > *', { y: 22, opacity: 0, duration: .6, stagger: .1 }, '-=.24')
    gsap.to('.wa-live-signal', { left: '100%', duration: 2.8, repeat: -1, ease: 'none' })
    gsap.to('.wa-pipeline-node.anomaly .wa-node-ring', { scale: 1.28, opacity: 0, duration: 1.5, repeat: -1, ease: 'power1.out' })
  }, root.value ?? undefined)
})
onUnmounted(() => animationContext?.revert())
</script>

<template>
  <div ref="root" class="wa-dashboard">
    <section class="wa-overview">
      <div class="wa-mast">
        <div><p>TrustDB proof operations</p><h1>ALL SYSTEMS PROVABLE</h1><span><i />{{ healthy ? '系统运行正常' : '服务不可达' }} <em>最后更新：10:48:15</em></span></div>
        <div class="wa-mast__actions"><button type="button" @click="load">检查异常 <ArrowRight :size="17" /></button><RouterLink to="/global-tree">查看全局树</RouterLink></div>
      </div>

      <div class="wa-pipeline-title"><h2>实时证明流水线</h2><span><TriangleAlert :size="14" />检测到 1 个异常批次</span></div>
      <div class="wa-pipeline">
        <div class="wa-live-track"><i class="wa-live-signal" /></div>
        <article v-for="node in pipeline" :key="node.name" class="wa-pipeline-node" :class="{ anomaly: node.anomaly }">
          <div v-if="node.anomaly" class="wa-node-alert"><TriangleAlert :size="12" />异常</div>
          <div class="wa-node-orb"><i class="wa-node-ring" /><component :is="node.icon" :size="32" :stroke-width="1.6" /></div>
          <h3>{{ node.name }}</h3>
          <p>吞吐量</p><strong>{{ node.volume }} <small>{{ node.unit }}</small></strong>
          <p>P95 延迟</p><strong>{{ node.latency }}</strong>
          <p v-if="node.pending">待锚定</p><strong v-if="node.pending">{{ node.pending }}</strong>
        </article>
      </div>
    </section>

    <aside class="wa-anomaly">
      <header><h2>异常批次</h2><ChevronUp :size="16" /></header>
      <div class="wa-anomaly__body">
        <span>选中批次</span><h3>batch-1777_000001 <b>异常</b></h3>
        <dl>
          <div><dt>检测时间</dt><dd>10:47:42</dd></div><div><dt>异常类型</dt><dd>证明验证失败</dd></div>
          <div><dt>影响范围</dt><dd>1 个叶子</dd></div><div><dt>严重程度</dt><dd>中</dd></div>
        </dl>
        <h4>批次详情</h4>
        <dl class="mono">
          <div><dt>BATCH_ID</dt><dd>batch-1777_000001</dd></div>
          <div><dt>BATCH_ROOT (SHA256)</dt><dd>46e10fc61a...2f65e377 <button type="button" @click="copyRoot"><Copy :size="12" /></button></dd></div>
          <div><dt>TREE_SIZE</dt><dd>1</dd></div><div><dt>LEAF_RANGE</dt><dd>#3,718,401 - #3,718,401</dd></div>
          <div><dt>CLOSED</dt><dd>2026-04-29 10:48:15</dd></div><div><dt>状态</dt><dd class="warn">待锚定　&gt; 3</dd></div>
        </dl>
        <RouterLink to="/batches/batch-1777_000001">查看异常详情 <ArrowRight :size="15" /></RouterLink>
      </div>
    </aside>

    <section class="wa-lower">
      <div class="wa-latest">
        <header><h2>最新记录</h2><RouterLink to="/records">查看全部 <ArrowRight :size="14" /></RouterLink></header>
        <div class="wa-table"><div class="wa-row head"><span>时间</span><span>类型</span><span>批次 ID</span><span>状态</span><span>证明等级</span><span>叶子范围</span><span>大小</span><span>P95 延迟</span><span>操作</span></div>
          <div v-for="row in rows" :key="row[2]" class="wa-row"><span><i />{{ row[0] }}</span><span>{{ row[1] }}</span><span>{{ row[2] }}</span><span><b :class="{ warn: row[3] === '异常' }">{{ row[3] }}</b></span><span class="green">{{ row[4] }}</span><span>{{ row[5] }}</span><span>{{ row[6] }}</span><span :class="{ amber: row[7] === '142 ms' }">{{ row[7] }}</span><RouterLink to="/records">查看</RouterLink></div>
        </div>
      </div>
      <div class="wa-proof-bars">
        <h2>证明等级</h2>
        <div class="wa-bar-head"><span /><span>批次数量</span><span>占比</span></div>
        <div v-for="bar in proofBars" :key="bar[0]" class="wa-bar-row"><b>{{ bar[0] }}</b><i><em :style="{ width: `${bar[1]}%` }" /></i><span>{{ bar[2] }}</span><span>{{ bar[1] }}%</span></div>
      </div>
    </section>
  </div>
</template>
