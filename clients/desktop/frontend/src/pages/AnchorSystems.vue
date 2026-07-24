<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { api, AnchorSystem, AnchorSystemResource, AnchorSystemStatus, hasNativeBridge } from '@/lib/api'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import EmptyState from '@/components/EmptyState.vue'
import StatusDot from '@/components/StatusDot.vue'
import { Blocks, Box, Database, FileKey2, Network, RefreshCcw, ScrollText, Server } from 'lucide-vue-next'

const systems = ref<AnchorSystem[]>([])
const selectedID = ref('')
const status = ref<AnchorSystemStatus | null>(null)
const resources = ref<AnchorSystemResource[]>([])
const resourceKind = ref('')
const loading = ref(false)
const error = ref('')

const demoSystems: AnchorSystem[] = [{
  schema_version: 'trustdb.anchor-system.v1',
  system_id: 'example-evidence-chain',
  sink_name: 'example-go',
  display_name: '示例存证区块链',
  kind: 'evidence_blockchain',
  network: 'example-local',
  provider: 'trustdb-example',
  capabilities: ['anchor.publish', 'anchor.verify', 'evidence.read', 'system.status.read', 'node.read', 'block.read', 'transaction.read'],
  assurance: { independent_time: false, publicly_verifiable: false, decentralized: false, finality: 'deterministic-demo', custody: 'operator' },
}] as AnchorSystem[]

const demoResources: Record<string, AnchorSystemResource[]> = {
  node: [{ schema_version: 'trustdb.anchor-system-resource.v1', system_id: 'example-evidence-chain', kind: 'node', resource_id: 'example-node-1', status: 'online', summary: '单节点演示验证器' } as AnchorSystemResource],
  block: [{ schema_version: 'trustdb.anchor-system-resource.v1', system_id: 'example-evidence-chain', kind: 'block', resource_id: '128', height: 128, hash: 'a87e0f2d9a4c…', summary: 'TrustDB tree size 128 对应区块' } as AnchorSystemResource],
  transaction: [{ schema_version: 'trustdb.anchor-system-resource.v1', system_id: 'example-evidence-chain', kind: 'transaction', resource_id: 'tx-8d10…7b2f', parent_id: '128', status: 'committed', summary: 'STH 锚定交易' } as AnchorSystemResource],
}

const selected = computed(() => systems.value.find((item) => item.system_id === selectedID.value) ?? null)
const kindLabel: Record<string, string> = {
  timestamp_evidence: '仅存证锚点',
  evidence_blockchain: '存证区块链',
  full_blockchain: '完整区块链',
}
const resourceKinds = computed(() => {
  const caps = new Set(selected.value?.capabilities ?? [])
  return [
    { kind: 'node', capability: 'node.read', label: '节点', icon: Server },
    { kind: 'block', capability: 'block.read', label: '区块', icon: Blocks },
    { kind: 'transaction', capability: 'transaction.read', label: '交易', icon: ScrollText },
    { kind: 'account', capability: 'account.read', label: '账户', icon: FileKey2 },
    { kind: 'contract', capability: 'contract.read', label: '合约', icon: Box },
  ].filter((item) => caps.has(item.capability))
})

function statusState(): 'ok' | 'warn' | 'bad' | 'idle' {
  if (status.value?.state === 'healthy') return 'ok'
  if (status.value?.state === 'degraded') return 'warn'
  if (status.value?.state === 'unavailable') return 'bad'
  return 'idle'
}

async function loadSystems() {
  loading.value = true
  error.value = ''
  try {
    systems.value = hasNativeBridge() ? await api.listAnchorSystems() : demoSystems
    if (!selectedID.value || !systems.value.some((item) => item.system_id === selectedID.value)) {
      selectedID.value = systems.value[0]?.system_id ?? ''
    }
  } catch (e: any) {
    error.value = String(e?.message ?? e)
    systems.value = []
  } finally {
    loading.value = false
  }
}

async function loadSelected() {
  if (!selected.value) return
  loading.value = true
  error.value = ''
  const defaultKind = resourceKinds.value[0]?.kind ?? ''
  if (!resourceKinds.value.some((item) => item.kind === resourceKind.value)) resourceKind.value = defaultKind
  try {
    if (hasNativeBridge()) {
	  status.value = selected.value.capabilities.includes('system.status.read')
	    ? await api.getAnchorSystemStatus(selected.value.system_id)
	    : ({ schema_version: 'trustdb.anchor-system-status.v1', system_id: selected.value.system_id, state: 'unknown', observed_at_unix_nano: 0, message: 'Provider 未声明实时状态读取能力' } as AnchorSystemStatus)
      resources.value = resourceKind.value
        ? (await api.listAnchorSystemResources(selected.value.system_id, resourceKind.value, 100)).resources ?? []
        : []
    } else {
      status.value = {
        schema_version: 'trustdb.anchor-system-status.v1', system_id: selected.value.system_id, state: 'healthy',
        observed_at_unix_nano: Date.now() * 1_000_000, message: '示例 provider 正常运行',
        details: { node_count: '1', block_count: '128', transaction_count: '128', sync_height: '128' },
      } as AnchorSystemStatus
      resources.value = demoResources[resourceKind.value] ?? []
    }
  } catch (e: any) {
    error.value = String(e?.message ?? e)
    resources.value = []
  } finally {
    loading.value = false
  }
}

function capabilityLabel(value: string) {
  return value.replaceAll('.', ' · ')
}

function short(value?: string) {
  if (!value) return '—'
  return value.length > 28 ? `${value.slice(0, 16)}…${value.slice(-8)}` : value
}

watch(selectedID, loadSelected)
watch(resourceKind, loadSelected)
onMounted(loadSystems)
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1240px] mx-auto">
    <Card dense>
      <template #title>
        <div class="flex items-center gap-2">
          <Network :size="16" class="text-accent" />
          <div>
            <h3 class="text-[14px] font-semibold text-ink-100">下游锚系统</h3>
            <p class="text-[11.5px] text-ink-400">统一查看 L5 provider 的能力、可信属性与实时资源；实时状态不参与 L5 证明判定。</p>
          </div>
        </div>
      </template>
      <template #actions>
        <Button size="sm" variant="subtle" :loading="loading" @click="loadSystems"><RefreshCcw :size="12" />刷新</Button>
      </template>
      <div v-if="error" class="px-5 py-3 text-[12px] text-danger border-b border-[var(--hairline)]">{{ error }}</div>
      <div v-if="systems.length" class="flex gap-2 px-5 py-4 overflow-x-auto">
        <button
          v-for="system in systems" :key="system.system_id" type="button" @click="selectedID = system.system_id"
          class="min-w-[220px] rounded-xl border px-4 py-3 text-left transition"
          :class="selectedID === system.system_id ? 'border-accent/60 bg-accent/10' : 'border-[var(--hairline)] bg-white/[0.025] hover:bg-white/[0.05]'"
        >
          <div class="flex items-center justify-between gap-3">
            <strong class="text-[13px] text-ink-100">{{ system.display_name }}</strong>
            <StatusDot :state="selectedID === system.system_id ? statusState() : 'idle'" />
          </div>
          <div class="mt-1 text-[11px] text-ink-400">{{ kindLabel[system.kind] || system.kind }} · {{ system.network || system.provider }}</div>
          <code class="mt-2 block text-[10.5px] text-accent/80">{{ system.system_id }}</code>
        </button>
      </div>
      <div v-else class="px-5"><EmptyState title="未配置锚系统" :hint="error || '服务端当前未启用 L5 anchor sink。'" :icon="Network" /></div>
    </Card>

    <template v-if="selected">
      <div class="grid grid-cols-1 lg:grid-cols-[1.15fr_.85fr] gap-5">
        <Card title="语义描述" :subtitle="`${kindLabel[selected.kind] || selected.kind} · sink ${selected.sink_name}`">
          <div class="grid grid-cols-2 gap-3 text-[12px]">
            <div class="rounded-xl border border-[var(--hairline)] p-3"><span class="text-ink-500">Provider</span><strong class="mt-1 block text-ink-100">{{ selected.provider || '—' }}</strong></div>
            <div class="rounded-xl border border-[var(--hairline)] p-3"><span class="text-ink-500">Network</span><strong class="mt-1 block text-ink-100">{{ selected.network || '—' }}</strong></div>
          </div>
          <div class="mt-4 flex flex-wrap gap-1.5">
            <span v-for="cap in selected.capabilities" :key="cap" class="rounded-full border border-accent/20 bg-accent/[0.06] px-2 py-1 text-[10.5px] text-accent">{{ capabilityLabel(cap) }}</span>
          </div>
          <div class="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px]">
            <div class="rounded-lg bg-white/[0.025] p-2"><span class="text-ink-500">独立时间</span><b class="block mt-1">{{ selected.assurance.independent_time ? '是' : '否' }}</b></div>
            <div class="rounded-lg bg-white/[0.025] p-2"><span class="text-ink-500">公开可验</span><b class="block mt-1">{{ selected.assurance.publicly_verifiable ? '是' : '否' }}</b></div>
            <div class="rounded-lg bg-white/[0.025] p-2"><span class="text-ink-500">去中心化</span><b class="block mt-1">{{ selected.assurance.decentralized ? '是' : '否' }}</b></div>
            <div class="rounded-lg bg-white/[0.025] p-2"><span class="text-ink-500">终局性</span><b class="block mt-1">{{ selected.assurance.finality || '未声明' }}</b></div>
          </div>
        </Card>

        <Card title="实时状态" subtitle="Provider 返回的可变快照">
          <div class="flex items-center gap-2"><StatusDot :state="statusState()" /><strong class="text-[14px]">{{ status?.state || 'unknown' }}</strong></div>
          <p class="mt-2 text-[12px] text-ink-400">{{ status?.message || '暂无状态说明' }}</p>
          <div class="mt-4 grid grid-cols-2 gap-2">
            <div v-for="(value, key) in status?.details" :key="key" class="rounded-lg border border-[var(--hairline)] p-2.5">
              <div class="text-[10px] uppercase tracking-wide text-ink-500">{{ key }}</div><div class="mt-1 num text-[14px] text-ink-100">{{ value }}</div>
            </div>
          </div>
        </Card>
      </div>

      <Card title="系统资源" subtitle="节点、区块、交易、账户与合约由 capability 动态开放" dense>
        <div class="flex gap-2 px-5 py-3 border-b border-[var(--hairline)]">
          <button v-for="item in resourceKinds" :key="item.kind" type="button" @click="resourceKind = item.kind" class="inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-[11.5px]" :class="resourceKind === item.kind ? 'bg-accent text-black' : 'bg-white/[0.04] text-ink-300'">
            <component :is="item.icon" :size="12" />{{ item.label }}
          </button>
        </div>
        <div v-if="!resourceKinds.length" class="px-5"><EmptyState title="此锚点只提供存取证" hint="Provider 未声明节点、区块、交易、账户或合约读取能力。" :icon="Database" /></div>
        <div v-else-if="!resources.length" class="px-5"><EmptyState title="暂无资源" hint="Provider 当前没有返回该类型资源。" :icon="Database" /></div>
        <div v-else class="overflow-x-auto">
          <table class="w-full text-[12px]">
            <thead class="text-left text-ink-500"><tr><th class="pl-5 py-2 font-normal">ID</th><th class="px-3 py-2 font-normal">状态 / 高度</th><th class="px-3 py-2 font-normal">摘要</th><th class="pr-5 py-2 font-normal">Hash / Parent</th></tr></thead>
            <tbody><tr v-for="item in resources" :key="item.resource_id" class="border-t border-[var(--hairline)]"><td class="pl-5 py-3 font-mono text-accent">{{ short(item.resource_id) }}</td><td class="px-3 py-3">{{ item.status || (item.height != null ? `#${item.height}` : '—') }}</td><td class="px-3 py-3 text-ink-300">{{ item.summary || '—' }}</td><td class="pr-5 py-3 font-mono text-[10.5px] text-ink-500">{{ short(item.hash || item.parent_id) }}</td></tr></tbody>
          </table>
        </div>
      </Card>
    </template>
  </div>
</template>
