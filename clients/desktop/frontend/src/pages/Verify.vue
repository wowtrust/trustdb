<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, VerifyRequest, VerifyResponse } from '@/lib/api'
import { useSettings } from '@/stores/settings'
import { useToasts } from '@/stores/toasts'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import LevelBadge from '@/components/LevelBadge.vue'
import HashChip from '@/components/HashChip.vue'
import KV from '@/components/KV.vue'
import {
  FolderOpen, FileSearch, CheckCircle2, XCircle, Loader2, ShieldCheck, ShieldAlert,
} from 'lucide-vue-next'
import { bytesToHex, formatTime, humanSize, nanoToDate } from '@/lib/format'

const settings = useSettings()
const toasts = useToasts()

type Mode = 'local' | 'remote'
const mode = ref<Mode>('local')

// Shared input
const filePath = ref('')
const clientPub = ref('')
const serverPub = ref('')
const skipAnchor = ref(false)

// Local-only
const singleProofPath = ref('')
const proofPath = ref('')
const globalProofPath = ref('')
const anchorPath = ref('')
const showSplitProofs = ref(false)

// Remote-only
const recordID = ref('')
const serverURL = ref('')
const configuredTransport = computed(() => (settings.settings.server_transport || 'http').toUpperCase())

const running = ref(false)
const result = ref<VerifyResponse | null>(null)

async function pickFile(target: 'file' | 'single' | 'proof' | 'global' | 'anchor') {
  const title =
    target === 'file' ? '选择被存证文件' :
    target === 'single' ? '选择 .sproof 单文件证明' :
    target === 'proof' ? '选择 .tdproof' :
    target === 'global' ? '选择 .tdgproof' :
    '选择 .tdanchor-result'
  const p = await api.chooseOpenPath(title)
  if (!p) return
  if (target === 'file') filePath.value = p
  if (target === 'single') singleProofPath.value = p
  if (target === 'proof') proofPath.value = p
  if (target === 'global') globalProofPath.value = p
  if (target === 'anchor') anchorPath.value = p
}

const canVerify = computed(() => {
  if (!filePath.value) return false
  if (mode.value === 'local') return !!singleProofPath.value || !!proofPath.value
  return !!recordID.value
})

async function verify() {
  if (!canVerify.value) return
  running.value = true
  result.value = null
  const req: VerifyRequest = {
    mode: mode.value,
    file_path: filePath.value,
    single_proof_path: singleProofPath.value || undefined,
    proof_path: proofPath.value || undefined,
    global_proof_path: globalProofPath.value || undefined,
    anchor_path: anchorPath.value || undefined,
    server_url: serverURL.value || undefined,
    record_id: recordID.value || undefined,
    skip_anchor: skipAnchor.value,
    client_public_key_b64: clientPub.value || undefined,
    server_public_key_b64: serverPub.value || undefined,
  }
  try {
    const res = await api.verifyProof(req)
    result.value = res
    if (res.valid) toasts.success(`验证通过 · ${res.level}`)
    else toasts.error('验证未通过', res.error)
  } catch (e: any) {
    toasts.error('验证出错', String(e?.message ?? e))
  } finally {
    running.value = false
  }
}

// L1→L5 step gate: figures out, from the outcome, which steps we
// should show as passed, current, or not-yet-reached. Conceptually
// mirrors the server's ProofLevel ladder.
type Step = { level: 'L1' | 'L2' | 'L3' | 'L4' | 'L5'; label: string; hint: string }
const STEPS: Step[] = [
  { level: 'L1', label: 'L1 本地内容与签名',   hint: '内容哈希匹配、客户端签名合法' },
  { level: 'L2', label: 'L2 服务端受理收据',   hint: 'AcceptedReceipt 签名有效' },
  { level: 'L3', label: 'L3 批次承诺',         hint: 'Merkle 审计路径到 BatchRoot' },
  { level: 'L4', label: 'L4 Global Log',       hint: 'BatchRoot 已进入某个 SignedTreeHead' },
  { level: 'L5', label: 'L5 外部锚定',         hint: '同一个 STH/global root 已被外部 sink 锚定' },
]

function stepState(s: Step): 'pass' | 'current' | 'todo' | 'fail' {
  const r = result.value
  if (!r) return 'todo'
  const order = ['L1', 'L2', 'L3', 'L4', 'L5']
  const reached = order.indexOf(r.level || '')
  const mine = order.indexOf(s.level)
  if (!r.valid && mine === reached + 1) return 'fail'
  if (mine <= reached && reached >= 0) return 'pass'
  if (mine === reached + 1) return 'current'
  return 'todo'
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1100px] mx-auto">
    <!-- Mode tabs + intro -->
    <Card>
      <template #title>
        <div class="flex items-center gap-2">
          <ShieldCheck :size="16" class="text-accent" />
          <h3 class="text-[14px] font-semibold tracking-[-0.01em] text-ink-800 dark:text-ink-100">验证存证</h3>
        </div>
      </template>
      <template #actions>
        <div class="inline-flex items-center gap-1 p-1 rounded-lg hairline border bg-white/50 dark:bg-ink-800/50">
          <button
            v-for="t in [{ v: 'local', l: '本地证据' }, { v: 'remote', l: '远程查询' }]"
            :key="t.v"
            class="px-3 h-7 rounded-md text-[12px] transition-all duration-150 ease-ios"
            :class="mode === t.v
              ? 'bg-white dark:bg-ink-700 text-ink-800 dark:text-ink-100 shadow-soft-sm'
              : 'text-ink-500 hover:text-ink-700'"
            @click="mode = t.v as Mode"
          >{{ t.l }}</button>
        </div>
      </template>

      <p class="text-[12.5px] text-ink-500 leading-relaxed mb-4">
        <template v-if="mode === 'local'">
          选择一份文件和它的 <span class="font-mono">.sproof</span> 单文件证明；它会携带当前可用的
          ProofBundle、GlobalLogProof 和 STHAnchorResult。全程离线即可验证，不需要连回服务器。
          需要逐级审计时，可以展开下方的分布式证明入口。
        </template>
        <template v-else>
          输入 record_id，客户端会按设置里的 <span class="font-mono">{{ configuredTransport }}</span>
          transport 从 <span class="font-mono">{{ serverURL || settings.settings.server_url || '（未配置）' }}</span>
          拉取 proof bundle、GlobalLogProof 和 STH anchor 并就地验证。
        </template>
      </p>
      <p v-if="settings.settings.anchor_plugin_command" class="mb-4 text-[11.5px] text-ink-500">
        自定义 L5 verifier：<span class="font-mono">{{ settings.settings.anchor_plugin_command }}</span>
      </p>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <!-- Common: file -->
        <Field label="被存证文件" hint="需要被核验内容的本机文件路径">
          <div class="flex items-center gap-2">
            <Input v-model="filePath" placeholder="选择或粘贴文件路径" />
            <Button size="sm" variant="subtle" @click="pickFile('file')">
              <FolderOpen :size="13" /> 浏览
            </Button>
          </div>
        </Field>

        <template v-if="mode === 'local'">
          <Field label=".sproof 单文件证明（推荐）" hint="包含当前可用的 L1-L5 证明路径；日常验证只需要这一份文件">
            <div class="flex items-center gap-2">
              <Input v-model="singleProofPath" placeholder="选择 .sproof" />
              <Button size="sm" variant="subtle" @click="pickFile('single')">
                <FolderOpen :size="13" /> 浏览
              </Button>
            </div>
          </Field>

          <div class="md:col-span-2">
            <button
              type="button"
              class="w-full rounded-[18px] hairline border bg-white/40 dark:bg-ink-800/35 px-4 py-3 text-left transition hover:border-accent/35 hover:bg-accent/5"
              @click="showSplitProofs = !showSplitProofs"
            >
              <div class="flex items-center justify-between gap-3">
                <div>
                  <div class="font-display text-[11px] font-bold uppercase tracking-[0.14em] text-ink-100">
                    分布式证明文件
                  </div>
                  <p class="mt-1 text-[11.5px] text-ink-500 leading-relaxed">
                    兼容底层审计：分别选择 <span class="font-mono">.tdproof</span> /
                    <span class="font-mono">.tdgproof</span> /
                    <span class="font-mono">.tdanchor-result</span>。如果已选择
                    <span class="font-mono">.sproof</span>，验证会优先使用单文件证明。
                  </p>
                </div>
                <span class="text-[11px] text-accent font-display uppercase tracking-[0.12em]">
                  {{ showSplitProofs ? '收起' : '展开' }}
                </span>
              </div>
            </button>
          </div>

          <template v-if="showSplitProofs">
            <Field label=".tdproof 证据包" hint="L1-L3 证据（及 claim/receipts）">
              <div class="flex items-center gap-2">
                <Input v-model="proofPath" placeholder="选择 .tdproof" />
                <Button size="sm" variant="subtle" @click="pickFile('proof')">
                  <FolderOpen :size="13" /> 浏览
                </Button>
              </div>
            </Field>
            <Field label=".tdgproof（可选）" hint="BatchRoot → SignedTreeHead inclusion proof，用于 L4">
              <div class="flex items-center gap-2">
                <Input v-model="globalProofPath" placeholder="选择 .tdgproof" />
                <Button size="sm" variant="subtle" @click="pickFile('global')">
                  <FolderOpen :size="13" /> 浏览
                </Button>
              </div>
            </Field>
            <Field label=".tdanchor-result（可选）" hint="STHAnchorResult；需要同时提供 .tdgproof 才能验证 L5">
              <div class="flex items-center gap-2">
                <Input v-model="anchorPath" placeholder="选择 .tdanchor-result" />
                <Button size="sm" variant="subtle" @click="pickFile('anchor')">
                  <FolderOpen :size="13" /> 浏览
                </Button>
              </div>
            </Field>
          </template>
        </template>

        <template v-else>
          <Field label="record_id" hint="服务端返回的 64 位十六进制 ID">
            <Input v-model="recordID" placeholder="例如 2e9d…" :mono="true" />
          </Field>
          <Field label="服务器地址（可选）" :hint="`默认使用设置里的 ${configuredTransport} · ${settings.settings.server_url || 'http://localhost:8081'}`">
            <Input v-model="serverURL" :placeholder="configuredTransport === 'GRPC' ? '127.0.0.1:9090' : 'http://host:8081'" />
          </Field>
        </template>

        <Field label="客户端公钥 base64（可选）" hint="留空则使用当前身份公钥">
          <Input v-model="clientPub" placeholder="Ed25519 public key (base64)" :mono="true" />
        </Field>
        <Field label="服务器公钥 base64（可选）" hint="留空则读取设置里的服务器公钥">
          <Input v-model="serverPub" placeholder="Ed25519 public key (base64)" :mono="true" />
        </Field>
      </div>

      <div class="mt-4 flex items-center justify-between">
        <label class="inline-flex items-center gap-2 text-[12.5px] text-ink-600 dark:text-ink-300 select-none">
          <input type="checkbox" v-model="skipAnchor" class="accent-accent" />
          跳过 L5 外部锚定（仍会尽量验证 L4 Global Log）
        </label>
        <Button :disabled="!canVerify" :loading="running" @click="verify">
          <FileSearch :size="14" /> 开始验证
        </Button>
      </div>
    </Card>

    <!-- Result -->
    <Card v-if="result" :title="result.valid ? '验证通过' : '验证未通过'" :subtitle="result.error">
      <template #actions>
        <LevelBadge v-if="result.level" :level="result.level" />
      </template>

      <!-- Level ladder -->
      <ol class="relative">
        <li
          v-for="(s, i) in STEPS"
          :key="s.level"
          class="flex gap-3 py-2.5"
        >
          <div class="relative flex flex-col items-center">
            <span
              class="w-6 h-6 rounded-full flex items-center justify-center transition-colors duration-200 ease-ios"
              :class="{
                'bg-success text-white': stepState(s) === 'pass',
                'bg-accent/15 text-accent ring-2 ring-accent/40': stepState(s) === 'current',
                'bg-danger text-white': stepState(s) === 'fail',
                'bg-ink-100 dark:bg-ink-800 text-ink-400': stepState(s) === 'todo',
              }"
            >
              <CheckCircle2 v-if="stepState(s) === 'pass'" :size="13" />
              <Loader2 v-else-if="stepState(s) === 'current'" :size="13" class="animate-spin" />
              <XCircle v-else-if="stepState(s) === 'fail'" :size="13" />
              <span v-else class="text-[10px]">{{ i + 1 }}</span>
            </span>
            <span
              v-if="i < STEPS.length - 1"
              class="w-px flex-1 mt-1 transition-colors"
              :class="stepState(s) === 'pass' ? 'bg-success/40' : 'bg-[var(--hairline)]'"
            />
          </div>
          <div class="flex-1 pb-1">
            <div class="text-[13px] font-medium text-ink-800 dark:text-ink-100">{{ s.label }}</div>
            <div class="text-[11.5px] text-ink-500">{{ s.hint }}</div>
          </div>
        </li>
      </ol>

      <!-- Detail -->
      <div v-if="result.bundle" class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <div class="rounded-xl hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
          <h4 class="text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-1">Claim</h4>
          <KV label="record_id" :inline="true"><HashChip :value="result.record_id" :head="10" :tail="8" /></KV>
          <KV label="tenant" :inline="true">
            <span class="font-mono text-[11.5px]">{{ result.bundle.signed_claim.claim.tenant_id }}</span>
          </KV>
          <KV label="client" :inline="true">
            <span class="font-mono text-[11.5px]">{{ result.bundle.signed_claim.claim.client_id }}</span>
          </KV>
          <KV label="key_id" :inline="true">
            <span class="font-mono text-[11.5px]">{{ result.bundle.signed_claim.claim.key_id }}</span>
          </KV>
          <KV label="content" :inline="true">
            <span class="text-[11.5px]">{{ humanSize(result.content_bytes) }} · {{ result.bundle.signed_claim.claim.content.media_type || '—' }}</span>
          </KV>
          <KV label="sha256" :inline="true">
            <HashChip :value="bytesToHex(result.bundle.signed_claim.claim.content.content_hash)" :head="8" :tail="8" />
          </KV>
        </div>

        <div class="rounded-xl hairline border bg-white/50 dark:bg-ink-800/40 p-3 space-y-2">
          <h4 class="text-[12px] font-semibold text-ink-700 dark:text-ink-100 mb-1">Batch & Anchor</h4>
          <KV label="batch_id" :inline="true">
            <HashChip :value="result.bundle.committed_receipt?.batch_id" :head="10" :tail="8" />
          </KV>
          <KV label="leaf_index" :inline="true">
            <span class="num">{{ result.bundle.committed_receipt?.leaf_index }}</span>
          </KV>
          <KV label="tree_size" :inline="true">
            <span class="num">{{ result.bundle.batch_proof?.tree_size }}</span>
          </KV>
          <KV label="batch_root" :inline="true">
            <HashChip :value="bytesToHex(result.bundle.committed_receipt?.batch_root)" :head="8" :tail="8" />
          </KV>
          <template v-if="result.global_proof">
            <KV label="sth_tree_size" :inline="true">
              <span class="num">{{ result.global_proof.sth.tree_size }}</span>
            </KV>
            <KV label="global_root" :inline="true">
              <HashChip :value="bytesToHex(result.global_proof.sth.root_hash)" :head="8" :tail="8" />
            </KV>
          </template>
          <template v-if="result.anchor">
            <KV label="anchor_tree_size" :inline="true">
              <span class="num">{{ result.anchor.tree_size }}</span>
            </KV>
            <KV label="sink" :inline="true">{{ result.anchor.sink_name }}</KV>
            <KV label="anchor_id" :inline="true"><HashChip :value="result.anchor.anchor_id" :head="10" :tail="8" /></KV>
            <KV label="published_at" :inline="true">
              {{ formatTime(nanoToDate(result.anchor.published_at_unix_nano)) }}
            </KV>
          </template>
          <div v-else class="flex items-center gap-1.5 text-[11.5px] text-ink-500">
            <ShieldAlert :size="12" /> 未提供锚定
          </div>
        </div>
      </div>
    </Card>
  </div>
</template>
