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
import { CheckCircle2, CircleDashed, FileSearch, FolderOpen, ShieldAlert, ShieldCheck, XCircle } from 'lucide-vue-next'
import { bytesToHex, formatTime, humanSize, nanoToDate } from '@/lib/format'

const settings = useSettings()
const toasts = useToasts()
type Mode = 'local' | 'remote'
type Picker = 'file' | 'single' | 'proof' | 'global' | 'anchor' | 'clientDesc' | 'serverDesc' | 'registry' | 'clientRoot' | 'serverRoot'

const mode = ref<Mode>('local')
const filePath = ref('')
const skipAnchor = ref(false)
const singleProofPath = ref('')
const proofPath = ref('')
const globalProofPath = ref('')
const anchorPath = ref('')
const showSplitProofs = ref(false)
const recordID = ref('')
const serverURL = ref('')
const clientPub = ref('')
const serverPub = ref('')
const clientDescriptors = ref('')
const serverDescriptors = ref('')
const registryDescriptor = ref('')
const clientRoots = ref('')
const serverRoots = ref('')
const requireEvidence = ref(false)
const requireCertificateStatus = ref(false)
const showTrustOverrides = ref(false)
const running = ref(false)
const result = ref<VerifyResponse | null>(null)
const configuredTransport = computed(() => (settings.settings.server_transport || 'http').toUpperCase())

async function pick(target: Picker) {
  const titles: Record<Picker, string> = {
    file: '选择被存证文件',
    single: '选择 .sproof V2 文件',
    proof: '选择 .tdproof',
    global: '选择 .tdgproof',
    anchor: '选择 .tdanchor-result',
    clientDesc: '选择客户端 verifier descriptor',
    serverDesc: '选择服务器 verifier descriptor',
    registry: '选择 registry verifier descriptor',
    clientRoot: '选择客户端本地 CA 根',
    serverRoot: '选择服务器本地 CA 根',
  }
  const path = await api.chooseOpenPath(titles[target])
  if (!path) return
  if (target === 'file') filePath.value = path
  if (target === 'single') singleProofPath.value = path
  if (target === 'proof') proofPath.value = path
  if (target === 'global') globalProofPath.value = path
  if (target === 'anchor') anchorPath.value = path
  if (target === 'clientDesc') clientDescriptors.value = path
  if (target === 'serverDesc') serverDescriptors.value = path
  if (target === 'registry') registryDescriptor.value = path
  if (target === 'clientRoot') clientRoots.value = path
  if (target === 'serverRoot') serverRoots.value = path
}

const canVerify = computed(() =>
  !!filePath.value && (mode.value === 'local' ? !!singleProofPath.value || !!proofPath.value : !!recordID.value),
)

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
    client_verifier_descriptors: clientDescriptors.value || undefined,
    server_verifier_descriptors: serverDescriptors.value || undefined,
    registry_verifier_descriptor: registryDescriptor.value || undefined,
    client_certificate_roots: clientRoots.value || undefined,
    server_certificate_roots: serverRoots.value || undefined,
    require_identity_evidence: requireEvidence.value,
    require_certificate_status: requireCertificateStatus.value,
  }
  try {
    result.value = await api.verifyProof(req)
    if (result.value.valid) toasts.success(`验证通过 · ${result.value.crypto_suite} · ${result.value.level}`)
    else toasts.error('验证未通过', result.value.error)
  } catch (e: any) {
    toasts.error('验证出错', String(e?.message ?? e))
  } finally {
    running.value = false
  }
}

const stageLabels: Record<string, string> = {
  sproof_container: 'V2 .sproof 容器',
  identity_evidence: '身份、registry 与证书证据',
  proof_bundle: 'ProofBundle 结构',
  content: '内容哈希',
  client_claim: '客户端签名',
  bundle_bindings: '证据字段绑定',
  accepted_receipt: 'AcceptedReceipt',
  committed_receipt: 'CommittedReceipt',
  batch_merkle: 'Batch Merkle path',
  global_log: 'Global Log inclusion',
  anchor: '外部锚定',
}

function stageClass(status: string) {
  if (status === 'passed') return 'bg-success text-white'
  if (status === 'failed') return 'bg-danger text-white'
  if (status === 'skipped') return 'bg-warn/20 text-warn'
  return 'bg-ink-100 dark:bg-ink-800 text-ink-400'
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1100px] mx-auto">
    <Card>
      <template #title>
        <div class="flex items-center gap-2">
          <ShieldCheck :size="16" class="text-accent" />
          <h3 class="text-[14px] font-semibold text-ink-800 dark:text-ink-100">断网可复算验证</h3>
        </div>
      </template>
      <template #actions>
        <div class="inline-flex items-center gap-1 p-1 rounded-lg hairline border bg-ink-800/50">
          <button
            v-for="tab in [{ value: 'local', label: '本地 .sproof' }, { value: 'remote', label: '先下载再验证' }]"
            :key="tab.value"
            class="px-3 h-7 rounded-md text-[12px]"
            :class="mode === tab.value ? 'bg-ink-700 text-ink-100' : 'text-ink-500'"
            @click="mode = tab.value as Mode"
          >{{ tab.label }}</button>
        </div>
      </template>

      <p class="text-[12.5px] text-ink-500 leading-relaxed mb-4">
        <template v-if="mode === 'local'">
          内容、签名、Merkle path、Global Log、锚定以及身份生命周期全部在本机复算；不会访问服务器、DNS、CA 或 signer provider。
        </template>
        <template v-else>
          仅通过 {{ configuredTransport }} 下载一次完整 .sproof，随后进入同一离线验证器。远程返回的证书仍然只是证据。
        </template>
      </p>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
        <Field label="被存证文件"><div class="flex gap-2"><Input v-model="filePath" /><Button size="sm" variant="subtle" @click="pick('file')"><FolderOpen :size="13" /></Button></div></Field>
        <template v-if="mode === 'local'">
          <Field label=".sproof V2（推荐）" hint="包含可携带的完整公开证据">
            <div class="flex gap-2"><Input v-model="singleProofPath" /><Button size="sm" variant="subtle" @click="pick('single')"><FolderOpen :size="13" /></Button></div>
          </Field>
          <div class="md:col-span-2">
            <button class="w-full rounded-xl border border-white/10 px-4 py-3 text-left text-[12px] text-ink-400" @click="showSplitProofs = !showSplitProofs">
              {{ showSplitProofs ? '收起' : '展开' }}底层分文件输入（.tdproof / .tdgproof / .tdanchor-result）
            </button>
          </div>
          <template v-if="showSplitProofs">
            <Field label=".tdproof"><div class="flex gap-2"><Input v-model="proofPath" /><Button size="sm" variant="subtle" @click="pick('proof')"><FolderOpen :size="13" /></Button></div></Field>
            <Field label=".tdgproof"><div class="flex gap-2"><Input v-model="globalProofPath" /><Button size="sm" variant="subtle" @click="pick('global')"><FolderOpen :size="13" /></Button></div></Field>
            <Field label=".tdanchor-result"><div class="flex gap-2"><Input v-model="anchorPath" /><Button size="sm" variant="subtle" @click="pick('anchor')"><FolderOpen :size="13" /></Button></div></Field>
          </template>
        </template>
        <template v-else>
          <Field label="record_id"><Input v-model="recordID" :mono="true" /></Field>
          <Field label="服务器地址（可选）"><Input v-model="serverURL" :placeholder="settings.settings.server_url" /></Field>
        </template>
      </div>

      <button class="mt-4 text-[12px] text-accent" @click="showTrustOverrides = !showTrustOverrides">
        {{ showTrustOverrides ? '收起' : '展开' }}本次验证的本地信任输入
      </button>
      <div v-if="showTrustOverrides" class="mt-3 rounded-xl border border-white/10 bg-black/15 p-4 space-y-3">
        <p class="text-[11.5px] text-warn">
          留空使用 Settings 中的 verifier-local trust。下列路径只从本机读取；证据文件自身携带的证书不会填充这些字段。
        </p>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <Field label="客户端 verifier descriptors"><div class="flex gap-2"><Input v-model="clientDescriptors" multiline :rows="2" /><Button size="sm" variant="subtle" @click="pick('clientDesc')"><FolderOpen :size="13" /></Button></div></Field>
          <Field label="服务器 verifier descriptors"><div class="flex gap-2"><Input v-model="serverDescriptors" multiline :rows="2" /><Button size="sm" variant="subtle" @click="pick('serverDesc')"><FolderOpen :size="13" /></Button></div></Field>
          <Field label="Registry verifier descriptor"><div class="flex gap-2"><Input v-model="registryDescriptor" /><Button size="sm" variant="subtle" @click="pick('registry')"><FolderOpen :size="13" /></Button></div></Field>
          <Field label="客户端 CA 根"><div class="flex gap-2"><Input v-model="clientRoots" multiline :rows="2" /><Button size="sm" variant="subtle" @click="pick('clientRoot')"><FolderOpen :size="13" /></Button></div></Field>
          <Field label="服务器 CA 根"><div class="flex gap-2"><Input v-model="serverRoots" multiline :rows="2" /><Button size="sm" variant="subtle" @click="pick('serverRoot')"><FolderOpen :size="13" /></Button></div></Field>
          <Field label="原始客户端公钥（单钥本地信任）"><Input v-model="clientPub" :mono="true" /></Field>
          <Field label="原始服务器公钥（单钥本地信任）"><Input v-model="serverPub" :mono="true" /></Field>
        </div>
        <label class="flex items-center gap-2 text-[12px]"><input v-model="requireEvidence" type="checkbox" class="accent-accent" />要求身份 lifecycle evidence</label>
        <label class="flex items-center gap-2 text-[12px]"><input v-model="requireCertificateStatus" type="checkbox" class="accent-accent" />要求证书链与 CRL 状态证据</label>
      </div>

      <div class="mt-4 flex items-center justify-between">
        <label class="inline-flex items-center gap-2 text-[12.5px] text-ink-300">
          <input v-model="skipAnchor" type="checkbox" class="accent-accent" />跳过外部锚定阶段
        </label>
        <Button :disabled="!canVerify" :loading="running" @click="verify"><FileSearch :size="14" /> 开始验证</Button>
      </div>
    </Card>

    <Card v-if="result" :title="result.valid ? '验证通过' : '验证未通过'" :subtitle="result.error">
      <template #actions>
        <span class="font-mono text-[11px] text-accent">{{ result.crypto_suite }} · {{ result.hash_alg }}</span>
        <LevelBadge v-if="result.level" :level="result.level" />
      </template>

      <div class="rounded-xl border border-white/10 bg-black/15 p-3 mb-4">
        <p class="text-[12px] text-ink-300">{{ result.trust_notice }}</p>
        <div class="mt-2 flex flex-wrap gap-3 text-[11.5px] text-ink-500">
          <span>证据证书 {{ result.evidence_certificate_count }}</span>
          <span>本地信任根 {{ result.local_trust_root_count }}</span>
          <span>网络访问 {{ result.external_network_access ? '发生' : '0' }}</span>
          <span>Provider 访问 {{ result.external_provider_access ? '发生' : '0' }}</span>
        </div>
      </div>

      <ol class="grid grid-cols-1 md:grid-cols-2 gap-2">
        <li v-for="stage in result.stages" :key="stage.name" class="rounded-xl border border-white/10 p-3 flex gap-3">
          <span class="w-6 h-6 rounded-full flex items-center justify-center shrink-0" :class="stageClass(stage.status)">
            <CheckCircle2 v-if="stage.status === 'passed'" :size="13" />
            <XCircle v-else-if="stage.status === 'failed'" :size="13" />
            <CircleDashed v-else :size="13" />
          </span>
          <div>
            <div class="text-[12.5px] text-ink-100">{{ stageLabels[stage.name] || stage.name }}</div>
            <div class="font-mono text-[10.5px] uppercase text-ink-500">{{ stage.status }}</div>
            <div v-if="stage.error" class="mt-1 text-[11px] text-danger">{{ stage.error }}</div>
          </div>
        </li>
      </ol>

      <div class="mt-4 grid grid-cols-1 md:grid-cols-2 gap-3">
        <div class="rounded-xl border border-white/10 p-3 space-y-2">
          <h4 class="text-[12px] font-semibold">身份验证报告</h4>
          <KV label="evidence" :inline="true">{{ result.identity.evidence_count }}</KV>
          <KV label="public key bindings" :inline="true">{{ result.identity.public_key_bindings_verified }}</KV>
          <KV label="lifecycle bindings" :inline="true">{{ result.identity.lifecycle_bindings_verified }}</KV>
          <KV label="certificate chains" :inline="true">{{ result.identity.certificate_chains_verified }}</KV>
          <KV label="certificate statuses" :inline="true">{{ result.identity.certificate_statuses_verified }}</KV>
        </div>
        <div v-if="result.bundle" class="rounded-xl border border-white/10 p-3 space-y-2">
          <h4 class="text-[12px] font-semibold">Claim</h4>
          <KV label="record_id" :inline="true"><HashChip :value="result.record_id" :head="10" :tail="8" /></KV>
          <KV label="key_id" :inline="true"><span class="font-mono text-[11px]">{{ result.bundle.signed_claim.claim.key_id }}</span></KV>
          <KV :label="result.hash_alg" :inline="true"><HashChip :value="bytesToHex(result.bundle.signed_claim.claim.content.content_hash)" :head="8" :tail="8" /></KV>
          <KV label="content" :inline="true">{{ humanSize(result.content_bytes) }} · {{ result.bundle.signed_claim.claim.content.media_type }}</KV>
          <template v-if="result.anchor">
            <KV label="anchor" :inline="true">{{ result.anchor.sink_name }} · {{ result.anchor.evidence_stage || 'published' }}</KV>
            <KV label="published_at" :inline="true">{{ formatTime(nanoToDate(result.anchor.published_at_unix_nano)) }}</KV>
          </template>
          <div v-else class="text-[11.5px] text-ink-500 flex items-center gap-1"><ShieldAlert :size="12" />未携带锚定</div>
        </div>
      </div>
    </Card>
  </div>
</template>
