<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { OnFileDrop, EventsOn } from '@wails/runtime/runtime'
import { api, FileInfo, SubmitRequest, BatchItemResult } from '@/lib/api'
import { useIdentity } from '@/stores/identity'
import { useSettings } from '@/stores/settings'
import { useRecords } from '@/stores/records'
import { useToasts } from '@/stores/toasts'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import EmptyState from '@/components/EmptyState.vue'
import HashChip from '@/components/HashChip.vue'
import LevelBadge from '@/components/LevelBadge.vue'
import { UploadCloud, X, File as FileIcon, CheckCircle2, AlertCircle, Loader2 } from 'lucide-vue-next'
import { humanSize } from '@/lib/format'

type RowStatus = 'hashing' | 'ready' | 'error'

type Row = {
  path: string
  name: string
  size: number
  crypto_suite: string
  hash_alg: string
  content_hash_hex: string
  media_type: string
  status: RowStatus
  bytes_hashed: number
  bytes_total: number
  error?: string
  job_id?: string
  // Per-row submit metadata: defaults from settings but editable.
  mediaType?: string
  eventType?: string
  source?: string
}

// Payload shape matches Go's HashJobEvent (camelCase transformed to
// snake_case via the standard json tags). We avoid importing from
// @wails/go/models because that TS file does not surface this struct
// when it's only used as an event payload.
type HashEvent = {
  job_id: string
  index?: number
  path?: string
  name?: string
  bytes_hashed?: number
  bytes_total?: number
  total_files?: number
  total_bytes?: number
  info?: FileInfo
  infos?: FileInfo[]
  error?: string
}

const identity = useIdentity()
const settings = useSettings()
const records = useRecords()
const toasts = useToasts()

const rows = ref<Row[]>([])
const submitting = ref(false)
const results = ref<BatchItemResult[]>([])
const dragActive = ref(false)

const hashingCount = computed(() => rows.value.filter((r) => r.status === 'hashing').length)
const readyCount   = computed(() => rows.value.filter((r) => r.status === 'ready').length)

// Submit is blocked while any row is still hashing: we don't have a
// content hash to put into the claim yet, and a partial submit would
// leak a broken record into the history.
const canSubmit = computed(
  () => !!identity.identity?.unlocked && readyCount.value > 0 && hashingCount.value === 0 && !submitting.value,
)

// Track the unsubscribe functions Wails hands back so we can detach
// the listeners on unmount — otherwise the callbacks keep firing into
// a dead component if the user navigates away mid-hash.
const offFns: Array<() => void> = []

onMounted(() => {
  OnFileDrop((_x, _y, paths) => void onDrop(paths), true)
  offFns.push(EventsOn('hash:file-progress', handleProgress))
  offFns.push(EventsOn('hash:file-done',     handleFileDone))
  offFns.push(EventsOn('hash:error',         handleError))
  offFns.push(EventsOn('hash:cancelled',     handleCancelled))
  // hash:begin and hash:done are useful for bulk telemetry but we do
  // not need them for the MVP UI — the per-file events already cover
  // the progress bar and the "all ready" state.
})

onBeforeUnmount(() => {
  offFns.forEach((off) => off())
  offFns.length = 0
})

async function onDrop(paths: string[]) {
  dragActive.value = false
  if (!paths?.length) return
  await enqueue(paths)
}

async function pick() {
  const paths = await api.chooseFiles()
  if (paths?.length) await enqueue(paths)
}

async function enqueue(paths: string[]) {
  // De-dupe by path so dragging the same file twice doesn't spawn
  // parallel hash jobs. Content-hash dedupe happens server-side via
  // the idempotency_key — we don't need to second-guess it here.
  const known = new Set(rows.value.map((r) => r.path))
  const fresh = paths.filter((p) => p && !known.has(p))
  if (!fresh.length) return

  const defaultMedia = settings.settings.default_media_type || 'application/octet-stream'
  const defaultEvent = settings.settings.default_event_type || 'file.snapshot'
  const defaultSource = identity.identity?.client_id ?? ''
  for (const p of fresh) {
    rows.value.push({
      path: p,
      name: baseName(p),
      size: 0,
      crypto_suite: identity.identity?.crypto_suite || '',
      hash_alg: identity.identity?.crypto_suite === 'CN_SM_V1' ? 'SM3' : 'SHA-256',
      content_hash_hex: '',
      media_type: defaultMedia,
      status: 'hashing',
      bytes_hashed: 0,
      bytes_total: 0,
      mediaType: defaultMedia,
      eventType: defaultEvent,
      source: defaultSource,
    })
  }

  try {
    const jobID = await api.startHashing(fresh)
    for (const p of fresh) {
      const r = rows.value.find((x) => x.path === p)
      if (r) r.job_id = jobID
    }
  } catch (e: any) {
    // A failure here means something like a bad path or unreadable
    // file — mark every fresh row as errored so the UI is honest
    // about what happened instead of showing a forever-spinning bar.
    for (const p of fresh) {
      const r = rows.value.find((x) => x.path === p)
      if (r) {
        r.status = 'error'
        r.error = String(e?.message ?? e)
      }
    }
    toasts.error('无法开始哈希', String(e?.message ?? e))
  }
}

function handleProgress(e: HashEvent) {
  if (!e.path) return
  const r = rows.value.find((x) => x.path === e.path)
  if (!r) return
  r.bytes_hashed = e.bytes_hashed ?? 0
  if (e.bytes_total) {
    r.bytes_total = e.bytes_total
    if (!r.size) r.size = e.bytes_total
  }
}

function handleFileDone(e: HashEvent) {
  if (!e.path || !e.info) return
  const r = rows.value.find((x) => x.path === e.path)
  if (!r) return
  r.status = 'ready'
  r.content_hash_hex = e.info.content_hash_hex
  r.crypto_suite = e.info.crypto_suite
  r.hash_alg = e.info.hash_alg
  r.size = e.info.size
  r.media_type = e.info.media_type
  if (!r.mediaType) r.mediaType = e.info.media_type
  r.bytes_hashed = e.info.size
  r.bytes_total = e.info.size
}

function handleError(e: HashEvent) {
  const target =
    (e.path && rows.value.find((x) => x.path === e.path)) ||
    (e.job_id ? rows.value.find((x) => x.job_id === e.job_id && x.status === 'hashing') : undefined)
  if (!target) {
    toasts.error('哈希失败', e.error || '未知错误')
    return
  }
  target.status = 'error'
  target.error = e.error || '未知错误'
}

function handleCancelled(e: HashEvent) {
  const toRemove: number[] = []
  rows.value.forEach((r, i) => {
    if (r.status === 'hashing' && r.job_id === e.job_id) toRemove.push(i)
  })
  toRemove.reverse().forEach((i) => rows.value.splice(i, 1))
}

function remove(idx: number) {
  const r = rows.value[idx]
  if (r?.status === 'hashing' && r.job_id) {
    // Fire-and-forget: the backend will emit hash:cancelled which in
    // turn removes the remaining rows belonging to this job. The
    // splice below handles the "just this one" case for already-done
    // rows.
    api.cancelHashing(r.job_id).catch(() => {})
  }
  rows.value.splice(idx, 1)
}

function progressPct(r: Row): number {
  if (r.status !== 'hashing') return 100
  if (!r.bytes_total) return 2
  return Math.max(2, Math.min(100, Math.floor((r.bytes_hashed * 100) / r.bytes_total)))
}

function baseName(p: string): string {
  const m = /[^\\/]+$/.exec(p)
  return m ? m[0] : p
}

async function submit() {
  if (!identity.identity) {
    toasts.error('尚未创建身份', '请先到「身份密钥」创建或引用一个 V2 signer descriptor')
    return
  }
  if (!identity.identity.unlocked) {
    toasts.error('身份已锁定', '请先到「身份密钥」解锁签名能力')
    return
  }
  submitting.value = true
  results.value = []
  const reqs: SubmitRequest[] = rows.value
    .filter((r) => r.status === 'ready')
    .map((r) => ({
      path: r.path,
      media_type: r.mediaType,
      event_type: r.eventType,
      source: r.source,
    }))
  try {
    const res = await api.submitBatch(reqs)
    results.value = res
    const ok = res.filter((r) => r.success).length
    const failed = res.length - ok
    if (failed === 0) toasts.success(`已提交 ${ok} 份存证`)
    else toasts.error(`${failed} / ${res.length} 提交失败`, res.find((r) => !r.success)?.error)
    const failedPaths = new Set(res.filter((r) => !r.success).map((r) => r.path))
    rows.value = rows.value.filter((r) => failedPaths.has(r.path))
    await records.load()
  } catch (e: any) {
    toasts.error('提交失败', String(e?.message ?? e))
  } finally {
    submitting.value = false
  }
}

function onDragOver(e: DragEvent) {
  e.preventDefault()
  dragActive.value = true
}
function onDragLeave() { dragActive.value = false }
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1100px] mx-auto">
    <Card v-if="!identity.identity" title="需要身份才能提交">
      <EmptyState
        title="尚未配置签名身份"
        hint="TrustDB 需要一个 INTL_V1 或 CN_SM_V1 签名身份。请先到「身份密钥」创建加密软件身份或引用 provider。"
      >
        <router-link to="/keys">
          <Button>前往设置身份</Button>
        </router-link>
      </EmptyState>
    </Card>

    <Card v-else
      title="新建存证"
      :subtitle="`当前 ${identity.identity?.crypto_suite}；大文件流式计算 ${identity.identity?.crypto_suite === 'CN_SM_V1' ? 'SM3' : 'SHA-256'} 并显示进度。`"
    >
      <template #actions>
        <Button variant="subtle" @click="pick">选择文件</Button>
        <Button :disabled="!canSubmit" :loading="submitting" @click="submit">
          <UploadCloud :size="14" />
          提交 {{ readyCount ? `(${readyCount})` : '' }}
          <span v-if="hashingCount" class="ml-1 text-[11px] text-ink-400">· {{ hashingCount }} 计算中</span>
        </Button>
      </template>

      <div
        class="relative rounded-[26px] border-2 border-dashed transition-all duration-200 ease-ios overflow-hidden"
        :class="dragActive ? 'bg-accent/10 border-accent/70 shadow-acid' : 'command-panel border-white/10'"
        @dragover.prevent="onDragOver"
        @dragleave="onDragLeave"
        @drop.prevent="onDragLeave"
      >
        <div v-if="!rows.length" class="py-14 text-center">
          <div class="w-14 h-14 rounded-[20px] bg-accent text-[#031004] shadow-acid flex items-center justify-center mx-auto mb-4">
            <UploadCloud :size="22" />
          </div>
          <h3 class="display-title text-[42px] font-black text-ink-50">DROP TO ATTEST</h3>
          <p class="mt-2 text-[12px] text-ink-400">拖拽文件到此处，或者点击「选择文件」从本地挑选；支持任意类型，一次可以多选。</p>
        </div>

        <div v-else class="divide-y hairline">
          <div v-for="(r, i) in rows" :key="r.path" class="flex items-center gap-3 px-4 py-3">
            <div class="w-8 h-8 rounded-lg bg-ink-100 dark:bg-ink-800 flex items-center justify-center text-ink-500 shrink-0">
              <Loader2 v-if="r.status === 'hashing'" :size="14" class="animate-spin text-accent" />
              <AlertCircle v-else-if="r.status === 'error'" :size="14" class="text-danger" />
              <FileIcon v-else :size="14" />
            </div>
            <div class="min-w-0 flex-1">
              <div class="flex items-center gap-2">
                <span class="text-[13px] font-medium text-ink-800 dark:text-ink-100 truncate">{{ r.name }}</span>
                <span class="text-[11.5px] text-ink-500">{{ humanSize(r.size || r.bytes_total) }}</span>
              </div>

              <div v-if="r.status === 'hashing'" class="mt-1.5">
                <div class="h-1 rounded-full bg-ink-100 dark:bg-ink-800 overflow-hidden">
                  <div
                    class="h-full bg-accent rounded-full transition-all duration-150 ease-ios"
                    :style="{ width: progressPct(r) + '%' }"
                  ></div>
                </div>
                <div class="mt-1 text-[11px] text-ink-500 flex items-center gap-2">
                  <span>计算 {{ r.hash_alg }} ·</span>
                  <span class="num">{{ humanSize(r.bytes_hashed) }} / {{ humanSize(r.bytes_total || r.size) }}</span>
                  <span class="num">· {{ progressPct(r) }}%</span>
                </div>
              </div>

              <div v-else-if="r.status === 'error'" class="mt-1 text-[11.5px] text-danger truncate">
                {{ r.error }}
              </div>

              <div v-else class="mt-1 flex items-center gap-1.5">
                <HashChip :value="r.content_hash_hex" :label="r.hash_alg" :head="6" :tail="6" />
                <span class="text-[10px] font-mono text-accent">{{ r.crypto_suite }}</span>
                <span class="text-[11px] text-ink-500 truncate">{{ r.path }}</span>
              </div>
            </div>
            <button
              class="text-ink-400 hover:text-danger transition"
              :title="r.status === 'hashing' ? '取消哈希' : '从列表移除'"
              @click="remove(i)"
            >
              <X :size="14" />
            </button>
          </div>
        </div>
      </div>

      <!-- Per-row metadata controls; fold below the list so the
           drop zone stays uncluttered. Defaults come from settings. -->
      <div v-if="rows.length" class="mt-5 grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Field label="media_type（统一应用）" hint="空即按每文件嗅探结果">
          <Input v-model="rows[0].mediaType" placeholder="application/octet-stream" />
        </Field>
        <Field label="event_type">
          <Input v-model="rows[0].eventType" placeholder="file.snapshot" />
        </Field>
        <Field label="source">
          <Input v-model="rows[0].source" :placeholder="identity.identity?.client_id" />
        </Field>
      </div>
    </Card>

    <Card v-if="results.length" title="本次提交结果" subtitle="保持在此页以便复核">
      <ul class="divide-y hairline -my-1">
        <li v-for="(it, i) in results" :key="i" class="py-3 flex items-center gap-3">
          <component :is="it.success ? CheckCircle2 : AlertCircle" :size="16"
            :class="it.success ? 'text-success' : 'text-danger'" />
          <div class="min-w-0 flex-1">
            <p class="text-[13px] text-ink-800 dark:text-ink-100 truncate">{{ it.path }}</p>
            <p v-if="it.success" class="text-[11.5px] text-ink-500 flex items-center gap-2 mt-0.5">
              <LevelBadge :level="it.result?.record.proof_level" size="sm" />
              <HashChip :value="it.result?.record.record_id" :head="6" :tail="6" />
              <span v-if="it.result?.idempotent" class="text-warn">幂等命中</span>
              <span v-else-if="it.result?.batch_queued">已进入批处理</span>
            </p>
            <p v-else class="text-[12px] text-danger mt-0.5 truncate">{{ it.error }}</p>
          </div>
        </li>
      </ul>
    </Card>
  </div>
</template>
