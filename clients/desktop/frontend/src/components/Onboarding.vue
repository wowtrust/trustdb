<script setup lang="ts">
import { computed, ref } from 'vue'
import { api } from '@/lib/api'
import { useSettings } from '@/stores/settings'
import { useIdentity } from '@/stores/identity'
import { useToasts } from '@/stores/toasts'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import HashChip from '@/components/HashChip.vue'
import LanguageSwitcher from '@/components/LanguageSwitcher.vue'
import { t } from '@/i18n'
import { copyToClipboard } from '@/lib/format'
import {
  Sparkles,
  Server,
  KeyRound,
  CheckCircle2,
  ArrowRight,
  ArrowLeft,
  Copy,
  Zap,
  X,
  CircleCheck,
} from 'lucide-vue-next'

const emit = defineEmits<{ (e: 'close'): void }>()

const settings = useSettings()
const identity = useIdentity()
const toasts = useToasts()

// Four-step flow: welcome → server → identity → register/finish.
// Step numbers are 1-based so the UI "第 N / 4 步" reads naturally.
type StepKey = 'welcome' | 'server' | 'identity' | 'register'
const steps: { key: StepKey; title: string; subtitle: string }[] = [
  { key: 'welcome',  title: '欢迎使用 TrustDB 存证', subtitle: '三分钟完成首次配置，立即可签、可存、可验' },
  { key: 'server',   title: '连接到 TrustDB 服务',   subtitle: '填入服务地址并粘贴它的公钥，用来校验签名' },
  { key: 'identity', title: '生成你的签名身份',       subtitle: '一对 Ed25519 密钥对；私钥只会保存在本机' },
  { key: 'register', title: '让服务器信任这把公钥',   subtitle: '把下面的命令贴到服务器上执行一次即可' },
]
const stepIdx = ref(0)
const current = computed(() => steps[stepIdx.value])
const progress = computed(() => ((stepIdx.value + 1) / steps.length) * 100)

// --- Step 2: server config ---------------------------------------
const serverTransport = ref(settings.settings.server_transport || 'http')
const serverUrl       = ref(settings.settings.server_url || 'http://127.0.0.1:8080')
const serverPubKey    = ref(settings.settings.server_public_key_b64 || '')
const testingServer   = ref(false)
const serverChecked   = ref<null | { ok: boolean; message: string }>(null)

const TRANSPORTS = [
  { v: 'http', label: 'HTTP', desc: '默认 REST 接入' },
  { v: 'grpc', label: 'gRPC', desc: 'SDK 直连 RPC' },
]
const serverEndpointHint = computed(() =>
  serverTransport.value === 'grpc'
    ? '例如 127.0.0.1:9090；误填 http://host:port 也会自动转成 host:port'
    : '例如 http://127.0.0.1:8080；也可以填远端 HTTPS',
)
const serverEndpointPlaceholder = computed(() =>
  serverTransport.value === 'grpc' ? '127.0.0.1:9090' : 'http://127.0.0.1:8080',
)

async function testServer() {
  testingServer.value = true
  serverChecked.value = null
  try {
    // Persist first so api.serverHealth (which reads settings from
    // the Go store) sees the user's transport/endpoint instead of
    // whatever was on disk before the wizard opened.
    await settings.save({
      server_transport: serverTransport.value,
      server_url: serverUrl.value.trim(),
      server_public_key_b64: serverPubKey.value.trim(),
    })
    const h = await api.serverHealth()
    if (h?.ok) {
      serverChecked.value = { ok: true, message: `${(h.transport || serverTransport.value).toUpperCase()} 服务正常 · ${h.rtt_millis ?? '?'}ms` }
    } else {
      serverChecked.value = { ok: false, message: h?.error || '服务未就绪' }
    }
  } catch (e: any) {
    serverChecked.value = { ok: false, message: String(e?.message ?? e) }
  } finally {
    testingServer.value = false
  }
}

// --- Step 3: identity --------------------------------------------
const tenant    = ref('default')
const clientID  = ref('desktop-1')
const keyID     = ref('ed25519-1')
const generating = ref(false)

const idState = computed(() => identity.identity)

async function generateIdentity() {
  generating.value = true
  try {
    await identity.generate(tenant.value.trim(), clientID.value.trim(), keyID.value.trim())
    toasts.success('身份已生成', '私钥只存本机，不会离开你的电脑')
  } catch (e: any) {
    toasts.error('生成失败', String(e?.message ?? e))
  } finally {
    generating.value = false
  }
}

// --- Step 4: registration command ---------------------------------
const registerCmd = computed(() => {
  // The command the operator needs to run on the *server* host. We
  // intentionally keep it copy-paste-friendly: a real, runnable
  // trustdb invocation with the client's public key inlined, plus a
  // sensible default registry path that matches the server's
  // built-in config.
  if (!idState.value) return ''
  const tenant   = idState.value.tenant_id   || 'default'
  const clientID = idState.value.client_id   || 'desktop-1'
  const keyID    = idState.value.key_id      || 'ed25519-1'
  const pub      = idState.value.public_key_b64
  return [
    'trustdb key-register \\',
    `  --registry .trustdb/keys.tdkeys \\`,
    `  --tenant ${shellQuote(tenant)} \\`,
    `  --client-id ${shellQuote(clientID)} \\`,
    `  --key-id ${shellQuote(keyID)} \\`,
    `  --public-key ${shellQuote(pub)}`,
  ].join('\n')
})

function shellQuote(s: string): string {
  // POSIX single quotes make backslashes, substitutions, and newlines
  // literal. Embedded single quotes are represented by ending the quote,
  // emitting one quoted single quote, and starting it again.
  return /^[A-Za-z0-9._/\-]+$/.test(s) ? s : `'${s.replaceAll("'", `'"'"'`)}'`
}

async function copyCmd() {
  await copyToClipboard(registerCmd.value)
  toasts.success('已复制命令', '到服务器上粘贴并执行即可完成注册')
}

async function copyPubKey() {
  if (!idState.value) return
  await copyToClipboard(idState.value.public_key_b64)
  toasts.success('公钥已复制')
}

// --- Navigation ---------------------------------------------------
const canGoNext = computed(() => {
  switch (current.value.key) {
    case 'welcome':  return true
    case 'server':   return !!serverUrl.value.trim()
    case 'identity': return !!idState.value
    case 'register': return !!idState.value
  }
})

function next() {
  if (!canGoNext.value) return
  if (stepIdx.value < steps.length - 1) stepIdx.value += 1
  else finish()
}
function prev() {
  if (stepIdx.value > 0) stepIdx.value -= 1
}
function finish() {
  // Persist the settings from step 2 one more time in case the user
  // edited them after the connection test succeeded, then remember
  // that the wizard has been seen so it doesn't reopen next launch.
  settings.save({
    server_transport: serverTransport.value,
    server_url: serverUrl.value.trim(),
    server_public_key_b64: serverPubKey.value.trim(),
  })
  try { localStorage.setItem('trustdb.onboarded', '1') } catch { /* ignore */ }
  emit('close')
}
function skip() {
  try { localStorage.setItem('trustdb.onboarded', '1') } catch { /* ignore */ }
  emit('close')
}
</script>

<template>
  <Teleport to="body">
    <div class="fixed inset-0 z-[60] flex items-center justify-center">
      <div class="absolute inset-0 bg-black/70 backdrop-blur-[10px]"></div>
      <div class="absolute inset-0 opacity-60 pointer-events-none bg-[radial-gradient(circle_at_20%_0%,rgba(0,255,34,0.22),transparent_32%),radial-gradient(circle_at_90%_70%,rgba(255,77,0,0.12),transparent_28%)]"></div>

      <div
        class="relative w-[min(760px,92vw)] max-h-[92vh] overflow-hidden rounded-[28px] glass shadow-soft-lg
               hairline animate-[fade_0.18s_ease-out] flex flex-col loki-ring"
        role="dialog"
        aria-modal="true"
      >
        <div class="h-[4px] bg-white/5">
          <div
            class="h-full bg-accent transition-[width] duration-300 ease-ios rounded-r-full shadow-[0_0_22px_rgba(0,255,34,0.78)]"
            :style="{ width: progress + '%' }"
          ></div>
        </div>

        <div class="px-8 pt-7 pb-2 flex items-start gap-4">
          <div class="w-12 h-12 rounded-[18px] bg-accent text-[#031004] flex items-center justify-center shadow-acid">
            <Sparkles v-if="current.key === 'welcome'"  :size="18" />
            <Server   v-else-if="current.key === 'server'"   :size="18" />
            <KeyRound v-else-if="current.key === 'identity'" :size="18" />
            <Zap      v-else :size="18" />
          </div>
          <div class="flex-1 min-w-0">
            <div class="kicker text-[10px] font-bold">
              {{ t('第 {current} / {total} 步', { current: stepIdx + 1, total: steps.length }) }}
            </div>
            <h2 class="display-title mt-2 text-[34px] font-black text-ink-50">
              {{ current.title }}
            </h2>
            <p class="mt-2 text-[13px] text-ink-400">{{ current.subtitle }}</p>
          </div>
          <div class="flex items-center gap-2 no-drag">
            <LanguageSwitcher />
            <button
              class="text-ink-500 hover:text-accent transition p-1 -mr-1"
              title="跳过向导"
              @click="skip"
            >
              <X :size="16" />
            </button>
          </div>
        </div>

        <div class="px-8 py-6 overflow-y-auto min-h-0">
          <!-- 1. Welcome -->
          <div v-if="current.key === 'welcome'" class="space-y-4">
            <p class="text-[13px] text-ink-300 leading-relaxed">
              TrustDB 是一套面向可审计存证的客户端 / 服务器系统，内核只有三件事：
              <b class="font-semibold text-ink-50">签署、批处理、出证</b>。
              这个向导会在几分钟内带你走完必要的配置，之后你就可以拖拽任意文件进来完成真实的存证。
            </p>
            <div class="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <div class="surface-tile rounded-[18px] p-4">
                <Server :size="14" class="text-accent" />
                <div class="mt-2 font-display text-[15px] font-bold uppercase text-ink-50">连接服务</div>
                <div class="mt-0.5 text-[11.5px] text-ink-400">配置服务地址与公钥</div>
              </div>
              <div class="surface-tile rounded-[18px] p-4">
                <KeyRound :size="14" class="text-accent" />
                <div class="mt-2 font-display text-[15px] font-bold uppercase text-ink-50">生成身份</div>
                <div class="mt-0.5 text-[11.5px] text-ink-400">Ed25519 密钥，仅存本机</div>
              </div>
              <div class="surface-tile rounded-[18px] p-4">
                <Zap :size="14" class="text-accent" />
                <div class="mt-2 font-display text-[15px] font-bold uppercase text-ink-50">注册公钥</div>
                <div class="mt-0.5 text-[11.5px] text-ink-400">一行命令让服务器信任</div>
              </div>
            </div>
            <p class="text-[11.5px] text-ink-400">
              已经配置过？可以随时点击右上角「跳过向导」。
            </p>
          </div>

          <!-- 2. Server -->
          <div v-else-if="current.key === 'server'" class="space-y-3">
            <Field label="传输协议" hint="HTTP 兼容现有服务；gRPC 用于连接已开启 --grpc-listen 的服务端">
              <div class="grid grid-cols-2 gap-2">
                <button
                  v-for="t in TRANSPORTS"
                  :key="t.v"
                  type="button"
                  class="rounded-[18px] border px-4 py-3 text-left transition-all duration-150"
                  :class="serverTransport === t.v
                    ? 'border-accent bg-accent/15 text-ink-50 shadow-[0_0_22px_rgba(0,255,34,0.16)]'
                    : 'border-white/10 bg-black/20 text-ink-400 hover:border-white/20 hover:text-ink-100'"
                  @click="serverTransport = t.v"
                >
                  <div class="font-display text-[13px] font-black tracking-[0.12em]">{{ t.label }}</div>
                  <div class="mt-1 text-[11.5px] opacity-75">{{ t.desc }}</div>
                </button>
              </div>
            </Field>
            <Field :label="serverTransport === 'grpc' ? 'gRPC Target' : '服务地址'" :hint="serverEndpointHint">
              <Input v-model="serverUrl" :placeholder="serverEndpointPlaceholder" />
            </Field>
            <Field label="服务端公钥（base64）" hint="从 server.pub 复制内容，留空也可以先跳过">
              <Input v-model="serverPubKey" placeholder="Zo46rzMjDyCXRa5-4bSqASte5A0JOLWOJ2mkeKzaCXw" />
            </Field>
            <div class="flex items-center gap-3">
              <Button variant="subtle" :loading="testingServer" @click="testServer">测试连接</Button>
              <div v-if="serverChecked" class="flex items-center gap-1.5 text-[12px]"
                   :class="serverChecked.ok ? 'text-success' : 'text-danger'">
                <CircleCheck v-if="serverChecked.ok" :size="14" />
                <component v-else :is="X" :size="14" />
                <span>{{ serverChecked.message }}</span>
              </div>
              <div v-else class="text-[11.5px] text-ink-400">连不上也可以继续，稍后在「设置」里改。</div>
            </div>
          </div>

          <!-- 3. Identity -->
          <div v-else-if="current.key === 'identity'" class="space-y-3">
            <div v-if="!idState" class="space-y-3">
              <div class="grid grid-cols-3 gap-2.5">
                <Field label="tenant">
                  <Input v-model="tenant" placeholder="default" />
                </Field>
                <Field label="client_id">
                  <Input v-model="clientID" placeholder="desktop-1" />
                </Field>
                <Field label="key_id">
                  <Input v-model="keyID" placeholder="ed25519-1" />
                </Field>
              </div>
              <p class="text-[11.5px] text-ink-400 leading-relaxed">
                TrustDB 用 <b>(tenant, client_id, key_id)</b> 三元组唯一标识签名者。
                如果只是试用，保持默认即可；生产环境里建议用有业务含义的名字，方便审计时辨认。
              </p>
              <Button :loading="generating" @click="generateIdentity">
                <KeyRound :size="14" /> 生成 Ed25519 密钥
              </Button>
            </div>
            <div v-else class="surface-tile rounded-[18px] p-4 space-y-2.5">
              <div class="flex items-center gap-2">
                <CheckCircle2 :size="16" class="text-success" />
                <div class="font-display text-[15px] font-bold uppercase text-ink-50">身份已生成</div>
                <div class="text-[11px] text-ink-400 ml-auto">
                  {{ idState.tenant_id }} / {{ idState.client_id }} / {{ idState.key_id }}
                </div>
              </div>
              <div class="flex items-center gap-1.5">
                <span class="kicker text-[10px] font-bold">公钥</span>
                <HashChip :value="idState.public_key_b64" :head="8" :tail="8" />
                <button class="text-ink-400 hover:text-accent transition" title="复制公钥" @click="copyPubKey">
                  <Copy :size="13" />
                </button>
              </div>
              <p class="text-[11.5px] text-ink-400">
                私钥保留在 <code class="text-ink-200">%APPDATA%/TrustDB-Desktop/config.json</code>
                ，永不外传。
              </p>
            </div>
          </div>

          <!-- 4. Register command -->
          <div v-else-if="current.key === 'register'" class="space-y-3">
            <p class="text-[12.5px] text-ink-300 leading-relaxed">
              服务器需要把你的公钥加入它的 key registry 才会接受你签的 claim。
              把下面这条命令<strong class="text-ink-50">复制到服务器</strong>执行一次即可，
              之后就可以关闭这个向导开始存证了。
            </p>
            <div class="rounded-[18px] border border-accent/20 bg-black/70 text-ink-100 text-[11.5px] font-mono
                        px-4 py-3 whitespace-pre leading-relaxed overflow-x-auto">{{ registerCmd }}</div>
            <div class="flex items-center gap-2.5">
              <Button variant="subtle" @click="copyCmd">
                <Copy :size="13" /> 复制命令
              </Button>
              <span class="text-[11.5px] text-ink-400">
                或者把公钥贴给管理员由对方完成 —
                <button class="underline decoration-dotted hover:text-accent" @click="copyPubKey">只复制公钥</button>
              </span>
            </div>
            <div class="mt-2 rounded-[18px] border border-accent/20 bg-accent/10 px-4 py-3 text-[11.5px] text-ink-300 leading-relaxed">
              <div class="flex items-center gap-1.5 text-accent font-medium mb-1">
                <Sparkles :size="12" /> 小贴士
              </div>
              如果你用的是单机开发模式、直接在服务器启动时传 <code>--client-public-key</code>，也可以完全跳过这一步 —
              向导只是帮你生成了正确的注册命令，并不强制必须用 registry。
            </div>
          </div>
        </div>

        <div class="px-8 py-4 border-t hairline flex items-center gap-2 bg-black/20">
          <Button v-if="stepIdx > 0" variant="ghost" @click="prev">
            <ArrowLeft :size="13" /> 上一步
          </Button>
          <div class="flex-1"></div>
          <Button variant="ghost" @click="skip">跳过向导</Button>
          <Button :disabled="!canGoNext" @click="next">
            <template v-if="stepIdx === steps.length - 1">
              <CheckCircle2 :size="14" /> 完成
            </template>
            <template v-else>
              下一步 <ArrowRight :size="13" />
            </template>
          </Button>
        </div>
      </div>
    </div>
  </Teleport>
</template>

<style scoped>
@keyframes fade {
  from { opacity: 0; transform: translateY(6px) scale(0.985); }
  to   { opacity: 1; transform: translateY(0)   scale(1); }
}
</style>
