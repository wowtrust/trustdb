<script setup lang="ts">
import { computed, reactive, ref, watch } from 'vue'
import { useSettings } from '@/stores/settings'
import { useToasts } from '@/stores/toasts'
import { api, HealthStatus } from '@/lib/api'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import StatusDot from '@/components/StatusDot.vue'
import { Save, RotateCcw, PlugZap, Sparkles, FolderOpen } from 'lucide-vue-next'

const settings = useSettings()
const toasts = useToasts()

// Edit a detached copy so cancel/reset is trivial.
const form = reactive({ ...settings.settings })
watch(
  () => settings.settings,
  (v) => Object.assign(form, v),
  { deep: true },
)

const dirty = computed(() => {
  return (
    form.server_url !== settings.settings.server_url ||
    form.server_transport !== settings.settings.server_transport ||
    form.server_ca_file !== settings.settings.server_ca_file ||
    form.server_name !== settings.settings.server_name ||
    form.server_ca_pins_sha256 !== settings.settings.server_ca_pins_sha256 ||
    form.client_tls_cert_file !== settings.settings.client_tls_cert_file ||
    form.client_tls_key_file !== settings.settings.client_tls_key_file ||
    form.tls_reload_interval !== settings.settings.tls_reload_interval ||
    form.server_public_key_b64 !== settings.settings.server_public_key_b64 ||
    form.anchor_plugin_command !== settings.settings.anchor_plugin_command ||
    form.anchor_plugin_args_text !== settings.settings.anchor_plugin_args_text ||
    form.anchor_plugin_start_timeout !== settings.settings.anchor_plugin_start_timeout ||
    form.anchor_plugin_rpc_timeout !== settings.settings.anchor_plugin_rpc_timeout ||
    form.default_media_type !== settings.settings.default_media_type ||
    form.default_event_type !== settings.settings.default_event_type
  )
})

const saving = ref(false)
async function save() {
  saving.value = true
  try {
    await settings.save({ ...form })
    toasts.success('设置已保存')
  } catch (e: any) {
    toasts.error('保存失败', String(e?.message ?? e))
  } finally {
    saving.value = false
  }
}

function revert() {
  Object.assign(form, settings.settings)
}

// ----- Ping test (uses the NEW url from the form, not the saved one) -----
const pingLoading = ref(false)
const pingResult = ref<HealthStatus | null>(null)
async function ping() {
  pingLoading.value = true
  pingResult.value = null
  try {
    // Temporarily persist so the backend's server client picks up the
    // new transport and endpoint. We restore afterwards if the user didn't click "Save".
    const previous = { ...settings.settings }
    await settings.save({ ...form })
    try {
      pingResult.value = await api.serverHealth()
    } finally {
      if (!dirty.value) return
      // Restore previous so the ping doesn't silently save.
      await settings.save(previous)
      Object.assign(form, settings.settings)
    }
  } catch (e: any) {
    toasts.error('连通性检查失败', String(e?.message ?? e))
  } finally {
    pingLoading.value = false
  }
}

const TRANSPORTS = [
  { v: 'http', label: 'HTTP', desc: '默认 REST 接入' },
  { v: 'grpc', label: 'gRPC', desc: 'SDK 直连 RPC' },
]
const endpointHint = computed(() =>
  form.server_transport === 'grpc'
    ? '例：127.0.0.1:9090；如果误填 http://host:port，客户端会自动归一化为 host:port'
    : '例：http://localhost:8081；结尾的 / 可省略',
)
const endpointPlaceholder = computed(() =>
  form.server_transport === 'grpc' ? '127.0.0.1:9090' : 'http://host:port',
)

function reopenOnboarding() {
  // App.vue exposes this on window so we don't need a dedicated
  // event bus for a single call site. If the page got hot-reloaded
  // before App mounted we silently fall back to reload.
  const fn = (window as any).trustdbOpenOnboarding as (() => void) | undefined
  if (typeof fn === 'function') fn()
  else location.reload()
}

async function pickAnchorPlugin() {
  const path = await api.chooseOpenPath('选择 L5 锚定插件')
  if (path) form.anchor_plugin_command = path
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[900px] mx-auto">
    <Card title="服务器" subtitle="TrustDB 服务端的入口和信任锚">
      <div class="space-y-3">
        <Field label="传输协议" hint="HTTP 继续兼容现有服务；gRPC 适合配合 Go SDK / 内网服务使用">
          <div class="grid grid-cols-2 gap-2">
            <button
              v-for="t in TRANSPORTS"
              :key="t.v"
              type="button"
              class="rounded-[18px] border px-4 py-3 text-left transition-all duration-150"
              :class="form.server_transport === t.v
                ? 'border-accent bg-accent/15 text-ink-50 shadow-[0_0_22px_rgba(0,255,34,0.16)]'
                : 'border-white/10 bg-black/20 text-ink-400 hover:border-white/20 hover:text-ink-100'"
              @click="form.server_transport = t.v"
            >
              <div class="font-display text-[13px] font-black tracking-[0.12em]">{{ t.label }}</div>
              <div class="mt-1 text-[11.5px] opacity-75">{{ t.desc }}</div>
            </button>
          </div>
        </Field>
        <Field :label="form.server_transport === 'grpc' ? 'gRPC Target' : '服务器 URL'" :hint="endpointHint">
          <Input v-model="form.server_url" :placeholder="endpointPlaceholder" :mono="true" />
        </Field>
        <Field label="服务器公钥 (base64)" hint="用于验证 AcceptedReceipt / CommittedReceipt 的签名">
          <Input v-model="form.server_public_key_b64" placeholder="Ed25519 public key" :mono="true" multiline :rows="2" />
        </Field>

        <div class="rounded-[18px] border border-white/10 bg-black/15 p-4 space-y-3">
          <div>
            <div class="text-[12px] font-semibold text-ink-200">TLS / mTLS 传输信任</div>
            <div class="mt-1 text-[11.5px] text-ink-500">仅验证网络证书；与上方 proof 签名公钥相互独立。HTTPS 或远端 gRPC 默认校验系统 CA 和主机名。</div>
          </div>
          <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Field label="服务器 CA PEM" hint="留空使用系统 CA；填写后固定到该 CA 集合">
              <Input v-model="form.server_ca_file" placeholder="/etc/trustdb/tls/server-ca.crt" :mono="true" />
            </Field>
            <Field label="TLS server_name" hint="留空使用 URL / target 主机名">
              <Input v-model="form.server_name" placeholder="trustdb.internal" :mono="true" />
            </Field>
            <Field label="客户端证书" hint="mTLS 客户端证书 PEM">
              <Input v-model="form.client_tls_cert_file" placeholder="/path/client.crt" :mono="true" />
            </Field>
            <Field label="客户端私钥" hint="必须与客户端证书一起配置">
              <Input v-model="form.client_tls_key_file" placeholder="/path/client.key" :mono="true" />
            </Field>
            <Field label="CA SHA-256 pins" hint="每行或逗号分隔 CA DER 指纹">
              <Input v-model="form.server_ca_pins_sha256" placeholder="64 hex characters" :mono="true" multiline :rows="2" />
            </Field>
            <Field label="轮换检查间隔" hint="证书、CA 和撤销策略无中断重载">
              <Input v-model="form.tls_reload_interval" placeholder="1m" :mono="true" />
            </Field>
          </div>
        </div>

        <div class="flex items-center justify-between pt-1">
          <div v-if="pingResult" class="flex items-center gap-2 text-[12.5px]">
            <StatusDot :state="pingResult.ok ? 'ok' : 'bad'" />
            <span class="text-ink-700 dark:text-ink-200">
              {{ pingResult.ok ? `在线 · ${pingResult.rtt_millis}ms` : (pingResult.error || '离线') }}
            </span>
            <span class="text-ink-400">·</span>
            <span class="text-ink-500 font-mono uppercase">{{ pingResult.transport || form.server_transport || 'http' }}</span>
            <span v-if="pingResult.transport_security" class="text-ink-500 font-mono uppercase">· {{ pingResult.transport_security }} {{ pingResult.tls_version || '' }}</span>
            <span class="text-ink-400">·</span>
            <span class="text-ink-500 font-mono">{{ pingResult.server_url }}</span>
          </div>
          <div v-else class="text-[12px] text-ink-500">点击"测试连接"检查服务器可达性</div>

          <Button size="sm" variant="subtle" :loading="pingLoading" @click="ping">
            <PlugZap :size="13" /> 测试连接
          </Button>
        </div>
      </div>
    </Card>

    <Card title="L5 锚定插件" subtitle="验证服务端返回的自定义外部锚定 proof">
      <div class="space-y-3">
        <Field label="插件 executable" hint="仅自定义 sink 需要；file / noop / ots 继续使用内置验证器">
          <div class="flex gap-2">
            <Input v-model="form.anchor_plugin_command" placeholder="/path/to/trustdb-anchor-plugin" :mono="true" />
            <Button size="sm" variant="subtle" @click="pickAnchorPlugin">
              <FolderOpen :size="13" /> 选择
            </Button>
          </div>
        </Field>
        <Field label="插件参数" hint="每行一个参数；不要在这里填写密钥或 token">
          <Input
            v-model="form.anchor_plugin_args_text"
            placeholder="--network\nconsortium-a"
            :mono="true"
            multiline
            :rows="3"
          />
        </Field>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="启动超时" hint="启动、握手并连接 loopback gRPC 的最长时间">
            <Input v-model="form.anchor_plugin_start_timeout" placeholder="10s" :mono="true" />
          </Field>
          <Field label="RPC 超时" hint="Publish / Verify 单次调用的最长时间">
            <Input v-model="form.anchor_plugin_rpc_timeout" placeholder="30s" :mono="true" />
          </Field>
        </div>
        <p class="text-[12px] text-ink-500">
          自定义 L5 proof 会在验证时启动该子进程；插件缺失、sink 名称不匹配或 proof 被拒绝时均 fail closed。
        </p>
      </div>
    </Card>

    <Card title="提交默认值" subtitle="新建存证时的预填字段">
      <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <Field label="默认 media_type" hint="若单个文件能嗅探出具体类型，以嗅探结果为准">
          <Input v-model="form.default_media_type" placeholder="application/octet-stream" :mono="true" />
        </Field>
        <Field label="默认 event_type" hint="如 file.snapshot / log.append / tx.receipt">
          <Input v-model="form.default_event_type" placeholder="file.snapshot" :mono="true" />
        </Field>
      </div>
    </Card>

    <Card title="入门向导" subtitle="四步完成首次配置，可以随时重新打开">
      <div class="flex items-center justify-between">
        <p class="text-[12.5px] text-ink-500 max-w-[560px]">
          首次启动会自动弹出向导；如果当时跳过了，或者想在另一台服务器上重新走一遍，
          点这里可以再来一次。不会清空你现有的身份和设置。
        </p>
        <Button size="sm" variant="subtle" @click="reopenOnboarding">
          <Sparkles :size="13" /> 打开向导
        </Button>
      </div>
    </Card>

    <!-- Sticky action bar; becomes visible only when form is dirty -->
    <transition name="bar">
      <div
        v-if="dirty"
        class="sticky bottom-0 z-10 rounded-xl hairline border glass shadow-soft-md px-4 py-3 flex items-center justify-between"
      >
        <span class="text-[12.5px] text-ink-600 dark:text-ink-200">有未保存的改动</span>
        <div class="flex items-center gap-2">
          <Button variant="subtle" size="sm" @click="revert">
            <RotateCcw :size="13" /> 还原
          </Button>
          <Button size="sm" :loading="saving" @click="save">
            <Save :size="13" /> 保存
          </Button>
        </div>
      </div>
    </transition>
  </div>
</template>

<style scoped>
.bar-enter-active, .bar-leave-active { transition: transform .2s cubic-bezier(.25,.1,.25,1), opacity .2s; }
.bar-enter-from, .bar-leave-to { opacity: 0; transform: translateY(8px); }
</style>
