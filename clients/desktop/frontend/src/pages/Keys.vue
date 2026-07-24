<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useIdentity } from '@/stores/identity'
import { useToasts } from '@/stores/toasts'
import { api } from '@/lib/api'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import HashChip from '@/components/HashChip.vue'
import KV from '@/components/KV.vue'
import EmptyState from '@/components/EmptyState.vue'
import {
  Download, FileKey2, FolderOpen, KeyRound, LockKeyhole, RotateCw, ShieldCheck, Trash2, UnlockKeyhole, Upload,
} from 'lucide-vue-next'
import { formatTime, nanoToDate } from '@/lib/format'

const identity = useIdentity()
const toasts = useToasts()
const hasIdentity = computed(() => !!identity.identity)
const suites = [
  { value: 'INTL_V1', label: 'INTL_V1 · Ed25519 / SHA-256' },
  { value: 'CN_SM_V1', label: 'CN_SM_V1 · SM2 / SM3' },
]

const newTenant = ref('default')
const newClient = ref('desktop-1')
const newKeyID = ref('intl-desktop-1')
const newSuite = ref('INTL_V1')
const newPassphrase = ref('')
const newPassphraseAgain = ref('')
const busyCreate = ref(false)
watch(newSuite, (suite) => {
  if (newKeyID.value === 'intl-desktop-1' || newKeyID.value === 'sm2-desktop-1') {
    newKeyID.value = suite === 'CN_SM_V1' ? 'sm2-desktop-1' : 'intl-desktop-1'
  }
})

function requireMatchingPassphrases(passphrase: string, confirmation: string): boolean {
  if (passphrase.length < 12) {
    toasts.error('口令过短', '加密口令至少 12 个字符')
    return false
  }
  if (passphrase !== confirmation) {
    toasts.error('口令不一致')
    return false
  }
  return true
}

async function create() {
  if (!newTenant.value || !newClient.value || !newKeyID.value) {
    toasts.error('缺少字段', 'tenant_id、client_id 和 key_id 都必须填写')
    return
  }
  if (!requireMatchingPassphrases(newPassphrase.value, newPassphraseAgain.value)) return
  busyCreate.value = true
  try {
    await identity.generate({
      tenant_id: newTenant.value,
      client_id: newClient.value,
      key_id: newKeyID.value,
      crypto_suite: newSuite.value,
      passphrase: newPassphrase.value,
    })
    toasts.success('加密身份已生成', `${newSuite.value} 私钥已写入 SM4 加密封装`)
  } catch (e: any) {
    toasts.error('生成失败', String(e?.message ?? e))
  } finally {
    newPassphrase.value = ''
    newPassphraseAgain.value = ''
    busyCreate.value = false
  }
}

const unlockPassphrase = ref('')
const busyUnlock = ref(false)
async function unlock() {
  busyUnlock.value = true
  try {
    await identity.unlock(unlockPassphrase.value)
    toasts.success('身份已解锁')
  } catch (e: any) {
    toasts.error('解锁失败', String(e?.message ?? e))
  } finally {
    unlockPassphrase.value = ''
    busyUnlock.value = false
  }
}

async function lock() {
  await identity.lock()
  toasts.success('身份已锁定')
}

async function exportVerifier() {
  const path = await api.chooseSavePath('导出 V2 verifier descriptor', `${identity.identity?.key_id || 'client'}.pub`)
  if (!path) return
  try {
    await api.exportVerifierDescriptor(path)
    toasts.success('公开 descriptor 已导出', '可交给服务端管理员登记到 V2 key registry')
  } catch (e: any) {
    toasts.error('导出失败', String(e?.message ?? e))
  }
}

const rotateKeyID = ref('')
const rotatePassphrase = ref('')
const rotatePassphraseAgain = ref('')
const busyRotate = ref(false)
async function rotate() {
  if (!rotateKeyID.value) {
    toasts.error('请填写新的 key_id')
    return
  }
  if (!requireMatchingPassphrases(rotatePassphrase.value, rotatePassphraseAgain.value)) return
  busyRotate.value = true
  try {
    await identity.rotate({ key_id: rotateKeyID.value, passphrase: rotatePassphrase.value })
    toasts.success('密钥已轮换', '请由管理员把新的公开描述符登记到 V2 key registry')
    rotateKeyID.value = ''
  } catch (e: any) {
    toasts.error('轮换失败', String(e?.message ?? e))
  } finally {
    rotatePassphrase.value = ''
    rotatePassphraseAgain.value = ''
    busyRotate.value = false
  }
}

const impTenant = ref('default')
const impClient = ref('desktop-1')
const impKeyID = ref('intl-import-1')
const impSuite = ref('INTL_V1')
const impPrivate = ref('')
const impPassphrase = ref('')
const impPassphraseAgain = ref('')
const busyImport = ref(false)
async function importKey() {
  if (!impTenant.value || !impClient.value || !impKeyID.value || !impPrivate.value) {
    toasts.error('缺少导入字段')
    return
  }
  if (!requireMatchingPassphrases(impPassphrase.value, impPassphraseAgain.value)) return
  busyImport.value = true
  try {
    await identity.importKey({
      tenant_id: impTenant.value,
      client_id: impClient.value,
      key_id: impKeyID.value,
      crypto_suite: impSuite.value,
      private_key_b64: impPrivate.value.trim(),
      passphrase: impPassphrase.value,
    })
    toasts.success('密钥已导入并加密')
  } catch (e: any) {
    toasts.error('导入失败', String(e?.message ?? e))
  } finally {
    impPrivate.value = ''
    impPassphrase.value = ''
    impPassphraseAgain.value = ''
    busyImport.value = false
  }
}

const refTenant = ref('default')
const refClient = ref('desktop-1')
const descriptorPath = ref('')
const pluginCommand = ref('')
const pluginEnv = ref('')
const referencePassphrase = ref('')
const busyReference = ref(false)
async function pickDescriptor() {
  descriptorPath.value = await api.chooseOpenPath('选择 V2 signer descriptor')
}
async function pickPlugin() {
  pluginCommand.value = await api.chooseOpenPath('选择 signer provider plugin')
}
async function referenceIdentity() {
  if (!descriptorPath.value || !refTenant.value || !refClient.value) {
    toasts.error('请选择 signer descriptor 并填写身份')
    return
  }
  busyReference.value = true
  try {
    await identity.reference({
      tenant_id: refTenant.value,
      client_id: refClient.value,
      descriptor_path: descriptorPath.value,
      plugin_command: pluginCommand.value,
      plugin_inherit_env: pluginEnv.value.split(/[\r\n,]+/).map((v) => v.trim()).filter(Boolean),
      passphrase: referencePassphrase.value,
    })
    toasts.success('Provider 身份已引用')
  } catch (e: any) {
    toasts.error('引用失败', String(e?.message ?? e))
  } finally {
    referencePassphrase.value = ''
    busyReference.value = false
  }
}

async function clear() {
  if (!confirm('确定移除此桌面身份？应用管理的加密私钥文件也会删除。')) return
  try {
    await identity.clear()
    toasts.success('本地身份已移除')
  } catch (e: any) {
    toasts.error('清除失败', String(e?.message ?? e))
  }
}
</script>

<template>
  <div class="flex flex-col gap-5 max-w-[1100px] mx-auto">
    <Card>
      <template #title>
        <div class="flex items-center gap-2">
          <ShieldCheck :size="15" class="text-accent" />
          <h3 class="text-[14px] font-semibold text-ink-800 dark:text-ink-100">当前 V2 身份</h3>
        </div>
      </template>
      <template v-if="hasIdentity" #actions>
        <Button size="sm" variant="subtle" @click="exportVerifier"><Download :size="13" /> 导出公开 descriptor</Button>
        <Button v-if="identity.identity!.unlocked" size="sm" variant="subtle" @click="lock">
          <LockKeyhole :size="13" /> 锁定
        </Button>
        <Button size="sm" variant="danger" @click="clear"><Trash2 :size="13" /> 移除</Button>
      </template>

      <template v-if="hasIdentity">
        <div v-if="identity.identity!.error" class="rounded-xl border border-danger/30 bg-danger/5 p-3 text-[12px] text-danger">
          身份状态已拒绝：{{ identity.identity!.error }}
        </div>
        <div v-else class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <KV label="tenant_id"><span class="font-mono text-[12px]">{{ identity.identity!.tenant_id }}</span></KV>
          <KV label="client_id"><span class="font-mono text-[12px]">{{ identity.identity!.client_id }}</span></KV>
          <KV label="crypto_suite"><span class="font-mono text-[12px] text-accent">{{ identity.identity!.crypto_suite }}</span></KV>
          <KV label="key_id"><span class="font-mono text-[12px]">{{ identity.identity!.key_id }}</span></KV>
          <KV label="provider / protection">
            <span class="text-[12px]">{{ identity.identity!.provider }} · {{ identity.identity!.protection || 'non-exportable provider' }}</span>
          </KV>
          <KV label="algorithm / encoding">
            <span class="text-[12px]">{{ identity.identity!.algorithm }} · {{ identity.identity!.public_key_encoding }}</span>
          </KV>
          <KV label="public fingerprint" class="sm:col-span-2">
            <HashChip :value="identity.identity!.public_fingerprint || ''" :head="16" :tail="10" />
          </KV>
          <KV v-if="identity.identity!.sm2_user_id" label="SM2 user ID">
            <span class="font-mono text-[12px]">{{ identity.identity!.sm2_user_id }}</span>
          </KV>
          <KV label="证书链">
            <span class="text-[12px]">{{ identity.identity!.certificate_count }} 张 · 仅公开证据，不自动成为信任根</span>
          </KV>
          <div
            v-if="identity.identity!.certificates?.length"
            class="sm:col-span-2 rounded-xl border border-white/10 bg-black/15 p-3 space-y-2"
          >
            <div
              v-for="certificate in identity.identity!.certificates"
              :key="`${certificate.index}-${certificate.serial_number}`"
              class="grid grid-cols-1 sm:grid-cols-2 gap-x-4 gap-y-1 text-[11.5px]"
            >
              <span>证书 {{ certificate.index + 1 }} · {{ certificate.subject }}</span>
              <span class="text-ink-500">issuer: {{ certificate.issuer }}</span>
              <span class="font-mono text-ink-500">serial: {{ certificate.serial_number }}</span>
              <span class="text-ink-500">有效期至 {{ formatTime(nanoToDate(certificate.not_after_unix_nano)) }}</span>
            </div>
          </div>
        </div>

        <div class="mt-4 rounded-xl border border-white/10 bg-black/15 p-3 flex items-center justify-between gap-3">
          <div>
            <div class="text-[12px] font-semibold" :class="identity.identity!.unlocked ? 'text-success' : 'text-warn'">
              {{ identity.identity!.unlocked ? '签名能力已解锁' : '签名能力已锁定' }}
            </div>
            <div class="text-[11.5px] text-ink-500">
              私钥不可导出；口令和 provider 凭据不会写入配置、日志或界面结果。
            </div>
          </div>
          <div v-if="!identity.identity!.unlocked && !identity.identity!.error" class="flex gap-2 min-w-[360px]">
            <Input v-model="unlockPassphrase" type="password" placeholder="加密软件密钥口令；外部 provider 可留空" />
            <Button :loading="busyUnlock" @click="unlock"><UnlockKeyhole :size="13" /> 解锁</Button>
          </div>
        </div>
      </template>

      <EmptyState
        v-else
        title="尚未配置身份"
        hint="创建 INTL_V1 或 CN_SM_V1 加密软件身份，或引用 PKCS#11 / SDF / remote provider 的 V2 signer descriptor。"
        :icon="KeyRound"
      />
    </Card>

    <div v-if="!hasIdentity" class="grid grid-cols-1 lg:grid-cols-2 gap-4">
      <Card title="新建加密软件身份" subtitle="私钥使用 SM4-GCM 封装，配置中不保存明文">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="tenant_id"><Input v-model="newTenant" /></Field>
          <Field label="client_id"><Input v-model="newClient" /></Field>
          <Field label="key_id"><Input v-model="newKeyID" /></Field>
        </div>
        <Field label="密码套件" class="mt-3">
          <select v-model="newSuite" class="w-full rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-[12px]">
            <option v-for="suite in suites" :key="suite.value" :value="suite.value">{{ suite.label }}</option>
          </select>
        </Field>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
          <Field label="加密口令" hint="至少 12 个字符"><Input v-model="newPassphrase" type="password" /></Field>
          <Field label="确认口令"><Input v-model="newPassphraseAgain" type="password" /></Field>
        </div>
        <div class="mt-4 flex justify-end">
          <Button :loading="busyCreate" @click="create"><KeyRound :size="13" /> 生成身份</Button>
        </div>
      </Card>

      <Card title="引用 V2 signer descriptor" subtitle="软件封装、PKCS#11、SDF 与 remote provider 共用一个边界">
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="tenant_id"><Input v-model="refTenant" /></Field>
          <Field label="client_id"><Input v-model="refClient" /></Field>
        </div>
        <Field label="Signer descriptor" class="mt-3">
          <div class="flex gap-2">
            <Input v-model="descriptorPath" :mono="true" />
            <Button size="sm" variant="subtle" @click="pickDescriptor"><FolderOpen :size="13" /> 选择</Button>
          </div>
        </Field>
        <Field label="Provider plugin" hint="software descriptor 可留空；其他 provider 必填" class="mt-3">
          <div class="flex gap-2">
            <Input v-model="pluginCommand" :mono="true" />
            <Button size="sm" variant="subtle" @click="pickPlugin"><FileKey2 :size="13" /> 选择</Button>
          </div>
        </Field>
        <Field label="允许继承的环境变量名" hint="每行一个变量名；只保存名称，不保存 PIN/token 值" class="mt-3">
          <Input v-model="pluginEnv" multiline :rows="2" :mono="true" />
        </Field>
        <Field label="软件封装口令" hint="引用加密 software descriptor 时填写；外部 provider 留空" class="mt-3">
          <Input v-model="referencePassphrase" type="password" />
        </Field>
        <div class="mt-4 flex justify-end">
          <Button variant="subtle" :loading="busyReference" @click="referenceIdentity">
            <FileKey2 :size="13" /> 引用并验证
          </Button>
        </div>
      </Card>

      <Card title="导入软件私钥" subtitle="仅作为一次性输入，成功后立即写入 SM4 加密封装">
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="tenant_id"><Input v-model="impTenant" /></Field>
          <Field label="client_id"><Input v-model="impClient" /></Field>
          <Field label="key_id"><Input v-model="impKeyID" /></Field>
        </div>
        <Field label="密码套件" class="mt-3">
          <select v-model="impSuite" class="w-full rounded-xl border border-white/10 bg-black/30 px-3 py-2 text-[12px]">
            <option v-for="suite in suites" :key="suite.value" :value="suite.value">{{ suite.label }}</option>
          </select>
        </Field>
        <Field label="私钥 (base64)" hint="输入不可切换为明文显示，成功或失败后都会从界面内存清除" class="mt-3">
          <Input v-model="impPrivate" type="password" :mono="true" />
        </Field>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-3">
          <Field label="新封装口令"><Input v-model="impPassphrase" type="password" /></Field>
          <Field label="确认口令"><Input v-model="impPassphraseAgain" type="password" /></Field>
        </div>
        <div class="mt-4 flex justify-end">
          <Button variant="subtle" :loading="busyImport" @click="importKey"><Upload :size="13" /> 加密导入</Button>
        </div>
      </Card>
    </div>

    <Card
      v-if="hasIdentity && identity.identity?.provider === 'software'"
      title="轮换加密软件密钥"
      subtitle="保留 tenant/client 和密码套件，生成新的 key_id；不会自动修改服务端 registry"
    >
      <div class="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <Field label="新 key_id"><Input v-model="rotateKeyID" :placeholder="identity.identity?.crypto_suite === 'CN_SM_V1' ? 'sm2-desktop-2' : 'intl-desktop-2'" /></Field>
        <Field label="新加密口令"><Input v-model="rotatePassphrase" type="password" /></Field>
        <Field label="确认口令"><Input v-model="rotatePassphraseAgain" type="password" /></Field>
      </div>
      <div class="mt-4 flex justify-end">
        <Button variant="subtle" :loading="busyRotate" @click="rotate"><RotateCw :size="13" /> 轮换</Button>
      </div>
    </Card>
  </div>
</template>
