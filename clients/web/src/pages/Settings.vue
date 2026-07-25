<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import Input from '@/components/Input.vue'
import Field from '@/components/Field.vue'
import { getConfig, getConfigRaw, getOverlays, putConfigYaml } from '@/lib/api'
import { useAuth } from '@/stores/auth'

const auth = useAuth()

const cfgJson = ref('')
const overlaysJson = ref('')
const rawYaml = ref('')
const cfgPath = ref('')
const msg = ref('')
const err = ref('')
const busy = ref(false)

const canSave = computed(() => !!cfgPath.value.trim() && auth.hasPermission('system.configure'))

async function load() {
  msg.value = ''
  err.value = ''
  busy.value = true
  try {
    const c = await getConfig()
    cfgPath.value = c.config_path
    cfgJson.value = JSON.stringify(c.config, null, 2)
    const o = await getOverlays()
    overlaysJson.value = JSON.stringify(o, null, 2)
    try {
      rawYaml.value = await getConfigRaw()
    } catch (e: unknown) {
      rawYaml.value = `; 无法读取原始 YAML（可能未使用 --config）：${e instanceof Error ? e.message : String(e)}`
    }
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

async function save() {
  msg.value = ''
  err.value = ''
  busy.value = true
  try {
    const r = await putConfigYaml(rawYaml.value)
    const success = r.backup ? `已保存，备份：${r.backup}` : '已保存'
    await load()
    msg.value = success
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : String(e)
  } finally {
    busy.value = false
  }
}

onMounted(() => { load() })
</script>

<template>
  <div class="flex flex-col gap-4 max-w-[1100px] mx-auto">
    <Card title="系统设置" subtitle="有效配置（脱敏）与 on-disk YAML（需 --config）">
      <template #actions>
        <Button size="sm" variant="subtle" :loading="busy" @click="load">刷新</Button>
      </template>
      <div class="px-5 pt-2 space-y-3">
        <p class="text-[12px] text-ink-500">配置文件路径：<span class="font-mono text-accent">{{ cfgPath || '（未设置）' }}</span></p>
        <p v-if="msg" class="text-[12px] text-accent">{{ msg }}</p>
        <p v-if="err" class="text-[12px] text-danger">{{ err }}</p>
      </div>
    </Card>

    <Card title="结构化配置 JSON" dense>
      <pre class="px-5 py-4 text-[11px] font-mono text-ink-300 whitespace-pre-wrap break-all max-h-[320px] overflow-y-auto">{{ cfgJson }}</pre>
    </Card>

    <Card title="Viper 覆盖字段" dense>
      <pre class="px-5 py-4 text-[11px] font-mono text-ink-300 whitespace-pre-wrap break-all max-h-[240px] overflow-y-auto">{{ overlaysJson }}</pre>
    </Card>

    <Card title="编辑 YAML" subtitle="保存前会校验；多数改动需重启 trustdb serve">
      <div class="px-5 py-4 space-y-3">
        <Field label="trustdb.yaml" hint="PUT 将写入 --config 指向的文件并生成 .bak 备份">
          <Input v-model="rawYaml" multiline :rows="18" mono />
        </Field>
        <p v-if="!cfgPath.trim()" class="text-[11px] text-warn">当前进程未指定 --config，无法通过 Web 写回文件。</p>
        <p v-else-if="!auth.hasPermission('system.configure')" class="text-[11px] text-warn">当前角色只有读取权限，保存需要 system.configure。</p>
        <div class="flex gap-2">
          <Button :loading="busy" :disabled="!canSave" @click="save">保存 YAML</Button>
        </div>
      </div>
    </Card>
  </div>
</template>
