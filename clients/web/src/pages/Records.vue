<script setup lang="ts">
import { onMounted, ref } from 'vue'
import Card from '@/components/Card.vue'
import Button from '@/components/Button.vue'
import HashChip from '@/components/HashChip.vue'
import LevelBadge from '@/components/LevelBadge.vue'
import EmptyState from '@/components/EmptyState.vue'
import { getRecords, type RecordIndex } from '@/lib/api'
import { formatTime, nanoToDate, relativeTime } from '@/lib/format'
import { ScrollText, RefreshCcw } from 'lucide-vue-next'

const items = ref<RecordIndex[]>([])
const limit = ref(50)
const cursor = ref('')
const query = ref('')
const level = ref('')
const loading = ref(false)
const err = ref('')

async function load(reset: boolean) {
  if (reset) cursor.value = ''
  loading.value = true
  err.value = ''
  try {
    const body = await getRecords({
      limit: limit.value,
      cursor: cursor.value,
      query: query.value.trim(),
      level: level.value.trim(),
    })
    if (reset) items.value = body.records
    else items.value = items.value.concat(body.records)
    cursor.value = body.next_cursor ?? ''
  } catch (e: unknown) {
    err.value = e instanceof Error ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

onMounted(() => { load(true) })
</script>

<template>
  <div class="flex flex-col gap-4 max-w-[1200px] mx-auto">
    <Card title="存证记录" subtitle="只读列表（经 Admin 代理 GET /v1/records）">
      <template #actions>
        <Button size="sm" variant="subtle" :loading="loading" @click="load(true)">
          <RefreshCcw :size="12" /> 刷新
        </Button>
      </template>
      <div class="flex flex-wrap gap-3 px-5 pt-2 pb-4">
        <input
          v-model="query"
          placeholder="搜索 q / content_hash"
          class="h-9 min-w-[200px] flex-1 px-3 rounded-[12px] border border-white/10 bg-[#0b0d0b]/80 text-[12px] text-ink-100"
          @keyup.enter="load(true)"
        />
        <input
          v-model="level"
          placeholder="等级 L3-L5"
          class="h-9 w-[120px] px-3 rounded-[12px] border border-white/10 bg-[#0b0d0b]/80 text-[12px] text-ink-100"
          @keyup.enter="load(true)"
        />
        <Button size="sm" @click="load(true)">应用</Button>
      </div>
      <p v-if="err" class="px-5 pb-2 text-[12px] text-danger">{{ err }}</p>
      <div v-if="!items.length && !loading" class="px-5 pb-6">
        <EmptyState title="暂无记录" hint="调整筛选或确认 proofstore 中已有索引数据。" :icon="ScrollText" />
      </div>
      <div v-else class="overflow-x-auto">
        <table class="w-full text-[12px]">
          <thead class="text-ink-500 text-left">
            <tr>
              <th class="pl-5 pr-2 py-2 font-normal">record</th>
              <th class="px-2 py-2 font-normal">level</th>
              <th class="px-2 py-2 font-normal">tenant / client</th>
              <th class="px-2 py-2 font-normal">received</th>
              <th class="pr-5 pl-2 py-2 font-normal">batch</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in items" :key="r.record_id" class="border-t border-[var(--hairline)]">
              <td class="pl-5 pr-2 py-2">
                <HashChip :value="r.record_id" :head="8" :tail="6" />
              </td>
              <td class="px-2 py-2">
                <LevelBadge v-if="r.proof_level" :level="r.proof_level" size="sm" />
                <span v-else class="text-ink-500">—</span>
              </td>
              <td class="px-2 py-2 text-ink-400">
                <span class="font-mono text-[11px]">{{ r.tenant_id || '—' }}</span>
                /
                <span class="font-mono text-[11px]">{{ r.client_id || '—' }}</span>
              </td>
              <td class="px-2 py-2 text-ink-400">
                {{ relativeTime(nanoToDate(r.received_at_unix_n)) }}
                <span class="block text-[10px] text-ink-600">{{ formatTime(nanoToDate(r.received_at_unix_n)) }}</span>
              </td>
              <td class="pr-5 pl-2 py-2 font-mono text-[11px] text-ink-300">
                {{ r.batch_id || '—' }}
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <div v-if="cursor" class="px-5 py-4 hairline-t flex justify-center">
        <Button size="sm" variant="subtle" :loading="loading" @click="load(false)">加载更多</Button>
      </div>
    </Card>
  </div>
</template>
