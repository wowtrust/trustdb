<script setup lang="ts">
defineProps<{
  modelValue?: string
  placeholder?: string
  type?: string
  mono?: boolean
  disabled?: boolean
  readonly?: boolean
  multiline?: boolean
  rows?: number
  leadingIcon?: boolean
}>()
const emit = defineEmits<{ (e: 'update:modelValue', value: string): void }>()

function onInput(e: Event) {
  const t = e.target as HTMLInputElement | HTMLTextAreaElement
  emit('update:modelValue', t.value)
}
</script>

<template>
  <template v-if="multiline">
    <textarea
      :rows="rows ?? 3"
      :value="modelValue ?? ''"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      @input="onInput"
      :class="[
        'w-full resize-none px-3.5 py-2.5 rounded-[14px] border border-white/10 bg-[#0b0d0b]/80 text-ink-50 placeholder:text-ink-500 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)] transition focus:border-accent/70 focus:bg-[#0f130f] focus:shadow-acid disabled:opacity-50',
        mono ? 'font-mono text-[12px]' : 'text-[13px]'
      ]"
    />
  </template>
  <template v-else>
    <input
      :type="type ?? 'text'"
      :value="modelValue ?? ''"
      :placeholder="placeholder"
      :disabled="disabled"
      :readonly="readonly"
      @input="onInput"
      :class="[
        'h-10 w-full rounded-[14px] border border-white/10 bg-[#0b0d0b]/80 text-ink-50 placeholder:text-ink-500 shadow-[inset_0_1px_0_rgba(255,255,255,0.05)] transition focus:border-accent/70 focus:bg-[#0f130f] focus:shadow-acid disabled:opacity-50',
        leadingIcon ? 'pl-9 pr-3.5' : 'px-3.5',
        mono ? 'font-mono text-[12px]' : 'text-[13px]'
      ]"
    />
  </template>
</template>
