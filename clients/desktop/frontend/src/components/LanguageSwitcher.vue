<script setup lang="ts">
import { Languages } from 'lucide-vue-next'
import { locale, localeOptions, setLocale, t } from '@/i18n'

withDefaults(defineProps<{ compact?: boolean }>(), { compact: false })
</script>

<template>
  <label class="td-language" :title="t('语言')" data-i18n-ignore>
    <Languages :size="14" />
    <select :aria-label="t('语言')" :value="locale" @change="setLocale(($event.target as HTMLSelectElement).value)">
      <option v-for="option in localeOptions" :key="option.code" :value="option.code">
        {{ compact ? option.short : option.label }}
      </option>
    </select>
  </label>
</template>

<style scoped>
.td-language { display: inline-flex; align-items: center; gap: 7px; height: 32px; padding: 0 9px; border: 1px solid rgba(255,255,255,.11); border-radius: 11px; color: #d4dbd1; background: rgba(255,255,255,.035); }
.td-language svg { color: var(--acid); flex: 0 0 auto; }
.td-language select { width: 112px; border: 0; outline: 0; appearance: none; color: inherit; background: transparent; font: 650 10px/1 ui-monospace, monospace; cursor: pointer; }
.td-language option { color: #101310; background: #f1f4ee; }
</style>
