<script setup lang="ts">
import UiButton from './UiButton.vue'

const props = withDefaults(
  defineProps<{
    page: number
    total: number
    perPage: number
    newerLabel?: string
    olderLabel?: string
    pageLabel?: string
    ofLabel?: string
    entriesLabel?: string
  }>(),
  { newerLabel: 'Newer', olderLabel: 'Older', pageLabel: 'page', ofLabel: 'of', entriesLabel: 'entries' },
)

const emit = defineEmits<{ (e: 'change', page: number): void }>()

const totalPages = Math.ceil(props.total / props.perPage)
</script>

<template>
  <div v-if="total > perPage" class="ui-pagination">
    <UiButton variant="ghost" size="sm" :disabled="page === 1" @click="emit('change', page - 1)">
      {{ newerLabel }}
    </UiButton>
    <span class="info">
      {{ pageLabel }} {{ page }} {{ ofLabel }} {{ totalPages }} · {{ total }} {{ entriesLabel }}
    </span>
    <UiButton variant="ghost" size="sm" :disabled="page * perPage >= total" @click="emit('change', page + 1)">
      {{ olderLabel }}
    </UiButton>
  </div>
</template>

<style scoped>
.ui-pagination {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-3);
  margin-top: var(--space-4);
}

.info {
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-dim);
}
</style>