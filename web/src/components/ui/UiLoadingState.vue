<script setup lang="ts">
withDefaults(defineProps<{ text?: string }>(), { text: 'Loading…' })
</script>

<template>
  <div class="ui-loading-state">
    <span class="spinner" aria-hidden="true" />
    <span>{{ text }}</span>
  </div>
</template>

<style scoped>
.ui-loading-state {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  padding: var(--space-8);
  color: var(--text-dim);
  font-size: 13px;
}

.spinner {
  width: 16px;
  height: 16px;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: ui-spin 0.6s linear infinite;
}

@keyframes ui-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>