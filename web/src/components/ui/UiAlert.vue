<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'error' | 'info' | 'success'
  }>(),
  { variant: 'info' },
)
</script>

<template>
  <div class="ui-alert" :class="`variant-${variant}`" role="alert">
    <slot />
  </div>
</template>

<style scoped>
.ui-alert {
  display: flex;
  align-items: flex-start;
  gap: var(--space-2);
  padding: var(--space-3) var(--space-4);
  border-radius: var(--radius-md);
  font-size: 13px;
  line-height: 1.5;
}

.variant-error {
  background: var(--danger-soft);
  color: var(--danger);
  border: 1px solid transparent;
}

.variant-info {
  background: var(--accent-soft);
  color: var(--accent);
  border: 1px solid transparent;
}

.variant-success {
  background: var(--ok-soft);
  color: var(--ok);
  border: 1px solid transparent;
}
</style>