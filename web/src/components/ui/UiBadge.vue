<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'dim' | 'info' | 'ok' | 'warn' | 'danger'
    dot?: boolean
  }>(),
  { variant: 'dim', dot: false },
)
</script>

<template>
  <span class="ui-badge" :class="`variant-${variant}`">
    <span v-if="dot" class="dot" aria-hidden="true" />
    <slot />
  </span>
</template>

<style scoped>
.ui-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 9px;
  border-radius: var(--radius-full, 9999px);
  font-size: 12px;
  font-weight: 500;
  line-height: 1.6;
  white-space: nowrap;
}

.dot {
  width: 6px;
  height: 6px;
  border-radius: 50%;
  background: currentColor;
}

.variant-dim {
  background: var(--surface-3);
  color: var(--text-dim);
}

.variant-info {
  background: var(--accent-soft);
  color: var(--accent);
}

.variant-ok {
  background: var(--ok-soft);
  color: var(--ok);
}

.variant-warn {
  background: var(--warn-soft);
  color: var(--warn);
}

.variant-danger {
  background: var(--danger-soft);
  color: var(--danger);
}
</style>