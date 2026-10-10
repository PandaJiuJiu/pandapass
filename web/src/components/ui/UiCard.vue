<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'elevated' | 'outlined' | 'subtle'
    padding?: boolean
  }>(),
  { variant: 'elevated', padding: true },
)
</script>

<template>
  <div class="ui-card" :class="[`variant-${variant}`, { 'no-padding': !padding }]">
    <slot />
  </div>
</template>

<style scoped>
.ui-card {
  border-radius: var(--radius-lg);
  margin-bottom: var(--space-4);
}

.ui-card.no-padding {
  padding: 0;
}

.variant-elevated {
  background: var(--surface);
  border: 1px solid var(--border);
  box-shadow: var(--shadow-sm);
}

.variant-outlined {
  background: var(--surface);
  border: 1px solid var(--border);
}

.variant-subtle {
  background: var(--surface-2);
  border: 1px solid var(--border);
}

.ui-card:not(.no-padding) {
  padding: 24px;
}
</style>