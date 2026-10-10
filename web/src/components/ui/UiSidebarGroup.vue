<script setup lang="ts">
defineProps<{ title?: string }>()
</script>

<template>
  <div class="ui-sidebar-group">
    <div v-if="title" class="ui-sidebar-group-title">{{ title }}</div>
    <slot />
  </div>
</template>

<style scoped>
.ui-sidebar-group {
  margin-bottom: var(--space-3);
}

.ui-sidebar-group-title {
  padding: var(--space-3) 12px var(--space-1);
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  color: var(--text-faint);
}
</style>