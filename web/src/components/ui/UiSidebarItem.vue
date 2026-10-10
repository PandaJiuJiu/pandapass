<script setup lang="ts">
defineProps<{ to: string; exact?: boolean }>()
defineEmits<{ (e: 'close'): void }>()
</script>

<template>
  <router-link class="ui-sidebar-item" :to="to" :exact="exact" @click="$emit('close')">
    <slot />
  </router-link>
</template>

<style scoped>
.ui-sidebar-item {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: 8px 12px;
  margin-bottom: 2px;
  border-radius: var(--radius-md);
  font-size: 13.5px;
  font-weight: 500;
  color: var(--text-dim);
  text-decoration: none;
  border-left: 2px solid transparent;
  transition: background-color var(--transition-fast), color var(--transition-fast);
}

.ui-sidebar-item:hover {
  background: var(--surface-2);
  color: var(--text);
  text-decoration: none;
}

.ui-sidebar-item.router-link-active {
  background: var(--accent-soft);
  color: var(--accent);
  border-left-color: var(--accent);
}
</style>