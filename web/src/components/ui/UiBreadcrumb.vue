<script setup lang="ts">
interface Crumb {
  label: string
  to?: string
}

defineProps<{ items: Crumb[] }>()
</script>

<template>
  <nav class="ui-breadcrumb" aria-label="Breadcrumb">
    <template v-for="(item, idx) in items" :key="idx">
      <span v-if="idx > 0" class="sep" aria-hidden="true">/</span>
      <router-link v-if="item.to" :to="item.to" class="crumb-link">{{ item.label }}</router-link>
      <span v-else class="crumb-current" aria-current="page">{{ item.label }}</span>
    </template>
  </nav>
</template>

<style scoped>
.ui-breadcrumb {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  font-size: 13px;
}

.sep {
  color: var(--text-faint);
}

.crumb-link {
  color: var(--text-dim);
  text-decoration: none;
}

.crumb-link:hover {
  color: var(--accent);
  text-decoration: underline;
}

.crumb-current {
  color: var(--text);
  font-weight: 600;
}
</style>