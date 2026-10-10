<script setup lang="ts">
withDefaults(
  defineProps<{
    title?: string
    description?: string
  }>(),
  { title: '', description: '' },
)
</script>

<template>
  <div class="ui-empty-state">
    <slot name="icon" />
    <h3 v-if="title">{{ title }}</h3>
    <p v-if="description" class="description">{{ description }}</p>
    <div v-if="$slots.action" class="action">
      <slot name="action" />
    </div>
  </div>
</template>

<style scoped>
.ui-empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  text-align: center;
  padding: var(--space-8) var(--space-4);
  color: var(--text-dim);
}

.ui-empty-state h3 {
  margin: var(--space-3) 0 0;
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}

.ui-empty-state .description {
  margin: var(--space-1) 0 0;
  font-size: 13px;
  max-width: 360px;
}

.ui-empty-state .action {
  margin-top: var(--space-4);
}
</style>