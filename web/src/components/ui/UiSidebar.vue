<script setup lang="ts">
defineProps<{ open?: boolean }>()
defineEmits<{ (e: 'close'): void }>()
</script>

<template>
  <aside class="ui-sidebar" :class="{ open }">
    <div class="ui-sidebar-inner">
      <div class="ui-sidebar-brand">
        <slot name="brand" />
      </div>
      <nav class="ui-sidebar-nav">
        <slot />
      </nav>
      <div class="ui-sidebar-footer">
        <slot name="footer" />
      </div>
    </div>
  </aside>
</template>

<style scoped>
.ui-sidebar {
  position: fixed;
  inset: 0 auto 0 0;
  width: var(--sidebar-width);
  background: var(--surface);
  border-right: 1px solid var(--border);
  z-index: 300;
  display: flex;
  flex-direction: column;
  transform: translateX(-100%);
  transition: transform var(--transition-base);
}

.ui-sidebar.open {
  transform: translateX(0);
}

.ui-sidebar-inner {
  display: flex;
  flex-direction: column;
  height: 100%;
}

.ui-sidebar-brand {
  display: flex;
  align-items: center;
  gap: var(--space-2);
  padding: var(--space-4) var(--space-4) var(--space-3);
  font-size: 15px;
  font-weight: 700;
}

.ui-sidebar-nav {
  flex: 1;
  overflow-y: auto;
  padding: var(--space-2) var(--space-3);
}

.ui-sidebar-footer {
  border-top: 1px solid var(--border);
  padding: var(--space-3);
}

@media (min-width: 769px) {
  .ui-sidebar {
    position: sticky;
    top: 0;
    height: 100vh;
    transform: none;
  }
}
</style>