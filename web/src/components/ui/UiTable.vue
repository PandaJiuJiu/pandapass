<script setup lang="ts">
withDefaults(
  defineProps<{
    loading?: boolean
    empty?: boolean
    emptyText?: string
    loadingText?: string
    colspan?: number
  }>(),
  { loading: false, empty: false, emptyText: '', loadingText: 'Loading…', colspan: 1 },
)
</script>

<template>
  <div class="ui-table-wrap">
    <table class="ui-table">
      <thead v-if="$slots.head">
        <slot name="head" />
      </thead>
      <tbody v-if="loading">
        <tr>
          <td :colspan="colspan" class="ui-table-loading">
            <span class="spinner" aria-hidden="true" />
            {{ loadingText }}
          </td>
        </tr>
      </tbody>
      <tbody v-else-if="empty">
        <tr>
          <td :colspan="colspan" class="ui-table-empty">
            <slot name="empty">
              {{ emptyText }}
            </slot>
          </td>
        </tr>
      </tbody>
      <tbody v-else>
        <slot />
      </tbody>
    </table>
  </div>
</template>

<style scoped>
.ui-table-wrap {
  overflow-x: auto;
}

.ui-table {
  width: 100%;
  border-collapse: collapse;
  font-variant-numeric: tabular-nums;
}

.ui-table :deep(th) {
  text-align: left;
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  color: var(--text-dim);
  font-weight: 500;
  font-size: 12.5px;
  white-space: nowrap;
}

.ui-table :deep(td) {
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  font-size: 13.5px;
}

.ui-table :deep(tbody tr:last-child td) {
  border-bottom: none;
}

.ui-table :deep(tbody tr:hover) {
  background: var(--surface-2);
}

.ui-table-loading,
.ui-table-empty {
  padding: var(--space-8);
  text-align: center;
  color: var(--text-dim);
  font-size: 13px;
}

.spinner {
  width: 14px;
  height: 14px;
  border: 2px solid var(--border-strong);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: ui-spin 0.6s linear infinite;
  display: inline-block;
  vertical-align: middle;
  margin-right: 6px;
}

@keyframes ui-spin {
  to {
    transform: rotate(360deg);
  }
}
</style>