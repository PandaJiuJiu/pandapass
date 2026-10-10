<script setup lang="ts">
withDefaults(
  defineProps<{
    variant?: 'primary' | 'secondary' | 'ghost' | 'danger'
    size?: 'sm' | 'md'
    loading?: boolean
    type?: 'button' | 'submit'
    disabled?: boolean
  }>(),
  { variant: 'secondary', size: 'md', loading: false, type: 'button', disabled: false },
)
</script>

<template>
  <button
    class="ui-button"
    :class="[`variant-${variant}`, `size-${size}`]"
    :type="type"
    :disabled="disabled || loading"
  >
    <span v-if="loading" class="ui-spinner" aria-hidden="true" />
    <slot />
  </button>
</template>

<style scoped>
.ui-button {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: var(--space-2);
  font: inherit;
  font-weight: 500;
  border-radius: var(--radius-md);
  cursor: pointer;
  white-space: nowrap;
  transition: background-color var(--transition-fast),
    border-color var(--transition-fast), color var(--transition-fast);
}

.ui-button:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
}

.ui-button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.size-sm {
  padding: 4px 10px;
  font-size: 12.5px;
}

.size-md {
  padding: 7px 14px;
  font-size: 13.5px;
}

.variant-primary {
  background: var(--accent);
  border: 1px solid var(--accent);
  color: #fff;
}

.variant-primary:hover:not(:disabled) {
  background: var(--accent-hover);
  border-color: var(--accent-hover);
}

.variant-secondary {
  background: var(--surface);
  border: 1px solid var(--border-strong);
  color: var(--text);
}

.variant-secondary:hover:not(:disabled) {
  background: var(--surface-2);
  border-color: var(--border-strong);
}

.variant-ghost {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-dim);
}

.variant-ghost:hover:not(:disabled) {
  background: var(--surface-2);
  color: var(--text);
}

.variant-danger {
  background: transparent;
  border: 1px solid var(--danger);
  color: var(--danger);
}

.variant-danger:hover:not(:disabled) {
  background: var(--danger-soft);
}

/* Loading spinner */
.ui-spinner {
  width: 13px;
  height: 13px;
  border: 2px solid currentColor;
  border-top-color: transparent;
  border-radius: 50%;
  animation: ui-spin 0.6s linear infinite;
}

@keyframes ui-spin {
  to {
    transform: rotate(360deg);
  }
}

@media (prefers-reduced-motion: reduce) {
  .ui-spinner {
    animation-duration: 1.4s;
  }
}
</style>