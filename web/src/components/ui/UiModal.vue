<script setup lang="ts">
import { onMounted, onUnmounted, watch } from 'vue'

const props = withDefaults(
  defineProps<{
    open: boolean
    title?: string
    size?: 'sm' | 'md' | 'lg'
  }>(),
  { size: 'md' },
)

const emit = defineEmits<{ (e: 'close'): void }>()

function onKeydown(e: KeyboardEvent): void {
  if (e.key === 'Escape' && props.open) emit('close')
}

watch(
  () => props.open,
  (open) => {
    if (open) {
      document.addEventListener('keydown', onKeydown)
    } else {
      document.removeEventListener('keydown', onKeydown)
    }
  },
  { immediate: true },
)

onMounted(() => {
  if (props.open) document.addEventListener('keydown', onKeydown)
})

onUnmounted(() => {
  document.removeEventListener('keydown', onKeydown)
})
</script>

<template>
  <Teleport to="body">
    <Transition name="modal">
      <div v-if="open" class="ui-modal-overlay" @click.self="emit('close')">
        <div class="ui-modal" :class="`size-${size}`" role="dialog" aria-modal="true">
          <header v-if="title" class="ui-modal-header">
            <h3>{{ title }}</h3>
            <button class="ui-close" aria-label="Close" @click="emit('close')">×</button>
          </header>
          <div class="ui-modal-body">
            <slot />
          </div>
          <footer v-if="$slots.footer" class="ui-modal-footer">
            <slot name="footer" />
          </footer>
        </div>
      </div>
    </Transition>
  </Teleport>
</template>

<style scoped>
.ui-modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(16, 24, 40, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
  padding: var(--space-4);
}

.ui-modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius-lg);
  box-shadow: var(--shadow-lg);
  max-height: 85vh;
  overflow: auto;
  width: 100%;
}

.size-sm {
  max-width: 420px;
}

.size-md {
  max-width: 560px;
}

.size-lg {
  max-width: 720px;
}

.ui-modal-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--space-4) var(--space-6) 0;
}

.ui-modal-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.ui-close {
  background: none;
  border: none;
  font-size: 20px;
  line-height: 1;
  color: var(--text-faint);
  cursor: pointer;
  padding: 4px 8px;
  border-radius: var(--radius-sm);
}

.ui-close:hover {
  color: var(--text);
  background: var(--surface-2);
}

.ui-modal-body {
  padding: var(--space-4) var(--space-6) var(--space-6);
}

.ui-modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-2);
  padding: 0 var(--space-6) var(--space-6);
}

/* Transition */
.modal-enter-active,
.modal-leave-active {
  transition: opacity var(--transition-base);
}

.modal-enter-active .ui-modal,
.modal-leave-active .ui-modal {
  transition: transform var(--transition-base), opacity var(--transition-base);
}

.modal-enter-from,
.modal-leave-to {
  opacity: 0;
}

.modal-enter-from .ui-modal,
.modal-leave-to .ui-modal {
  transform: translateY(8px) scale(0.98);
  opacity: 0;
}
</style>