<script setup lang="ts">
withDefaults(
  defineProps<{
    label?: string
    modelValue: string
    placeholder?: string
    error?: string
    id?: string
  }>(),
  {},
)

defineEmits<{ (e: 'update:modelValue', value: string): void }>()
</script>

<template>
  <label class="ui-field" :for="id">
    <span v-if="label" class="ui-label">{{ label }}</span>
    <select
      :id="id"
      class="ui-select"
      :value="modelValue"
      @change="$emit('update:modelValue', ($event.target as HTMLSelectElement).value)"
    >
      <option v-if="placeholder" value="" disabled>{{ placeholder }}</option>
      <slot />
    </select>
    <span v-if="error" class="ui-error">{{ error }}</span>
  </label>
</template>

<style scoped>
.ui-field {
  display: block;
  margin-bottom: var(--space-4);
}

.ui-label {
  display: block;
  margin-bottom: var(--space-1);
  font-size: 12.5px;
  font-weight: 500;
  color: var(--text-dim);
}

.ui-select {
  font: inherit;
  padding: 7px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface);
  color: var(--text);
  width: 100%;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.ui-select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-ring);
}

.ui-error {
  display: block;
  margin-top: var(--space-1);
  font-size: 12px;
  color: var(--danger);
}
</style>