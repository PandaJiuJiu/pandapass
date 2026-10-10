<script setup lang="ts">
withDefaults(
  defineProps<{
    label?: string
    modelValue: string
    placeholder?: string
    rows?: number
    mono?: boolean
    error?: string
    id?: string
  }>(),
  { rows: 4, mono: false },
)

defineEmits<{ (e: 'update:modelValue', value: string): void }>()
</script>

<template>
  <label class="ui-field" :for="id">
    <span v-if="label" class="ui-label">{{ label }}</span>
    <textarea
      :id="id"
      class="ui-textarea"
      :class="{ mono }"
      :rows="rows"
      :value="modelValue"
      :placeholder="placeholder"
      @input="$emit('update:modelValue', ($event.target as HTMLTextAreaElement).value)"
    />
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

.ui-textarea {
  font: inherit;
  padding: 7px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface);
  color: var(--text);
  width: 100%;
  resize: vertical;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.ui-textarea::placeholder {
  color: var(--text-faint);
}

.ui-textarea:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-ring);
}

.mono {
  font-family: var(--font-mono);
  font-size: 13px;
}

.ui-error {
  display: block;
  margin-top: var(--space-1);
  font-size: 12px;
  color: var(--danger);
}
</style>