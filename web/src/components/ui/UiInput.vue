<script setup lang="ts">
withDefaults(
  defineProps<{
    label?: string
    modelValue: string
    type?: string
    placeholder?: string
    hint?: string
    error?: string
    autocomplete?: string
    spellcheck?: boolean
    mono?: boolean
    id?: string
  }>(),
  { type: 'text', spellcheck: false, mono: false },
)

defineEmits<{ (e: 'update:modelValue', value: string): void }>()
</script>

<template>
  <label class="ui-field" :for="id">
    <span v-if="label" class="ui-label">{{ label }}</span>
    <input
      :id="id"
      class="ui-input"
      :class="{ mono }"
      :type="type"
      :value="modelValue"
      :placeholder="placeholder"
      :autocomplete="autocomplete"
      :spellcheck="spellcheck"
      @input="$emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    />
    <span v-if="hint && !error" class="ui-hint">{{ hint }}</span>
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

.ui-input {
  font: inherit;
  padding: 7px 10px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface);
  color: var(--text);
  width: 100%;
  transition: border-color var(--transition-fast), box-shadow var(--transition-fast);
}

.ui-input::placeholder {
  color: var(--text-faint);
}

.ui-input:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: 0 0 0 3px var(--accent-ring);
}

.mono {
  font-family: var(--font-mono);
  font-size: 13px;
}

.ui-hint {
  display: block;
  margin-top: var(--space-1);
  font-size: 12px;
  color: var(--text-faint);
}

.ui-error {
  display: block;
  margin-top: var(--space-1);
  font-size: 12px;
  color: var(--danger);
}
</style>