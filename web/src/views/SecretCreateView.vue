<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const router = useRouter()
const { t } = useI18n()

const props = defineProps<{ slug: string; env: string }>()

const saving = ref(false)
const newKey = ref('')
const newValue = ref('')
const error = ref('')

async function save(): Promise<void> {
  if (!newKey.value || !newValue.value) return
  saving.value = true
  error.value = ''
  try {
    await api.setSecret(props.slug, props.env, newKey.value, newValue.value)
    router.push(`/projects/${props.slug}`)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.saveFailed')
  } finally {
    saving.value = false
  }
}

function cancel(): void {
  router.push(`/projects/${props.slug}`)
}
</script>

<template>
  <div>
    <UiPageHeader :title="t('secretTable.addOrReplace')">
      <template #actions>
        <UiButton variant="ghost" size="sm" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="elevated" class="create-card">
      <div class="form-grid">
        <UiInput
          v-model="newKey"
          mono
          :label="t('secretTable.key')"
          :placeholder="t('secretTable.keyPlaceholder')"
          autocomplete="off"
          :spellcheck="false"
        />
        <UiInput
          v-model="newValue"
          mono
          type="password"
          :label="t('secretTable.valuePlaceholder')"
          :placeholder="t('secretTable.valuePlaceholder')"
          autocomplete="off"
          :spellcheck="false"
        />
      </div>
      <p class="hint">{{ t('secretTable.maskedHint') }}</p>
      <div class="form-actions">
        <UiButton variant="secondary" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
        <UiButton
          variant="primary"
          :loading="saving"
          :disabled="saving || !newKey || !newValue"
          @click="save"
        >
          {{ saving ? t('secretTable.saving') : t('secretTable.save') }}
        </UiButton>
      </div>
    </UiCard>
  </div>
</template>

<style scoped>
.page-alert {
  margin-bottom: var(--space-4);
}

.create-card {
  max-width: 500px;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
}

.hint {
  margin: var(--space-2) 0 0;
  font-size: 12px;
  color: var(--text-faint);
}

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border);
}
</style>