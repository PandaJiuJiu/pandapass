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

const creating = ref(false)
const name = ref('')
const slug = ref('')
const description = ref('')
const error = ref('')

/** True once the user edits the slug by hand; stops auto-derivation. */
const slugTouched = ref(false)
function onNameInput(): void {
  if (slugTouched.value) return
  slug.value = name.value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

async function create(): Promise<void> {
  if (!name.value || !slug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createProject(name.value, slug.value, description.value || undefined)
    router.push('/projects')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

function cancel(): void {
  router.push('/projects')
}
</script>

<template>
  <div>
    <UiPageHeader :title="t('dashboard.newProject')">
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
          v-model="name"
          :label="t('dashboard.projectName')"
          :placeholder="t('dashboard.projectName')"
          @input="onNameInput"
        />
        <UiInput
          v-model="slug"
          mono
          :label="t('dashboard.projectSlug')"
          :hint="t('dashboard.slugHint')"
          :placeholder="t('dashboard.projectSlug')"
          @update:model-value="slugTouched = true"
        />
        <UiInput
          v-model="description"
          :label="`${t('common.description')} ${t('common.optional')}`"
          class="span-2"
        />
      </div>
      <div class="form-actions">
        <UiButton variant="secondary" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
        <UiButton
          variant="primary"
          :loading="creating"
          :disabled="creating || !name || !slug"
          @click="create"
        >
          {{ creating ? t('dashboard.creating') : t('dashboard.createProject') }}
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
  max-width: 600px;
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
}

.span-2 {
  grid-column: 1 / -1;
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