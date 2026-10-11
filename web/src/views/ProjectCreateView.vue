<script setup lang="ts">
import { computed, ref } from 'vue'
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

/** Is the current slug syntactically valid? */
const slugValid = computed(() => /^[a-z0-9]+(-[a-z0-9]+)*$/.test(slug.value))

async function create(): Promise<void> {
  if (!name.value || !slugValid.value) return
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
      <div class="field-row">
        <label class="field-label" for="project-name">{{ t('dashboard.projectName') }}</label>
        <div class="field-control">
          <UiInput
            v-model="name"
            id="project-name"
            :placeholder="t('dashboard.projectNamePlaceholder')"
          />
        </div>
      </div>

      <div class="field-row">
        <label class="field-label" for="project-slug">{{ t('dashboard.projectSlug') }}</label>
        <div class="field-control">
          <UiInput
            v-model="slug"
            id="project-slug"
            mono
            :placeholder="t('dashboard.projectSlug')"
            :hint="t('dashboard.slugHint')"
            :error="slug && !slugValid ? t('dashboard.slugHint') : undefined"
          />
        </div>
      </div>

      <div class="field-row">
        <label class="field-label" for="project-description">
          {{ t('dashboard.descriptionOptional') }}
        </label>
        <div class="field-control">
          <UiInput
            v-model="description"
            id="project-description"
            :placeholder="t('dashboard.descriptionOptional')"
          />
        </div>
      </div>

      <div class="form-actions">
        <UiButton variant="secondary" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
        <UiButton
          variant="primary"
          :loading="creating"
          :disabled="creating || !name || !slugValid"
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
  max-width: 640px;
}

.field-row {
  display: grid;
  grid-template-columns: 160px 1fr;
  gap: var(--space-4);
  align-items: start;
  margin-bottom: var(--space-4);
}

.field-label {
  padding-top: 9px;
  font-size: 13px;
  font-weight: 500;
  color: var(--text-dim);
}

.field-control {
  min-width: 0;
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