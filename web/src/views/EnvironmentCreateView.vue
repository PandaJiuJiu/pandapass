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

const props = defineProps<{ slug: string }>()

const creating = ref(false)
const envName = ref('')
const envSlug = ref('')
const error = ref('')

async function createEnv(): Promise<void> {
  if (!envName.value || !envSlug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createEnv(props.slug, envName.value, envSlug.value)
    router.push(`/projects/${props.slug}`)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

function cancel(): void {
  router.push(`/projects/${props.slug}`)
}
</script>

<template>
  <div>
    <UiPageHeader :title="t('project.newEnvironment')">
      <template #actions>
        <UiButton variant="ghost" size="sm" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="elevated" class="create-card">
      <div class="env-form">
        <UiInput
          v-model="envName"
          :label="t('project.envName')"
          :placeholder="t('project.envNamePlaceholder')"
        />
        <UiInput
          v-model="envSlug"
          :label="t('project.envSlug')"
          :placeholder="t('project.envSlugPlaceholder')"
          mono
        />
        <div class="env-form-actions">
          <UiButton variant="secondary" @click="cancel">
            {{ t('common.cancel') }}
          </UiButton>
          <UiButton
            variant="primary"
            :loading="creating"
            :disabled="creating || !envName || !envSlug"
            @click="createEnv"
          >
            {{ creating ? t('project.creatingEnvironment') : t('project.addEnvironment') }}
          </UiButton>
        </div>
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

.env-form {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
  align-items: end;
}

.env-form-actions {
  grid-column: 1 / -1;
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border);
}
</style>