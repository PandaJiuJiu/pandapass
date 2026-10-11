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
const email = ref('')
const password = ref('')
const error = ref('')

async function create(): Promise<void> {
  if (!email.value || !password.value) return
  creating.value = true
  error.value = ''
  try {
    await api.adminCreateUser(email.value, password.value)
    router.push('/users')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

function cancel(): void {
  router.push('/users')
}
</script>

<template>
  <div>
    <UiPageHeader :title="t('users.createUser')">
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
          v-model="email"
          type="email"
          spellcheck="false"
          :label="t('users.email')"
          :placeholder="t('users.emailPlaceholder')"
        />
        <UiInput
          v-model="password"
          :label="t('common.password')"
          :placeholder="t('users.passwordPlaceholder')"
        />
      </div>
      <div class="form-actions">
        <UiButton variant="secondary" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
        <UiButton
          variant="primary"
          :loading="creating"
          :disabled="creating || !email || !password"
          @click="create"
        >
          {{ creating ? t('users.creating') : t('users.createUser') }}
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

.form-actions {
  display: flex;
  justify-content: flex-end;
  gap: var(--space-3);
  margin-top: var(--space-4);
  padding-top: var(--space-4);
  border-top: 1px solid var(--border);
}
</style>