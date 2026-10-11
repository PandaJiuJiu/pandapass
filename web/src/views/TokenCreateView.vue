<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiSelect from '@/components/ui/UiSelect.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const router = useRouter()
const { t } = useI18n()

const creating = ref(false)
const name = ref('')
const scope = ref('')
const project = ref('')
const expiresDays = ref('')
const error = ref('')

/** The plaintext token, shown exactly once. Never stored anywhere. */
const issued = ref('')

type ScopeKey =
  | 'readSecret'
  | 'listSecret'
  | 'writeSecret'
  | 'readAudit'
  | 'manageProject'

const SCOPES: ReadonlyArray<readonly [string, ScopeKey]> = [
  ['read:secret', 'readSecret'],
  ['list:secret', 'listSecret'],
  ['write:secret', 'writeSecret'],
  ['read:audit', 'readAudit'],
  ['manage:project', 'manageProject'],
]

async function create(): Promise<void> {
  if (!name.value || !scope.value) return
  creating.value = true
  error.value = ''
  try {
    const res = await api.createToken({
      name: name.value,
      scopes: [scope.value],
      project_id: project.value || null,
      expires_at: expiresDays.value
        ? new Date(Date.now() + Number(expiresDays.value) * 86_400_000).toISOString()
        : null,
    })
    issued.value = res.plain_token
    name.value = ''
    project.value = ''
    expiresDays.value = ''
    scope.value = ''
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

function dismissIssued(): void {
  issued.value = ''
  router.push('/tokens')
}

function cancel(): void {
  router.push('/tokens')
}
</script>

<template>
  <div>
    <UiPageHeader :title="t('tokens.issueToken')">
      <template #actions>
        <UiButton variant="ghost" size="sm" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiAlert v-if="issued" variant="success" class="issued-alert">
      <div class="issued-inner">
        <div>
          <strong>{{ t('tokens.copyNow') }}</strong>
          <div class="token-value">{{ issued }}</div>
        </div>
        <UiButton variant="ghost" size="sm" @click="dismissIssued">
          {{ t('tokens.dismiss') }}
        </UiButton>
      </div>
    </UiAlert>

    <UiCard v-if="!issued" variant="elevated" class="create-card">
      <div class="form-grid">
        <UiInput
          v-model="name"
          :label="t('tokens.name')"
          :placeholder="t('tokens.namePlaceholder')"
        />
        <UiInput
          v-model="project"
          mono
          :label="`${t('tokens.projectSlug')} ${t('tokens.projectBlankAll')}`"
          :placeholder="t('tokens.projectSlug')"
        />
        <UiSelect v-model="scope" :label="t('tokens.scope')" :placeholder="t('tokens.selectScope')">
          <option v-for="[value, label] in SCOPES" :key="value" :value="value">
            {{ t(`tokens.scopeDescriptions.${label}`) }} ({{ value }})
          </option>
        </UiSelect>
        <UiInput
          v-model="expiresDays"
          type="number"
          min="1"
          :label="`${t('tokens.expiresDays')} ${t('tokens.expiresBlankNever')}`"
        />
      </div>
      <div class="form-actions">
        <UiButton variant="secondary" @click="cancel">
          {{ t('common.cancel') }}
        </UiButton>
        <UiButton
          variant="primary"
          :loading="creating"
          :disabled="creating || !name || !scope"
          @click="create"
        >
          {{ creating ? t('tokens.issuing') : t('tokens.issueToken') }}
        </UiButton>
      </div>
    </UiCard>
  </div>
</template>

<style scoped>
.page-alert {
  margin-bottom: var(--space-4);
}

.issued-alert {
  margin-bottom: var(--space-4);
}

.issued-inner {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--space-4);
  width: 100%;
}

.token-value {
  margin-top: var(--space-2);
  font-family: var(--font-mono);
  font-size: 13px;
  overflow-wrap: anywhere;
  background: var(--surface);
  padding: var(--space-3);
  border-radius: var(--radius-md);
  border: 1px solid var(--border);
}

.create-card {
  max-width: 600px;
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