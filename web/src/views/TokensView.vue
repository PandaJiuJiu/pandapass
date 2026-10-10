<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type ServiceToken } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiSelect from '@/components/ui/UiSelect.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiAlert from '@/components/ui/UiAlert.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'

const { t } = useI18n()

const tokens = ref<ServiceToken[]>([])
const loading = ref(true)
const error = ref('')

const name = ref('')
const scope = ref('')
const project = ref('')
const expiresDays = ref('')
const creating = ref(false)

/** The plaintext token, shown exactly once. Never stored anywhere. */
const issued = ref('')

/**
 * The complete set, and what each may do. Listed here so the choice is made
 * deliberately — the default here is read-only because a token that can write
 * can rotate a production credential, and that is not what a CI job usually
 * needs.
 */
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

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    tokens.value = await api.listTokens()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

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
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

async function revoke(tok: ServiceToken): Promise<void> {
  if (!confirm(t('tokens.revokeConfirm', { name: tok.name }))) return
  error.value = ''
  try {
    await api.revokeToken(tok.id)
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.revokeFailed')
  }
}

function dismissIssued(): void {
  issued.value = ''
}

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="t('tokens.title')" :description="t('tokens.subtitle')" />

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

    <UiCard variant="outlined" padding>
      <UiTable
        :loading="loading"
        :empty="!tokens.length"
        :empty-text="t('tokens.noTokens')"
        :colspan="4"
      >
        <template #head>
          <tr>
            <th>{{ t('tokens.tokenName') }}</th>
            <th style="width: 30%">{{ t('tokens.scopes') }}</th>
            <th style="width: 18%">{{ t('tokens.expires') }}</th>
            <th style="width: 12%" />
          </tr>
        </template>

        <tr v-for="tok in tokens" :key="tok.id" :class="{ revoked: tok.revoked_at }">
          <td>
            <span class="token-name">{{ tok.name }}</span>
            <span v-if="tok.revoked_at" class="revoked-tag">· {{ t('tokens.revokedTag') }}</span>
          </td>
          <td>
            <code class="mono dim small">{{ tok.scopes.join(', ') }}</code>
          </td>
          <td class="dim mono small">
            {{ tok.expires_at ? new Date(tok.expires_at).toLocaleDateString() : t('common.never') }}
          </td>
          <td>
            <UiButton
              v-if="!tok.revoked_at"
              size="sm"
              variant="danger"
              class="float-right"
              @click="revoke(tok)"
            >
              {{ t('common.revoke') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- Issue a token -->
    <UiCard variant="elevated" class="issue-card">
      <h2 class="section-title">{{ t('tokens.issueToken') }}</h2>
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
      <UiButton
        variant="primary"
        :loading="creating"
        :disabled="creating || !name || !scope"
        @click="create"
      >
        {{ creating ? t('tokens.issuing') : t('tokens.issueToken') }}
      </UiButton>
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

.revoked {
  opacity: 0.45;
}

.token-name {
  font-weight: 500;
}

.revoked-tag {
  font-size: 12px;
  color: var(--text-dim);
}

.small {
  font-size: 12px;
}

.float-right {
  float: right;
}

.section-title {
  margin: 0 0 var(--space-4);
  font-size: 15px;
  font-weight: 600;
}

.issue-card {
  margin-top: var(--space-6);
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
}
</style>