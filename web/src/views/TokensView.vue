<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type ServiceToken } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const router = useRouter()
const { t } = useI18n()

const tokens = ref<ServiceToken[]>([])
const loading = ref(true)
const error = ref('')
const issued = ref('')

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

function newToken(): void {
  router.push('/tokens/new')
}

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="t('tokens.title')" :description="t('tokens.subtitle')">
      <template #actions>
        <UiButton variant="primary" size="sm" @click="newToken">
          {{ t('tokens.issueToken') }}
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
</style>