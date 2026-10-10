<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, type DynamicCred, type CreateDynamicCredRequest } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiSelect from '@/components/ui/UiSelect.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiBadge from '@/components/ui/UiBadge.vue'
import UiModal from '@/components/ui/UiModal.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'

const route = useRoute()
const { t } = useI18n()

const loading = ref(false)
const creds = ref<DynamicCred[]>([])
const showCreateModal = ref(false)
const creating = ref(false)
const form = ref<CreateDynamicCredRequest>({
  kind: 'postgres',
  username: '',
  ttl_seconds: 3600,
})
const formError = ref('')

const kindOptions = ['postgresql', 'mysql', 'redis'] as const

async function loadCreds() {
  if (!route.params.slug) return
  loading.value = true
  try {
    const projectSlug = route.params.slug as string
    const envSlug = 'prod' // TODO: support env selection
    creds.value = await api.listDynamicCreds(projectSlug, envSlug)
  } catch (e: any) {
    console.error('Failed to load dynamic creds:', e)
  } finally {
    loading.value = false
  }
}

async function handleCreate() {
  formError.value = ''
  if (!form.value.username.trim()) {
    formError.value = t('dynamicCreds.usernameRequired')
    return
  }
  if (form.value.ttl_seconds < 60) {
    formError.value = t('dynamicCreds.ttlTooShort')
    return
  }

  creating.value = true
  try {
    const projectSlug = route.params.slug as string
    const envSlug = 'prod'
    await api.createDynamicCred(projectSlug, envSlug, form.value)
    showCreateModal.value = false
    form.value = { kind: 'postgres', username: '', ttl_seconds: 3600 }
    await loadCreds()
  } catch (e: any) {
    formError.value = e.message ?? t('dynamicCreds.createFailed')
  } finally {
    creating.value = false
  }
}

async function handleRevoke(id: string) {
  if (!confirm(t('dynamicCreds.revokeConfirm'))) return
  try {
    const projectSlug = route.params.slug as string
    const envSlug = 'prod'
    await api.revokeDynamicCred(projectSlug, envSlug, id)
    await loadCreds()
  } catch (e: any) {
    console.error('Failed to revoke credential:', e)
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

function isExpired(expiresAt: string) {
  return new Date(expiresAt) < new Date()
}

function isRevoked(revokedAt: string | null) {
  return revokedAt !== null
}

function credStatus(c: DynamicCred): 'ok' | 'danger' | 'warn' {
  if (isRevoked(c.revoked_at)) return 'danger'
  if (isExpired(c.expires_at)) return 'warn'
  return 'ok'
}

onMounted(() => loadCreds())
watch(() => route.params.slug, loadCreds)
</script>

<template>
  <div>
    <UiPageHeader :title="t('dynamicCreds.title')">
      <template #actions>
        <UiButton variant="primary" size="sm" :disabled="!route.params.slug" @click="showCreateModal = true">
          {{ t('dynamicCreds.issueCredential') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiCard variant="outlined" padding>
      <UiTable :loading="loading" :empty="!creds.length" :empty-text="t('dynamicCreds.noCreds')" :colspan="8">
        <template #head>
          <tr>
            <th style="width: 90px">{{ t('dynamicCreds.kind') }}</th>
            <th style="width: 140px">{{ t('dynamicCreds.username') }}</th>
            <th style="width: 70px">{{ t('dynamicCreds.ttl') }}</th>
            <th style="width: 170px">{{ t('dynamicCreds.issued') }}</th>
            <th style="width: 170px">{{ t('dynamicCreds.expires') }}</th>
            <th style="width: 90px">{{ t('dynamicCreds.status') }}</th>
            <th style="width: 140px">{{ t('dynamicCreds.createdBy') }}</th>
            <th style="width: 90px">{{ t('dynamicCreds.actions') }}</th>
          </tr>
        </template>

        <tr v-for="c in creds" :key="c.id" :class="{ faded: isRevoked(c.revoked_at) || isExpired(c.expires_at) }">
          <td>
            <span class="mono" :class="{ dim: isRevoked(c.revoked_at) || isExpired(c.expires_at) }">
              {{ c.kind.toUpperCase() }}
            </span>
          </td>
          <td class="mono">{{ c.username }}</td>
          <td class="mono">{{ Math.floor(c.ttl_seconds / 60) }}m</td>
          <td class="dim mono small">{{ formatDate(c.issued_at) }}</td>
          <td :class="{ 'dim': !isExpired(c.expires_at), 'warn': isExpired(c.expires_at) }" class="mono small">
            {{ formatDate(c.expires_at) }}
            <span v-if="isExpired(c.expires_at)" class="expired-tag">({{ t('dynamicCreds.expired') }})</span>
          </td>
          <td>
            <UiBadge :variant="credStatus(c)" :dot="true">
              {{ isRevoked(c.revoked_at) ? t('dynamicCreds.revoked') : isExpired(c.expires_at) ? t('dynamicCreds.expired') : t('dynamicCreds.active') }}
            </UiBadge>
          </td>
          <td class="dim mono small">{{ c.created_by }}</td>
          <td>
            <UiButton
              v-if="!isRevoked(c.revoked_at) && !isExpired(c.expires_at)"
              size="sm"
              variant="danger"
              @click="handleRevoke(c.id)"
            >
              {{ t('dynamicCreds.revoke') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- Create Modal -->
    <UiModal :open="showCreateModal" :title="t('dynamicCreds.issueTitle')" size="md" @close="showCreateModal = false">
      <UiSelect v-model="form.kind" :label="t('dynamicCreds.type')">
        <option v-for="k in kindOptions" :key="k" :value="k">{{ k.toUpperCase() }}</option>
      </UiSelect>
      <UiInput
        v-model="form.username"
        :label="t('dynamicCreds.usernameLabel')"
        :placeholder="t('dynamicCreds.usernamePlaceholder')"
      />
      <UiInput
        v-model.number="form.ttl_seconds"
        type="number"
        min="60"
        :label="t('dynamicCreds.ttlSeconds')"
        :placeholder="t('dynamicCreds.ttlPlaceholder')"
      />
      <p v-if="formError" class="error">{{ formError }}</p>
      <template #footer>
        <UiButton variant="secondary" @click="showCreateModal = false">
          {{ t('dynamicCreds.cancel') }}
        </UiButton>
        <UiButton variant="primary" :loading="creating" :disabled="creating" @click="handleCreate">
          {{ creating ? t('dynamicCreds.issuing') : t('dynamicCreds.issue') }}
        </UiButton>
      </template>
    </UiModal>
  </div>
</template>

<style scoped>
.faded {
  opacity: 0.45;
}

.small {
  font-size: 12px;
}

.expired-tag {
  margin-left: 6px;
  font-size: 11px;
}
</style>