<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type AuditEntry } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiAlert from '@/components/ui/UiAlert.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiPagination from '@/components/ui/UiPagination.vue'

const { t } = useI18n()
const entries = ref<AuditEntry[]>([])
const loading = ref(true)
const error = ref('')
const page = ref(1)
const total = ref(0)
const perPage = 50

/**
 * Refuse to render an unknown outcome as success. An audit log that silently
 * colours an unrecognised status green is worse than one that shows it raw.
 */
function outcomeColour(o: AuditEntry['outcome']): string {
  switch (o) {
    case 'success':
      return 'var(--ok)'
    case 'denied':
      return 'var(--danger)'
    case 'failure':
    case 'error':
      return 'var(--warn)'
    default:
      return 'var(--text-dim)'
  }
}

function outcomeBadge(o: AuditEntry['outcome']): 'ok' | 'danger' | 'warn' | 'dim' {
  switch (o) {
    case 'success':
      return 'ok'
    case 'denied':
      return 'danger'
    case 'failure':
    case 'error':
      return 'warn'
    default:
      return 'dim'
  }
}

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.listAudit(undefined, page.value, perPage)
    entries.value = res.items
    total.value = res.total
  } catch (e) {
    error.value =
      e instanceof ApiError
        ? e.message
        : t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

function goToPage(p: number): void {
  page.value = p
  refresh()
}

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="t('audit.title')" :description="t('audit.subtitle')">
      <template #actions>
        <UiButton variant="ghost" size="sm" @click="refresh">
          {{ t('audit.refresh') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="outlined" padding>
      <UiTable
        :loading="loading"
        :empty="!entries.length"
        :empty-text="t('audit.noEntries')"
        :colspan="5"
      >
        <template #head>
          <tr>
            <th style="width: 18%">{{ t('audit.when') }}</th>
            <th style="width: 20%">{{ t('audit.action') }}</th>
            <th style="width: 20%">{{ t('audit.key') }}</th>
            <th style="width: 14%">{{ t('audit.outcome') }}</th>
            <th style="width: 28%">{{ t('audit.detail') }}</th>
          </tr>
        </template>

        <tr v-for="e in entries" :key="e.id">
          <td class="dim mono small">
            {{ new Date(e.ts).toLocaleString() }}
          </td>
          <td class="mono small">{{ e.action }}</td>
          <td class="mono small">{{ e.secret_key ?? '—' }}</td>
          <td :style="{ color: outcomeColour(e.outcome) }" class="small">
            <UiBadge :variant="outcomeBadge(e.outcome)">
              {{ e.outcome }}
            </UiBadge>
          </td>
          <td class="dim small" style="overflow-wrap: anywhere">
            {{ e.meta ? JSON.stringify(e.meta) : '' }}
          </td>
        </tr>
      </UiTable>

      <UiPagination
        :page="page"
        :total="total"
        :per-page="perPage"
        :newer-label="t('audit.newer')"
        :older-label="t('audit.older')"
        :page-label="t('audit.page')"
        :of-label="t('audit.of')"
        :entries-label="t('audit.entries')"
        @change="goToPage"
      />
    </UiCard>
  </div>
</template>

<style scoped>
.page-alert {
  margin-bottom: var(--space-4);
}

.small {
  font-size: 12px;
}
</style>