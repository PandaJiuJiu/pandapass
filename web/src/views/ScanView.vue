<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type ScanFinding, type ScanRunResult } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiAlert from '@/components/ui/UiAlert.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiPagination from '@/components/ui/UiPagination.vue'
import UiBadge from '@/components/ui/UiBadge.vue'

const { t } = useI18n()

const findings = ref<ScanFinding[]>([])
const loading = ref(true)
const scanning = ref(false)
const error = ref('')
const lastRun = ref<ScanRunResult | null>(null)

const page = ref(1)
const total = ref(0)
const perPage = 50

/**
 * Refuse to render an unknown severity as if it were low-risk. A scan UI that
 * silently downgrades an unrecognised severity is worse than one that shows
 * it raw.
 */
function severityColour(s: ScanFinding['severity']): string {
  switch (s) {
    case 'high':
      return 'var(--danger)'
    case 'medium':
      return 'var(--warn)'
    case 'low':
      return 'var(--ok)'
    default:
      return 'var(--text-dim)'
  }
}

function severityBadge(s: ScanFinding['severity']): 'danger' | 'warn' | 'ok' | 'dim' {
  switch (s) {
    case 'high':
      return 'danger'
    case 'medium':
      return 'warn'
    case 'low':
      return 'ok'
    default:
      return 'dim'
  }
}

async function runScan(): Promise<void> {
  scanning.value = true
  error.value = ''
  try {
    lastRun.value = await api.triggerScan()
    page.value = 1
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.scanFailed')
  } finally {
    scanning.value = false
  }
}

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.getScanResults(undefined, undefined, page.value, perPage)
    findings.value = res.items
    total.value = res.total
  } catch (e) {
    error.value =
      e instanceof ApiError ? e.message : t('common.loadFailed')
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
    <UiPageHeader :title="t('scan.title')" :description="t('scan.subtitle')">
      <template #actions>
        <UiButton variant="primary" size="sm" :loading="scanning" :disabled="scanning" @click="runScan">
          {{ scanning ? t('scan.scanning') : t('scan.runScan') }}
        </UiButton>
        <UiButton variant="ghost" size="sm" :disabled="loading" @click="refresh">
          {{ t('scan.refresh') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <p v-if="lastRun" class="last-run dim">
      {{ t('scan.lastRun') }}: {{ lastRun.secrets_scanned }} {{ t('scan.secretsScanned') }},
      {{ lastRun.findings }} {{ t('scan.findingsCount') }}
      {{ t('scan.across') }} {{ lastRun.projects }} {{ t('scan.projects') }}
      / {{ lastRun.envs }} {{ t('scan.envs') }}
      <template v-if="lastRun.errors">
        · {{ lastRun.errors }} {{ t('scan.skipped') }}
      </template>
      .
    </p>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="outlined" padding>
      <UiTable
        :loading="loading"
        :empty="!findings.length"
        :empty-text="t('scan.noFindings')"
        :colspan="6"
      >
        <template #head>
          <tr>
            <th style="width: 16%">{{ t('scan.projectEnv') }}</th>
            <th style="width: 18%">{{ t('scan.secretKey') }}</th>
            <th style="width: 20%">{{ t('scan.rule') }}</th>
            <th style="width: 10%">{{ t('scan.severity') }}</th>
            <th style="width: 14%">{{ t('scan.position') }}</th>
            <th style="width: 22%">{{ t('scan.detected') }}</th>
          </tr>
        </template>

        <tr v-for="f in findings" :key="f.id">
          <td class="mono dim small" style="overflow-wrap: anywhere">
            {{ f.project_id }} / {{ f.env_id }}
          </td>
          <td class="mono small">{{ f.secret_key }}</td>
          <td class="mono small">
            {{ f.rule_id }}
            <span class="dim">({{ f.rule_name }})</span>
          </td>
          <td :style="{ color: severityColour(f.severity) }" class="small">
            <UiBadge :variant="severityBadge(f.severity)">{{ f.severity }}</UiBadge>
          </td>
          <td class="mono dim small">
            [{{ f.match_start }}, {{ f.match_end }})
          </td>
          <td class="dim mono small">
            {{ new Date(f.detected_at).toLocaleString() }}
          </td>
        </tr>
      </UiTable>

      <UiPagination
        :page="page"
        :total="total"
        :per-page="perPage"
        :newer-label="t('scan.newer')"
        :older-label="t('scan.older')"
        :page-label="t('scan.page')"
        :of-label="t('scan.of')"
        :entries-label="t('scan.findings')"
        @change="goToPage"
      />
    </UiCard>
  </div>
</template>

<style scoped>
.last-run {
  font-size: 13px;
  margin: 0 0 var(--space-4);
}

.page-alert {
  margin-bottom: var(--space-4);
}

.small {
  font-size: 12px;
}
</style>