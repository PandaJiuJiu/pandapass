<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, type AuditEntry } from '@/api/client'

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
        : 'Could not load the audit log. Reading it needs the read:audit scope or admin.'
  } finally {
    loading.value = false
  }
}

function next(): void {
  if (page.value * perPage < total.value) {
    page.value += 1
    refresh()
  }
}

function prev(): void {
  if (page.value > 1) {
    page.value -= 1
    refresh()
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <div class="spread" style="margin-bottom: 16px">
      <h1 style="font-size: 20px; margin: 0">Audit log</h1>
      <button @click="refresh">Refresh</button>
    </div>

    <p class="dim" style="font-size: 13px">
      Every read, write, and denial. Secret <em>values</em> are never recorded —
      only the key names and the outcome.
    </p>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <div v-else class="card" style="padding: 0">
      <table>
        <thead>
          <tr>
            <th style="width: 18%">When</th>
            <th style="width: 20%">Action</th>
            <th style="width: 20%">Key</th>
            <th style="width: 14%">Outcome</th>
            <th style="width: 28%">Detail</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="e in entries" :key="e.id">
            <td class="dim mono" style="font-size: 12px">
              {{ new Date(e.ts).toLocaleString() }}
            </td>
            <td class="mono" style="font-size: 12px">{{ e.action }}</td>
            <td class="mono" style="font-size: 12px">{{ e.secret_key ?? '—' }}</td>
            <td :style="{ color: outcomeColour(e.outcome), fontSize: '12px' }">
              {{ e.outcome }}
            </td>
            <td class="dim" style="font-size: 12px; overflow-wrap: anywhere">
              {{ e.meta ? JSON.stringify(e.meta) : '' }}
            </td>
          </tr>
          <tr v-if="!entries.length">
            <td colspan="5" class="dim">No entries.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="total > perPage" class="row" style="justify-content: center; margin-top: 12px">
      <button :disabled="page === 1" @click="prev">Newer</button>
      <span class="dim mono">
        page {{ page }} of {{ Math.ceil(total / perPage) }} · {{ total }} entries
      </span>
      <button :disabled="page * perPage >= total" @click="next">Older</button>
    </div>
  </div>
</template>
