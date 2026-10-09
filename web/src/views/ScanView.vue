<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, type ScanFinding, type ScanRunResult } from '@/api/client'

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

async function runScan(): Promise<void> {
  scanning.value = true
  error.value = ''
  try {
    lastRun.value = await api.triggerScan()
    page.value = 1
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Scan failed'
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
      e instanceof ApiError ? e.message : 'Could not load scan results. This view needs admin.'
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
      <h1 style="font-size: 20px; margin: 0">Secret scan</h1>
      <div class="row" style="gap: 8px">
        <button :disabled="scanning" @click="runScan">
          {{ scanning ? 'Scanning…' : 'Run scan' }}
        </button>
        <button :disabled="loading" @click="refresh">Refresh</button>
      </div>
    </div>

    <p class="dim" style="font-size: 13px">
      Detects known secret formats (AWS keys, GitHub tokens, JWTs, private keys, …) inside
      decrypted secret values. Findings store the secret <em>key name</em> and match offsets —
      never the plaintext itself.
    </p>

    <p v-if="lastRun" class="dim" style="font-size: 13px">
      Last run: {{ lastRun.secrets_scanned }} secrets scanned, {{ lastRun.findings }} findings
      across {{ lastRun.projects }} project(s) / {{ lastRun.envs }} env(s)
      <template v-if="lastRun.errors"> · {{ lastRun.errors }} skipped (no server-sealed key)</template>.
    </p>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <div v-else class="card" style="padding: 0">
      <table>
        <thead>
          <tr>
            <th style="width: 16%">Project / env</th>
            <th style="width: 18%">Secret key</th>
            <th style="width: 20%">Rule</th>
            <th style="width: 10%">Severity</th>
            <th style="width: 14%">Position</th>
            <th style="width: 22%">Detected</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="f in findings" :key="f.id">
            <td class="mono dim" style="font-size: 12px; overflow-wrap: anywhere">
              {{ f.project_id }} / {{ f.env_id }}
            </td>
            <td class="mono" style="font-size: 12px">{{ f.secret_key }}</td>
            <td class="mono" style="font-size: 12px">
              {{ f.rule_id }}
              <span class="dim">({{ f.rule_name }})</span>
            </td>
            <td :style="{ color: severityColour(f.severity), fontSize: '12px' }">
              {{ f.severity }}
            </td>
            <td class="mono dim" style="font-size: 12px">
              [{{ f.match_start }}, {{ f.match_end }})
            </td>
            <td class="dim mono" style="font-size: 12px">
              {{ new Date(f.detected_at).toLocaleString() }}
            </td>
          </tr>
          <tr v-if="!findings.length">
            <td colspan="6" class="dim">No findings. Run a scan to check your vault.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div v-if="total > perPage" class="row" style="justify-content: center; margin-top: 12px">
      <button :disabled="page === 1" @click="prev">Newer</button>
      <span class="dim mono">
        page {{ page }} of {{ Math.ceil(total / perPage) }} · {{ total }} findings
      </span>
      <button :disabled="page * perPage >= total" @click="next">Older</button>
    </div>
  </div>
</template>