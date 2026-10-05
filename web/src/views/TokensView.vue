<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, type ServiceToken } from '@/api/client'

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
const SCOPES = [
  ['read:secret', 'Read secret values'],
  ['list:secret', 'List secret names'],
  ['write:secret', 'Create, replace, and delete secrets'],
  ['read:audit', 'Read the audit log'],
  ['manage:project', 'Manage projects and members'],
]

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    tokens.value = await api.listTokens()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not load tokens'
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
    error.value = e instanceof ApiError ? e.message : 'Could not create token'
  } finally {
    creating.value = false
  }
}

async function revoke(t: ServiceToken): Promise<void> {
  if (!confirm(`Revoke "${t.name}"? Anything using it stops working immediately.`)) return
  error.value = ''
  try {
    await api.revokeToken(t.id)
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not revoke'
  }
}

function dismissIssued(): void {
  issued.value = ''
}

onMounted(refresh)
</script>

<template>
  <div>
    <h1 style="font-size: 20px; margin-top: 0">Service tokens</h1>
    <p class="dim" style="font-size: 13px">
      Tokens let CI and agents act without a password. Scope each one to the
      least it can do — a token that can write can rotate a production credential.
    </p>

    <p v-if="error" class="error">{{ error }}</p>

    <div v-if="issued" class="card" style="border-color: var(--accent)">
      <div class="spread" style="margin-bottom: 8px">
        <strong>Copy this now — it will not be shown again</strong>
        <button @click="dismissIssued">Dismiss</button>
      </div>
      <div class="mono" style="background: var(--bg); padding: 12px; border-radius: 6px; overflow-wrap: anywhere">
        {{ issued }}
      </div>
    </div>

    <div class="card" style="padding: 0">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th style="width: 30%">Scopes</th>
            <th style="width: 18%">Expires</th>
            <th style="width: 12%" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tokens" :key="t.id" :style="{ opacity: t.revoked_at ? 0.45 : 1 }">
            <td>
              {{ t.name }}
              <span v-if="t.revoked_at" class="dim" style="font-size: 12px">· revoked</span>
            </td>
            <td class="mono dim" style="font-size: 12px">{{ t.scopes.join(', ') }}</td>
            <td class="dim mono" style="font-size: 12px">
              {{ t.expires_at ? new Date(t.expires_at).toLocaleDateString() : 'never' }}
            </td>
            <td>
              <button
                v-if="!t.revoked_at"
                class="danger"
                style="float: right"
                @click="revoke(t)"
              >
                Revoke
              </button>
            </td>
          </tr>
          <tr v-if="!loading && !tokens.length">
            <td colspan="4" class="dim">No tokens yet.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <strong style="font-size: 14px">Issue a token</strong>
      <div style="margin-top: 12px">
        <div class="row">
          <label style="flex: 1">
            Name
            <input v-model="name" placeholder="ci-deploy" />
          </label>
          <label style="flex: 1">
            Project slug <span class="dim">(blank = all)</span>
            <input v-model="project" class="mono" placeholder="my-app" />
          </label>
        </div>
        <div class="row">
          <label style="flex: 1">
            Scope
            <select v-model="scope">
              <option value="" disabled>Select a scope…</option>
              <option v-for="[value, label] in SCOPES" :key="value" :value="value">
                {{ label }} ({{ value }})
              </option>
            </select>
          </label>
          <label style="flex: 0 0 160px">
            Expires in days <span class="dim">(blank = never)</span>
            <input v-model="expiresDays" type="number" min="1" />
          </label>
        </div>
        <button class="primary" :disabled="creating || !name || !scope" @click="create">
          {{ creating ? 'Issuing…' : 'Issue token' }}
        </button>
      </div>
    </div>
  </div>
</template>
