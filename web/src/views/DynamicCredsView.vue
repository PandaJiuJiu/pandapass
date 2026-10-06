<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute } from 'vue-router'
import { api, type DynamicCred, type CreateDynamicCredRequest } from '@/api/client'

const route = useRoute()

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
    formError.value = 'Username is required'
    return
  }
  if (form.value.ttl_seconds < 60) {
    formError.value = 'TTL must be at least 60 seconds'
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
    formError.value = e.message ?? 'Failed to create credential'
  } finally {
    creating.value = false
  }
}

async function handleRevoke(id: string) {
  if (!confirm('Revoke this credential? Anything using it stops working immediately.')) return
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

onMounted(() => loadCreds())
watch(() => route.params.slug, loadCreds)
</script>

<template>
  <div class="dynamic-creds-view">
    <div class="spread" style="margin-bottom: 16px">
      <h2 style="margin: 0">Dynamic Credentials</h2>
      <button class="primary" @click="showCreateModal = true" :disabled="!route.params.slug">
        Issue Credential
      </button>
    </div>

    <div class="card" style="padding: 0">
      <table v-if="!loading">
        <thead>
          <tr>
            <th style="width: 100px">Kind</th>
            <th style="width: 150px">Username</th>
            <th style="width: 80px">TTL</th>
            <th style="width: 180px">Issued</th>
            <th style="width: 180px">Expires</th>
            <th style="width: 100px">Status</th>
            <th style="width: 150px">Created By</th>
            <th style="width: 100px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in creds" :key="c.id" :style="{ opacity: isRevoked(c.revoked_at) || isExpired(c.expires_at) ? 0.45 : 1 }">
            <td>
              <span class="mono" :class="{ 'dim': isRevoked(c.revoked_at) || isExpired(c.expires_at) }">
                {{ c.kind.toUpperCase() }}
              </span>
            </td>
            <td class="mono">{{ c.username }}</td>
            <td class="mono">{{ Math.floor(c.ttl_seconds / 60) }}m</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(c.issued_at) }}</td>
            <td :class="{ 'dim': !isExpired(c.expires_at), 'error': isExpired(c.expires_at) }" class="mono" style="font-size: 12px">
              {{ formatDate(c.expires_at) }}
              <span v-if="isExpired(c.expires_at)" style="margin-left: 8px; font-size: 11px">(expired)</span>
            </td>
            <td>
              <span v-if="isRevoked(c.revoked_at)" class="error">Revoked</span>
              <span v-else-if="isExpired(c.expires_at)" class="warn">Expired</span>
              <span v-else class="ok">Active</span>
            </td>
            <td class="dim mono" style="font-size: 12px">{{ c.created_by }}</td>
            <td>
              <button
                v-if="!isRevoked(c.revoked_at) && !isExpired(c.expires_at)"
                class="danger"
                @click="handleRevoke(c.id)"
              >
                Revoke
              </button>
            </td>
          </tr>
          <tr v-if="!creds.length">
            <td colspan="8" class="dim">No dynamic credentials issued yet.</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim" style="text-align: center; padding: 20px">Loading…</p>
    </div>

    <!-- Create Modal -->
    <div v-if="showCreateModal" class="modal-overlay" @click.self="showCreateModal = false">
      <div class="modal">
        <h3>Issue Dynamic Credential</h3>
        <div class="card">
          <label>
            Type
            <select v-model="form.kind">
              <option v-for="k in kindOptions" :key="k" :value="k">{{ k.toUpperCase() }}</option>
            </select>
          </label>
          <label>
            Username
            <input v-model="form.username" placeholder="Database username" />
          </label>
          <label>
            TTL (seconds)
            <input v-model.number="form.ttl_seconds" type="number" placeholder="3600" min="60" />
          </label>
        </div>
        <p v-if="formError" class="error">{{ formError }}</p>
        <div class="spread" style="margin-top: 16px; justify-content: flex-end">
          <button @click="showCreateModal = false">Cancel</button>
          <button class="primary" @click="handleCreate" :disabled="creating">
            {{ creating ? 'Issuing…' : 'Issue' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.dynamic-creds-view {
  padding: 16px;
}
.modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.6);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}
.modal {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 24px;
  width: 480px;
  max-height: 80vh;
  overflow: auto;
}
.modal h3 {
  margin: 0 0 16px;
}
</style>