<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api, type Policy, type PolicyBinding } from '@/api/client'

const loading = ref(false)
const policies = ref<Policy[]>([])
const bindings = ref<PolicyBinding[]>([])

const showCreatePolicyModal = ref(false)
const showBindModal = ref(false)
const creating = ref(false)
const binding = ref(false)

const policyForm = ref({ name: '', rego_source: '' })
const policyFormError = ref('')

const bindForm = ref({ policy_id: '', project_id: '', env_id: '' })
const bindFormError = ref('')

const projectId = ref('')
const envId = ref('')

const regoPlaceholder = `package pandapass.authz

deny[msg] {
  input.env == "prod"
  input.role == "editor"
  input.action == "read_secret"
  msg := "Editors cannot read prod secrets"
}`

async function loadPolicies() {
  loading.value = true
  try {
    policies.value = await api.listPolicies(true)
  } catch (e: any) {
    console.error('Failed to load policies:', e)
  } finally {
    loading.value = false
  }
}

async function loadBindings() {
  try {
    bindings.value = await api.listPolicyBindings(projectId.value || undefined, envId.value || undefined)
  } catch (e: any) {
    console.error('Failed to load bindings:', e)
  }
}

async function handleCreatePolicy() {
  policyFormError.value = ''
  if (!policyForm.value.name.trim()) {
    policyFormError.value = 'Policy name is required'
    return
  }
  if (!policyForm.value.rego_source.trim()) {
    policyFormError.value = 'Rego source is required'
    return
  }

  creating.value = true
  try {
    await api.createPolicy(policyForm.value.name, policyForm.value.rego_source)
    showCreatePolicyModal.value = false
    policyForm.value = { name: '', rego_source: '' }
    await loadPolicies()
  } catch (e: any) {
    policyFormError.value = e.message ?? 'Failed to create policy'
  } finally {
    creating.value = false
  }
}

async function handleBindPolicy() {
  bindFormError.value = ''
  if (!bindForm.value.policy_id) {
    bindFormError.value = 'Select a policy'
    return
  }

  binding.value = true
  try {
    await api.bindPolicy(
      bindForm.value.policy_id,
      bindForm.value.project_id || undefined,
      bindForm.value.env_id || undefined
    )
    showBindModal.value = false
    bindForm.value = { policy_id: '', project_id: '', env_id: '' }
    await loadBindings()
  } catch (e: any) {
    bindFormError.value = e.message ?? 'Failed to bind policy'
  } finally {
    binding.value = false
  }
}

async function handleUnbind(id: string) {
  if (!confirm('Unbind this policy?')) return
  try {
    await api.unbindPolicy(id)
    await loadBindings()
  } catch (e: any) {
    console.error('Failed to unbind policy:', e)
  }
}

async function handleDeletePolicy(id: string) {
  if (!confirm('Delete this policy? This cannot be undone.')) return
  try {
    await api.deletePolicy(id)
    await loadPolicies()
  } catch (e: any) {
    console.error('Failed to delete policy:', e)
  }
}

async function handleTogglePolicy(p: Policy) {
  try {
    await api.updatePolicy(p.id, p.name, p.rego_source, !p.enabled)
    await loadPolicies()
  } catch (e: any) {
    console.error('Failed to update policy:', e)
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

onMounted(() => {
  loadPolicies()
  loadBindings()
})
</script>

<template>
  <div class="policies-view">
    <div class="spread" style="margin-bottom: 16px">
      <h2 style="margin: 0">Policies (OPA)</h2>
      <div class="row">
        <button class="primary" @click="showCreatePolicyModal = true">Create Policy</button>
        <button @click="showBindModal = true">Bind Policy</button>
      </div>
    </div>

    <div class="card" style="padding: 0">
      <div class="section-title">Policies</div>
      <table v-if="!loading">
        <thead>
          <tr>
            <th style="width: 200px">Name</th>
            <th style="width: 100px">Status</th>
            <th style="width: 180px">Created</th>
            <th style="width: 180px">Updated</th>
            <th>Rego Source</th>
            <th style="width: 150px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="p in policies" :key="p.id">
            <td><strong>{{ p.name }}</strong></td>
            <td>
              <span :class="p.enabled ? 'ok' : 'dim'">
                {{ p.enabled ? 'Enabled' : 'Disabled' }}
              </span>
            </td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(p.created_at) }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(p.updated_at) }}</td>
            <td class="mono dim" style="font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              {{ p.rego_source }}
            </td>
            <td>
              <div class="row" style="gap: 8px">
                <button
                  class="primary"
                  size="small"
                  @click="handleTogglePolicy(p)"
                >
                  {{ p.enabled ? 'Disable' : 'Enable' }}
                </button>
                <button class="danger" @click="handleDeletePolicy(p.id)">Delete</button>
              </div>
            </td>
          </tr>
          <tr v-if="!policies.length">
            <td colspan="6" class="dim">No policies yet.</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim" style="text-align: center; padding: 20px">Loading…</p>
    </div>

    <div class="card" style="padding: 0; margin-top: 16px">
      <div class="section-title">Policy Bindings</div>
      <table v-if="!loading">
        <thead>
          <tr>
            <th style="width: 200px">Policy</th>
            <th style="width: 200px">Project</th>
            <th style="width: 200px">Environment</th>
            <th style="width: 180px">Created</th>
            <th style="width: 100px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="b in bindings" :key="b.id">
            <td class="mono" style="font-size: 12px">
              {{ policies.find(x => x.id === b.policy_id)?.name ?? b.policy_id }}
            </td>
            <td class="mono dim" style="font-size: 12px">{{ b.project_id || '(global)' }}</td>
            <td class="mono dim" style="font-size: 12px">{{ b.env_id || '(all)' }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(b.created_at) }}</td>
            <td>
              <button class="danger" @click="handleUnbind(b.id)">Unbind</button>
            </td>
          </tr>
          <tr v-if="!bindings.length">
            <td colspan="5" class="dim">No bindings yet.</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim" style="text-align: center; padding: 20px">Loading…</p>
    </div>

    <!-- Create Policy Modal -->
    <div v-if="showCreatePolicyModal" class="modal-overlay" @click.self="showCreatePolicyModal = false">
      <div class="modal" style="width: 700px">
        <h3>Create Policy</h3>
        <div class="card">
          <label>
            Name
            <input v-model="policyForm.name" placeholder="e.g., deny-prod-read-for-editors" />
          </label>
          <label>
            Rego Source
            <textarea
              v-model="policyForm.rego_source"
              :placeholder="regoPlaceholder"
              rows="12"
              style="font-family: var(--mono); font-size: 13px; width: 100%"
            />
          </label>
        </div>
        <p v-if="policyFormError" class="error">{{ policyFormError }}</p>
        <div class="spread" style="margin-top: 16px; justify-content: flex-end">
          <button @click="showCreatePolicyModal = false">Cancel</button>
          <button class="primary" @click="handleCreatePolicy" :disabled="creating">
            {{ creating ? 'Creating…' : 'Create' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Bind Policy Modal -->
    <div v-if="showBindModal" class="modal-overlay" @click.self="showBindModal = false">
      <div class="modal" style="width: 500px">
        <h3>Bind Policy to Project/Environment</h3>
        <div class="card">
          <label>
            Policy
            <select v-model="bindForm.policy_id">
              <option value="" disabled>Select a policy</option>
              <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
          </label>
          <label>
            Project ID (optional)
            <input v-model="bindForm.project_id" placeholder="UUID or leave empty for global" />
          </label>
          <label>
            Environment ID (optional)
            <input v-model="bindForm.env_id" placeholder="UUID or leave empty for all" />
          </label>
        </div>
        <p v-if="bindFormError" class="error">{{ bindFormError }}</p>
        <div class="spread" style="margin-top: 16px; justify-content: flex-end">
          <button @click="showBindModal = false">Cancel</button>
          <button class="primary" @click="handleBindPolicy" :disabled="binding">
            {{ binding ? 'Binding…' : 'Bind' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.policies-view {
  padding: 16px;
}
.section-title {
  font-weight: 600;
  margin-bottom: 12px;
  font-size: 14px;
  color: var(--text-dim);
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
  max-height: 80vh;
  overflow: auto;
}
.modal h3 {
  margin: 0 0 16px;
}
</style>