<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, type Policy, type PolicyBinding } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiTextarea from '@/components/ui/UiTextarea.vue'
import UiSelect from '@/components/ui/UiSelect.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiBadge from '@/components/ui/UiBadge.vue'
import UiModal from '@/components/ui/UiModal.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'

const { t } = useI18n()

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
    policyFormError.value = t('policies.policyNameRequired')
    return
  }
  if (!policyForm.value.rego_source.trim()) {
    policyFormError.value = t('policies.regoSourceRequired')
    return
  }

  creating.value = true
  try {
    await api.createPolicy(policyForm.value.name, policyForm.value.rego_source)
    showCreatePolicyModal.value = false
    policyForm.value = { name: '', rego_source: '' }
    await loadPolicies()
  } catch (e: any) {
    policyFormError.value = e.message ?? t('policies.createFailed')
  } finally {
    creating.value = false
  }
}

async function handleBindPolicy() {
  bindFormError.value = ''
  if (!bindForm.value.policy_id) {
    bindFormError.value = t('policies.selectPolicyRequired')
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
    bindFormError.value = e.message ?? t('policies.bindFailed')
  } finally {
    binding.value = false
  }
}

async function handleUnbind(id: string) {
  if (!confirm(t('policies.unbindConfirm'))) return
  try {
    await api.unbindPolicy(id)
    await loadBindings()
  } catch (e: any) {
    console.error('Failed to unbind policy:', e)
  }
}

async function handleDeletePolicy(id: string) {
  if (!confirm(t('policies.deleteConfirm'))) return
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
  <div>
    <UiPageHeader :title="t('policies.title')">
      <template #actions>
        <UiButton variant="primary" size="sm" @click="showCreatePolicyModal = true">
          {{ t('policies.createPolicy') }}
        </UiButton>
        <UiButton variant="secondary" size="sm" @click="showBindModal = true">
          {{ t('policies.bindPolicy') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <!-- Policies table -->
    <UiCard variant="outlined" padding>
      <h2 class="section-title">{{ t('policies.policies') }}</h2>
      <UiTable :loading="loading" :empty="!policies.length" :empty-text="t('policies.noPolicies')" :colspan="6">
        <template #head>
          <tr>
            <th style="width: 180px">{{ t('policies.name') }}</th>
            <th style="width: 90px">{{ t('policies.status') }}</th>
            <th style="width: 170px">{{ t('policies.created') }}</th>
            <th style="width: 170px">{{ t('policies.updated') }}</th>
            <th>{{ t('policies.regoSource') }}</th>
            <th style="width: 150px">{{ t('policies.actions') }}</th>
          </tr>
        </template>

        <tr v-for="p in policies" :key="p.id">
          <td><strong>{{ p.name }}</strong></td>
          <td>
            <UiBadge :variant="p.enabled ? 'ok' : 'dim'" :dot="true">
              {{ p.enabled ? t('policies.enabled') : t('policies.disabled') }}
            </UiBadge>
          </td>
          <td class="dim mono small">{{ formatDate(p.created_at) }}</td>
          <td class="dim mono small">{{ formatDate(p.updated_at) }}</td>
          <td class="mono dim rego-cell">{{ p.rego_source }}</td>
          <td>
            <div class="row actions">
              <UiButton size="sm" :variant="p.enabled ? 'secondary' : 'primary'" @click="handleTogglePolicy(p)">
                {{ p.enabled ? t('policies.toggleDisable') : t('policies.toggleEnable') }}
              </UiButton>
              <UiButton size="sm" variant="danger" @click="handleDeletePolicy(p.id)">
                {{ t('policies.delete') }}
              </UiButton>
            </div>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- Policy bindings -->
    <UiCard variant="outlined" padding class="bindings-card">
      <h2 class="section-title">{{ t('policies.policyBindings') }}</h2>
      <UiTable :loading="loading" :empty="!bindings.length" :empty-text="t('policies.noBindings')" :colspan="5">
        <template #head>
          <tr>
            <th style="width: 180px">{{ t('policies.policy') }}</th>
            <th style="width: 180px">{{ t('policies.project') }}</th>
            <th style="width: 180px">{{ t('policies.environment') }}</th>
            <th style="width: 170px">{{ t('policies.createdCol') }}</th>
            <th style="width: 100px">{{ t('policies.actions') }}</th>
          </tr>
        </template>

        <tr v-for="b in bindings" :key="b.id">
          <td class="mono small">
            {{ policies.find(x => x.id === b.policy_id)?.name ?? b.policy_id }}
          </td>
          <td class="mono dim small">{{ b.project_id || t('policies.global') }}</td>
          <td class="mono dim small">{{ b.env_id || t('policies.all') }}</td>
          <td class="dim mono small">{{ formatDate(b.created_at) }}</td>
          <td>
            <UiButton size="sm" variant="danger" @click="handleUnbind(b.id)">
              {{ t('policies.unbind') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- Create Policy Modal -->
    <UiModal :open="showCreatePolicyModal" :title="t('policies.createTitle')" size="lg" @close="showCreatePolicyModal = false">
      <UiInput
        v-model="policyForm.name"
        :label="t('policies.policyName')"
        :placeholder="t('policies.policyNamePlaceholder')"
      />
      <UiTextarea
        v-model="policyForm.rego_source"
        :label="t('policies.regoSourceLabel')"
        :placeholder="regoPlaceholder"
        :rows="12"
        mono
      />
      <p v-if="policyFormError" class="error">{{ policyFormError }}</p>
      <template #footer>
        <UiButton variant="secondary" @click="showCreatePolicyModal = false">
          {{ t('policies.cancel') }}
        </UiButton>
        <UiButton variant="primary" :loading="creating" :disabled="creating" @click="handleCreatePolicy">
          {{ creating ? t('policies.creating') : t('policies.create') }}
        </UiButton>
      </template>
    </UiModal>

    <!-- Bind Policy Modal -->
    <UiModal :open="showBindModal" :title="t('policies.bindTitle')" size="md" @close="showBindModal = false">
      <UiSelect v-model="bindForm.policy_id" :label="t('policies.policy')" :placeholder="t('policies.selectPolicy')">
        <option v-for="p in policies" :key="p.id" :value="p.id">{{ p.name }}</option>
      </UiSelect>
      <UiInput
        v-model="bindForm.project_id"
        mono
        :label="t('policies.projectId')"
        :placeholder="t('policies.projectIdPlaceholder')"
      />
      <UiInput
        v-model="bindForm.env_id"
        mono
        :label="t('policies.envId')"
        :placeholder="t('policies.envIdPlaceholder')"
      />
      <p v-if="bindFormError" class="error">{{ bindFormError }}</p>
      <template #footer>
        <UiButton variant="secondary" @click="showBindModal = false">
          {{ t('policies.cancel') }}
        </UiButton>
        <UiButton variant="primary" :loading="binding" :disabled="binding" @click="handleBindPolicy">
          {{ binding ? t('policies.binding') : t('policies.bind') }}
        </UiButton>
      </template>
    </UiModal>
  </div>
</template>

<style scoped>
.section-title {
  margin: 0 0 var(--space-3);
  font-size: 15px;
  font-weight: 600;
}

.bindings-card {
  margin-top: var(--space-4);
}

.rego-cell {
  font-size: 11px;
  max-width: 300px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.actions {
  gap: var(--space-2);
}
</style>