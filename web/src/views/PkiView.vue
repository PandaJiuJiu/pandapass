<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, type CaKey, type SshCert, type CaKeyType, type SshKeyType } from '@/api/client'
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
const caKeys = ref<CaKey[]>([])
const sshCerts = ref<SshCert[]>([])

const showCreateCaModal = ref(false)
const showCreateSshCertModal = ref(false)
const creating = ref(false)

const caForm = ref({
  kind: 'intermediate' as CaKeyType,
  key_pem: '',
  cert_pem: '',
  not_before: '',
  not_after: '',
})
const caFormError = ref('')

const sshForm = ref({
  user_id: '',
  project_id: '',
  principal: '',
  cert_pem: '',
  key_type: 'ed25519' as SshKeyType,
  valid_before: '',
  valid_after: '',
})
const sshFormError = ref('')

async function loadCaKeys() {
  loading.value = true
  try {
    caKeys.value = await api.listCaKeys(true)
  } catch (e: any) {
    console.error('Failed to load CA keys:', e)
  } finally {
    loading.value = false
  }
}

async function loadSshCerts() {
  try {
    sshCerts.value = await api.listSshCerts(undefined, undefined, true)
  } catch (e: any) {
    console.error('Failed to load SSH certs:', e)
  }
}

async function handleCreateCa() {
  caFormError.value = ''
  if (!caForm.value.key_pem.trim() || !caForm.value.cert_pem.trim()) {
    caFormError.value = t('pki.caRequired')
    return
  }
  creating.value = true
  try {
    await api.createCaKey(
      caForm.value.kind,
      caForm.value.key_pem,
      caForm.value.cert_pem,
      caForm.value.not_before || new Date().toISOString(),
      caForm.value.not_after || new Date(Date.now() + 365 * 86_400_000).toISOString(),
    )
    showCreateCaModal.value = false
    caForm.value = { kind: 'intermediate', key_pem: '', cert_pem: '', not_before: '', not_after: '' }
    await loadCaKeys()
  } catch (e: any) {
    caFormError.value = e.message ?? t('pki.caCreateFailed')
  } finally {
    creating.value = false
  }
}

async function handleRevokeCa(id: string) {
  if (!confirm(t('pki.revokeConfirm'))) return
  try {
    await api.revokeCaKey(id)
    await loadCaKeys()
  } catch (e: any) {
    console.error('Failed to revoke CA:', e)
  }
}

async function handleCreateSshCert() {
  sshFormError.value = ''
  if (!sshForm.value.principal.trim()) {
    sshFormError.value = t('pki.principalRequired')
    return
  }
  if (!sshForm.value.cert_pem.trim()) {
    sshFormError.value = t('pki.certRequired')
    return
  }

  creating.value = true
  try {
    const me = await api.me()
    await api.createSshCert(
      me.id,
      sshForm.value.principal,
      sshForm.value.cert_pem,
      sshForm.value.key_type,
      sshForm.value.valid_before || new Date().toISOString(),
      sshForm.value.valid_after || new Date(Date.now() + 24 * 3600 * 1000).toISOString(),
      sshForm.value.project_id || undefined,
    )
    showCreateSshCertModal.value = false
    sshForm.value = { user_id: '', project_id: '', principal: '', cert_pem: '', key_type: 'ed25519', valid_before: '', valid_after: '' }
    await loadSshCerts()
  } catch (e: any) {
    sshFormError.value = e.message ?? t('pki.createFailed')
  } finally {
    creating.value = false
  }
}

async function handleRevokeSshCert(id: string) {
  if (!confirm(t('pki.revokeSshConfirm'))) return
  try {
    await api.revokeSshCert(id)
    await loadSshCerts()
  } catch (e: any) {
    console.error('Failed to revoke SSH cert:', e)
  }
}

function formatDate(dateStr: string) {
  return new Date(dateStr).toLocaleString()
}

function isExpired(dateStr: string) {
  return new Date(dateStr) < new Date()
}

function caStatus(k: CaKey): 'ok' | 'warn' | 'danger' | 'dim' {
  if (k.revoked_at) return 'danger'
  if (isExpired(k.not_after)) return 'warn'
  return 'ok'
}

function certStatus(c: SshCert): 'ok' | 'warn' | 'danger' | 'dim' {
  if (c.revoked_at) return 'danger'
  if (isExpired(c.valid_after)) return 'warn'
  return 'ok'
}

onMounted(() => {
  loadCaKeys()
  loadSshCerts()
})
</script>

<template>
  <div>
    <UiPageHeader :title="t('pki.title')" />

    <!-- Certificate Authorities -->
    <UiCard variant="outlined" padding>
      <h2 class="section-title">{{ t('pki.cas') }}</h2>
      <UiTable :loading="loading" :empty="!caKeys.length" :empty-text="t('pki.noCas')" :colspan="6">
        <template #head>
          <tr>
            <th style="width: 100px">{{ t('pki.kind') }}</th>
            <th style="width: 170px">{{ t('pki.notBefore') }}</th>
            <th style="width: 170px">{{ t('pki.notAfter') }}</th>
            <th style="width: 100px">{{ t('pki.status') }}</th>
            <th>{{ t('pki.certificate') }}</th>
            <th style="width: 100px">{{ t('pki.actions') }}</th>
          </tr>
        </template>

        <tr v-for="k in caKeys" :key="k.id" :class="{ faded: k.revoked_at || isExpired(k.not_after) }">
          <td class="mono">{{ k.kind.toUpperCase() }}</td>
          <td class="dim mono small">{{ formatDate(k.not_before) }}</td>
          <td class="dim mono small">{{ formatDate(k.not_after) }}</td>
          <td>
            <UiBadge :variant="caStatus(k)" :dot="true">
              {{ k.revoked_at ? t('pki.revoked') : isExpired(k.not_after) ? t('pki.expired') : t('pki.active') }}
            </UiBadge>
          </td>
          <td class="mono dim cert-cell">{{ k.cert_pem }}</td>
          <td>
            <UiButton v-if="!k.revoked_at" size="sm" variant="danger" @click="handleRevokeCa(k.id)">
              {{ t('pki.revoke') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- SSH Certificates -->
    <UiCard variant="outlined" padding class="ssh-card">
      <div class="ssh-head">
        <h2 class="section-title" style="margin: 0">{{ t('pki.sshCerts') }}</h2>
        <UiButton variant="primary" size="sm" @click="showCreateSshCertModal = true">
          {{ t('pki.issueSshCert') }}
        </UiButton>
      </div>
      <UiTable :loading="loading" :empty="!sshCerts.length" :empty-text="t('pki.noSshCerts')" :colspan="6">
        <template #head>
          <tr>
            <th style="width: 160px">{{ t('pki.principal') }}</th>
            <th style="width: 100px">{{ t('pki.keyType') }}</th>
            <th style="width: 170px">{{ t('pki.validFrom') }}</th>
            <th style="width: 160px">{{ t('pki.validUntil') }}</th>
            <th style="width: 100px">{{ t('pki.status') }}</th>
            <th style="width: 100px">{{ t('pki.actions') }}</th>
          </tr>
        </template>

        <tr v-for="c in sshCerts" :key="c.id" :class="{ faded: c.revoked_at || isExpired(c.valid_after) }">
          <td class="mono">{{ c.principal }}</td>
          <td class="mono dim small">{{ c.key_type }}</td>
          <td class="dim mono small">{{ formatDate(c.valid_before) }}</td>
          <td class="dim mono small">{{ formatDate(c.valid_after) }}</td>
          <td>
            <UiBadge :variant="certStatus(c)" :dot="true">
              {{ c.revoked_at ? t('pki.revoked') : isExpired(c.valid_after) ? t('pki.expired') : t('pki.active') }}
            </UiBadge>
          </td>
          <td>
            <UiButton
              v-if="!c.revoked_at && !isExpired(c.valid_after)"
              size="sm"
              variant="danger"
              @click="handleRevokeSshCert(c.id)"
            >
              {{ t('pki.revoke') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- Create CA Modal -->
    <UiModal :open="showCreateCaModal" :title="t('pki.addCa')" size="lg" @close="showCreateCaModal = false">
      <UiSelect v-model="caForm.kind" :label="t('pki.caKind')">
        <option value="root">{{ t('pki.root') }}</option>
        <option value="intermediate">{{ t('pki.intermediate') }}</option>
      </UiSelect>
      <UiTextarea
        v-model="caForm.key_pem"
        :label="t('pki.privateKeyPem')"
        :rows="6"
        mono
        placeholder="-----BEGIN PRIVATE KEY-----"
      />
      <UiTextarea
        v-model="caForm.cert_pem"
        :label="t('pki.certPem')"
        :rows="6"
        mono
        placeholder="-----BEGIN CERTIFICATE-----"
      />
      <div class="row-fields">
        <UiInput v-model="caForm.not_before" :label="t('pki.notBeforeLabel')" type="datetime-local" />
        <UiInput v-model="caForm.not_after" :label="t('pki.notAfterLabel')" type="datetime-local" />
      </div>
      <p v-if="caFormError" class="error">{{ caFormError }}</p>
      <template #footer>
        <UiButton variant="secondary" @click="showCreateCaModal = false">
          {{ t('pki.cancel') }}
        </UiButton>
        <UiButton variant="primary" :loading="creating" :disabled="creating" @click="handleCreateCa">
          {{ creating ? t('pki.saving') : t('pki.add') }}
        </UiButton>
      </template>
    </UiModal>

    <!-- Issue SSH Cert Modal -->
    <UiModal :open="showCreateSshCertModal" :title="t('pki.issueTitle')" size="lg" @close="showCreateSshCertModal = false">
      <UiInput
        v-model="sshForm.principal"
        :label="t('pki.sshPrincipal')"
        :placeholder="t('pki.sshPrincipalPlaceholder')"
      />
      <UiSelect v-model="sshForm.key_type" :label="t('pki.sshKeyType')">
        <option value="ed25519">Ed25519</option>
        <option value="rsa">RSA</option>
        <option value="ecdsa">ECDSA</option>
      </UiSelect>
      <UiTextarea
        v-model="sshForm.cert_pem"
        :label="t('pki.certFormat')"
        :rows="8"
        mono
        :placeholder="t('pki.certPlaceholder')"
      />
      <div class="row-fields">
        <UiInput v-model="sshForm.valid_before" :label="t('pki.validFromOptional')" type="datetime-local" />
        <UiInput v-model="sshForm.valid_after" :label="t('pki.validUntilOptional')" type="datetime-local" />
      </div>
      <p v-if="sshFormError" class="error">{{ sshFormError }}</p>
      <template #footer>
        <UiButton variant="secondary" @click="showCreateSshCertModal = false">
          {{ t('pki.cancel') }}
        </UiButton>
        <UiButton variant="primary" :loading="creating" :disabled="creating" @click="handleCreateSshCert">
          {{ creating ? t('pki.issuing') : t('pki.issue') }}
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

.ssh-card {
  margin-top: var(--space-4);
}

.ssh-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-3);
}

.cert-cell {
  font-size: 11px;
  max-width: 280px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.faded {
  opacity: 0.45;
}

.row-fields {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
}
</style>