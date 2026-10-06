<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { api, type CaKey, type SshCert, type CaKeyType, type SshKeyType } from '@/api/client'

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
    caFormError.value = 'Key PEM and cert PEM are both required'
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
    caFormError.value = e.message ?? 'Failed to create CA key'
  } finally {
    creating.value = false
  }
}

async function handleRevokeCa(id: string) {
  if (!confirm('Revoke this CA? Certificates it signed stop being trusted.')) return
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
    sshFormError.value = 'Principal is required'
    return
  }
  if (!sshForm.value.cert_pem.trim()) {
    sshFormError.value = 'Certificate PEM is required'
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
    sshFormError.value = e.message ?? 'Failed to issue SSH certificate'
  } finally {
    creating.value = false
  }
}

async function handleRevokeSshCert(id: string) {
  if (!confirm('Revoke this SSH certificate?')) return
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

onMounted(() => {
  loadCaKeys()
  loadSshCerts()
})
</script>

<template>
  <div class="pki-view">
    <div class="spread" style="margin-bottom: 16px">
      <h2 style="margin: 0">PKI / SSH Certificates</h2>
    </div>

    <div class="card" style="padding: 0">
      <div class="section-title">Certificate Authorities</div>
      <table v-if="!loading">
        <thead>
          <tr>
            <th style="width: 100px">Kind</th>
            <th style="width: 180px">Not Before</th>
            <th style="width: 180px">Not After</th>
            <th style="width: 100px">Status</th>
            <th>Certificate</th>
            <th style="width: 100px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="k in caKeys" :key="k.id" :style="{ opacity: k.revoked_at || isExpired(k.not_after) ? 0.45 : 1 }">
            <td class="mono">{{ k.kind.toUpperCase() }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(k.not_before) }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(k.not_after) }}</td>
            <td>
              <span v-if="k.revoked_at" class="error">Revoked</span>
              <span v-else-if="isExpired(k.not_after)" class="warn">Expired</span>
              <span v-else class="ok">Active</span>
            </td>
            <td class="mono dim" style="font-size: 11px; max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
              {{ k.cert_pem }}
            </td>
            <td>
              <button v-if="!k.revoked_at" class="danger" @click="handleRevokeCa(k.id)">Revoke</button>
            </td>
          </tr>
          <tr v-if="!caKeys.length">
            <td colspan="6" class="dim">No CAs yet.</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim" style="text-align: center; padding: 20px">Loading…</p>
    </div>

    <div class="card" style="padding: 0; margin-top: 16px">
      <div class="spread" style="margin-bottom: 12px">
        <div class="section-title" style="margin-bottom: 0">SSH Certificates</div>
        <button class="primary" @click="showCreateSshCertModal = true">Issue SSH Cert</button>
      </div>
      <table v-if="!loading">
        <thead>
          <tr>
            <th style="width: 160px">Principal</th>
            <th style="width: 100px">Key Type</th>
            <th style="width: 180px">Valid From</th>
            <th style="width: 160px">Valid Until</th>
            <th style="width: 100px">Status</th>
            <th style="width: 100px">Actions</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in sshCerts" :key="c.id" :style="{ opacity: c.revoked_at || isExpired(c.valid_after) ? 0.45 : 1 }">
            <td class="mono">{{ c.principal }}</td>
            <td class="mono dim" style="font-size: 12px">{{ c.key_type }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(c.valid_before) }}</td>
            <td class="dim mono" style="font-size: 12px">{{ formatDate(c.valid_after) }}</td>
            <td>
              <span v-if="c.revoked_at" class="error">Revoked</span>
              <span v-else-if="isExpired(c.valid_after)" class="warn">Expired</span>
              <span v-else class="ok">Active</span>
            </td>
            <td>
              <button v-if="!c.revoked_at && !isExpired(c.valid_after)" class="danger" @click="handleRevokeSshCert(c.id)">Revoke</button>
            </td>
          </tr>
          <tr v-if="!sshCerts.length">
            <td colspan="5" class="dim">No SSH certificates yet.</td>
          </tr>
        </tbody>
      </table>
      <p v-else class="dim" style="text-align: center; padding: 20px">Loading…</p>
    </div>

    <!-- Create CA Modal -->
    <div v-if="showCreateCaModal" class="modal-overlay" @click.self="showCreateCaModal = false">
      <div class="modal" style="width: 640px">
        <h3>Add CA Key</h3>
        <div class="card">
          <label>
            Kind
            <select v-model="caForm.kind">
              <option value="root">Root</option>
              <option value="intermediate">Intermediate</option>
            </select>
          </label>
          <label>
            Private Key (PEM)
            <textarea v-model="caForm.key_pem" rows="6" style="font-family: var(--mono); font-size: 12px" placeholder="-----BEGIN PRIVATE KEY-----" />
          </label>
          <label>
            Certificate (PEM)
            <textarea v-model="caForm.cert_pem" rows="6" style="font-family: var(--mono); font-size: 12px" placeholder="-----BEGIN CERTIFICATE-----" />
          </label>
          <div class="row">
            <label style="flex: 1">
              Not Before
              <input v-model="caForm.not_before" type="datetime-local" />
            </label>
            <label style="flex: 1">
              Not After
              <input v-model="caForm.not_after" type="datetime-local" />
            </label>
          </div>
        </div>
        <p v-if="caFormError" class="error">{{ caFormError }}</p>
        <div class="spread" style="margin-top: 16px; justify-content: flex-end">
          <button @click="showCreateCaModal = false">Cancel</button>
          <button class="primary" @click="handleCreateCa" :disabled="creating">
            {{ creating ? 'Saving…' : 'Add' }}
          </button>
        </div>
      </div>
    </div>

    <!-- Issue SSH Cert Modal -->
    <div v-if="showCreateSshCertModal" class="modal-overlay" @click.self="showCreateSshCertModal = false">
      <div class="modal" style="width: 640px">
        <h3>Issue SSH Certificate</h3>
        <div class="card">
          <label>
            Principal
            <input v-model="sshForm.principal" placeholder="alice@build-*" />
          </label>
          <label>
            Key Type
            <select v-model="sshForm.key_type">
              <option value="ed25519">Ed25519</option>
              <option value="rsa">RSA</option>
              <option value="ecdsa">ECDSA</option>
            </select>
          </label>
          <label>
            Certificate (OpenSSH authorized_keys format)
            <textarea v-model="sshForm.cert_pem" rows="8" style="font-family: var(--mono); font-size: 12px" placeholder="ssh-ed25519-cert-v01@openssh.com ..." />
          </label>
          <div class="row">
            <label style="flex: 1">
              Valid From (optional)
              <input v-model="sshForm.valid_before" type="datetime-local" />
            </label>
            <label style="flex: 1">
              Valid Until (optional)
              <input v-model="sshForm.valid_after" type="datetime-local" />
            </label>
          </div>
        </div>
        <p v-if="sshFormError" class="error">{{ sshFormError }}</p>
        <div class="spread" style="margin-top: 16px; justify-content: flex-end">
          <button @click="showCreateSshCertModal = false">Cancel</button>
          <button class="primary" @click="handleCreateSshCert" :disabled="creating">
            {{ creating ? 'Issuing…' : 'Issue' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.pki-view {
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