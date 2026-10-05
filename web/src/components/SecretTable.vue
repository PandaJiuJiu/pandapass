<script setup lang="ts">
/**
 * Lists secret names for one environment.
 *
 * The deliberate omission: there is no "reveal all" and no bulk display. A
 * value is fetched only when someone asks for that one key, is held in a
 * component-local ref, and is overwritten the moment the row is closed. Nothing
 * is cached, and no value is ever written to the URL, storage, or a store.
 */
import { onMounted, ref } from 'vue'
import { api, ApiError, type SecretMeta } from '@/api/client'

const props = defineProps<{ project: string; env: string }>()
const emit = defineEmits<{ (e: 'changed'): void }>()

const secrets = ref<SecretMeta[]>([])
const loading = ref(true)
const error = ref('')

/** Key currently revealed, if any. At most one, by design. */
const revealedKey = ref<string | null>(null)
const revealedValue = ref('')
const busyKey = ref<string | null>(null)

const newKey = ref('')
const newValue = ref('')
const saving = ref(false)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.listSecrets(props.project, props.env)
    // A soft-deleted secret is still listed by the API; hide it here so the UI
    // matches what a reader would expect to find.
    secrets.value = res.items.filter((s) => !s.deleted_at)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not load secrets'
  } finally {
    loading.value = false
  }
}

async function reveal(key: string): Promise<void> {
  if (revealedKey.value === key) {
    hide()
    return
  }
  busyKey.value = key
  error.value = ''
  try {
    const res = await api.getSecret(props.project, props.env, key)
    revealedKey.value = key
    revealedValue.value = res.value
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : `Could not read ${key}`
  } finally {
    busyKey.value = null
  }
}

function hide(): void {
  revealedKey.value = null
  // Overwrite rather than just null the ref: this drops the last reference to
  // the string so it can be collected instead of lingering in a heap snapshot.
  revealedValue.value = ''
}

async function save(): Promise<void> {
  if (!newKey.value || !newValue.value) return
  saving.value = true
  error.value = ''
  try {
    await api.setSecret(props.project, props.env, newKey.value, newValue.value)
    // Clear the form *before* any await-resume work, so the value does not sit
    // in the DOM while the list refreshes.
    newKey.value = ''
    newValue.value = ''
    await refresh()
    emit('changed')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not save'
  } finally {
    saving.value = false
  }
}

async function remove(key: string): Promise<void> {
  if (!confirm(`Delete ${key}? This cannot be undone from the UI.`)) return
  error.value = ''
  try {
    await api.deleteSecret(props.project, props.env, key)
    if (revealedKey.value === key) hide()
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not delete'
  }
}

async function copyValue(): Promise<void> {
  if (!revealedValue.value) return
  try {
    await navigator.clipboard.writeText(revealedValue.value)
    // The clipboard is a place a secret goes to live that the page cannot
    // control, so it is cleared on a timer. See SECURITY.md.
    setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), 30_000)
  } catch {
    error.value = 'Clipboard unavailable'
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <div class="spread" style="margin-bottom: 12px">
      <h3 style="margin: 0; font-size: 15px">
        Secrets <span class="dim">({{ secrets.length }})</span>
      </h3>
      <button @click="refresh">Refresh</button>
    </div>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <table v-else>
      <thead>
        <tr>
          <th style="width: 34%">Key</th>
          <th style="width: 10%">Ver</th>
          <th style="width: 24%">Updated</th>
          <th />
        </tr>
      </thead>
      <tbody>
        <tr v-for="s in secrets" :key="s.id">
          <td class="mono">{{ s.key }}</td>
          <td class="dim">{{ s.version }}</td>
          <td class="dim mono">{{ new Date(s.updated_at).toLocaleString() }}</td>
          <td>
            <div class="row" style="justify-content: flex-end">
              <template v-if="revealedKey === s.key">
                <span class="mono" style="overflow-wrap: anywhere">{{ revealedValue }}</span>
                <button class="primary" @click="copyValue">Copy</button>
                <button @click="hide">Hide</button>
              </template>
              <template v-else>
                <button :disabled="busyKey === s.key" @click="reveal(s.key)">
                  {{ busyKey === s.key ? '…' : 'Reveal' }}
                </button>
                <button class="danger" @click="remove(s.key)">Delete</button>
              </template>
            </div>
          </td>
        </tr>
        <tr v-if="!secrets.length">
          <td colspan="4" class="dim">No secrets in this environment yet.</td>
        </tr>
      </tbody>
    </table>

    <div class="card" style="margin-top: 20px; background: var(--surface-2)">
      <div class="spread" style="margin-bottom: 10px">
        <strong style="font-size: 14px">Add or replace a secret</strong>
      </div>
      <div class="row">
        <input
          v-model="newKey"
          placeholder="KEY_NAME"
          class="mono"
          style="flex: 0 0 30%"
          autocomplete="off"
          spellcheck="false"
        />
        <input
          v-model="newValue"
          type="password"
          placeholder="value"
          autocomplete="off"
          spellcheck="false"
          @keyup.enter="save"
        />
        <button class="primary" :disabled="saving || !newKey || !newValue" @click="save">
          {{ saving ? 'Saving…' : 'Save' }}
        </button>
      </div>
      <p class="dim" style="font-size: 12px; margin: 10px 0 0">
        The value field is masked. Writing a key that already exists creates a new
        version; the old one is kept for rollback.
      </p>
    </div>
  </div>
</template>
