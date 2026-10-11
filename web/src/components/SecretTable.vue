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
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type SecretMeta } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const props = defineProps<{ project: string; env: string }>()
const router = useRouter()
const { t } = useI18n()

const secrets = ref<SecretMeta[]>([])
const loading = ref(true)
const error = ref('')

/** Key currently revealed, if any. At most one, by design. */
const revealedKey = ref<string | null>(null)
const revealedValue = ref('')
const busyKey = ref<string | null>(null)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.listSecrets(props.project, props.env)
    // A soft-deleted secret is still listed by the API; hide it here so the UI
    // matches what a reader would expect to find.
    secrets.value = res.items.filter((s) => !s.deleted_at)
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

function newSecret(): void {
  router.push(`/projects/${props.project}/envs/${props.env}/secrets/new`)
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

async function remove(key: string): Promise<void> {
  if (!confirm(t('secretTable.deleteConfirm', { key }))) return
  error.value = ''
  try {
    await api.deleteSecret(props.project, props.env, key)
    if (revealedKey.value === key) hide()
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.deleteFailed')
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
    error.value = t('secretTable.clipboardUnavailable')
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <div class="secret-head">
      <h3 class="secret-title">
        {{ t('secretTable.title') }} <span class="count">({{ secrets.length }})</span>
      </h3>
      <div class="row actions">
        <UiButton variant="primary" size="sm" @click="newSecret">
          {{ t('secretTable.addOrReplace') }}
        </UiButton>
        <UiButton variant="ghost" size="sm" @click="refresh">
          {{ t('secretTable.refresh') }}
        </UiButton>
      </div>
    </div>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>
    <div v-if="loading" class="dim">{{ t('common.loading') }}</div>

    <UiTable
      v-else
      :empty="!secrets.length"
      :empty-text="t('secretTable.noSecrets')"
      :colspan="4"
    >
      <template #head>
        <tr>
          <th style="width: 34%">{{ t('secretTable.key') }}</th>
          <th style="width: 10%">{{ t('secretTable.version') }}</th>
          <th style="width: 24%">{{ t('secretTable.updated') }}</th>
          <th />
        </tr>
      </template>

      <tr v-for="s in secrets" :key="s.id">
        <td>
          <code class="mono">{{ s.key }}</code>
        </td>
        <td class="dim">{{ s.version }}</td>
        <td class="dim mono small">
          {{ new Date(s.updated_at).toLocaleString() }}
        </td>
        <td>
          <div class="row actions">
            <template v-if="revealedKey === s.key">
              <span class="mono value" :class="{ empty: !revealedValue }">{{ revealedValue }}</span>
              <UiButton size="sm" variant="primary" @click="copyValue">
                {{ t('secretTable.copy') }}
              </UiButton>
              <UiButton size="sm" @click="hide">
                {{ t('secretTable.hide') }}
              </UiButton>
            </template>
            <template v-else>
              <UiButton size="sm" :loading="busyKey === s.key" @click="reveal(s.key)">
                {{ t('secretTable.reveal') }}
              </UiButton>
              <UiButton size="sm" variant="danger" @click="remove(s.key)">
                {{ t('secretTable.delete') }}
              </UiButton>
            </template>
          </div>
        </td>
      </tr>
    </UiTable>
  </div>
</template>

<style scoped>
.secret-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: var(--space-3);
}

.secret-title {
  margin: 0;
  font-size: 15px;
  font-weight: 600;
}

.count {
  color: var(--text-dim);
  font-weight: 500;
}

.page-alert {
  margin-bottom: var(--space-3);
}

.small {
  font-size: 12px;
}

.value {
  overflow-wrap: anywhere;
  max-width: 320px;
  font-size: 13px;
  padding: 2px 8px;
  background: var(--surface-2);
  border-radius: var(--radius-sm);
  border: 1px solid var(--border);
}

.value.empty {
  opacity: 0.5;
}

.actions {
  justify-content: flex-end;
}
</style>