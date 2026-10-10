<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type Environment } from '@/api/client'
import SecretTable from '@/components/SecretTable.vue'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiAlert from '@/components/ui/UiAlert.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'

const props = defineProps<{ slug: string }>()
const { t } = useI18n()

const envs = ref<Environment[]>([])
const selected = ref('')
const loading = ref(true)
const error = ref('')

const envName = ref('')
const envSlug = ref('')
const creating = ref(false)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    envs.value = await api.listEnvs(props.slug)
    // Keep the current selection if it still exists, otherwise fall back to the
    // first environment so the page is never in a state showing nothing.
    if (!envs.value.some((e) => e.slug === selected.value)) {
      selected.value = envs.value[0]?.slug ?? ''
    }
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

async function createEnv(): Promise<void> {
  if (!envName.value || !envSlug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createEnv(props.slug, envName.value, envSlug.value)
    envName.value = ''
    envSlug.value = ''
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

// The slug is a route param, so navigating between projects changes it in place
// rather than remounting the view.
watch(() => props.slug, refresh)

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="`${slug}${selected ? ` / ${selected}` : ''}`">
      <template #actions>
        <router-link
          :to="`/projects/${slug}/dynamic-creds`"
          class="creds-link"
        >
          <UiButton variant="secondary" size="sm">
            {{ t('project.dynamicCreds') }}
          </UiButton>
        </router-link>
        <router-link to="/projects" class="back-link">{{ t('project.allProjects') }}</router-link>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>
    <div v-if="loading" class="dim">{{ t('common.loading') }}</div>

    <template v-else>
      <!-- Environment tabs -->
      <div class="env-tabs" role="tablist">
        <button
          v-for="e in envs"
          :key="e.id"
          class="env-tab"
          :class="{ active: e.slug === selected }"
          role="tab"
          :aria-selected="e.slug === selected"
          @click="selected = e.slug"
        >
          {{ e.name }}
        </button>
        <span v-if="!envs.length" class="dim">{{ t('project.noEnvironments') }}</span>
      </div>

      <UiCard variant="elevated">
        <SecretTable v-if="selected" :project="slug" :env="selected" />
        <p v-else class="dim">{{ t('project.noEnvironments') }}</p>
      </UiCard>

      <!-- New environment -->
      <UiCard variant="subtle" class="new-env">
        <h2 class="section-title">{{ t('project.newEnvironment') }}</h2>
        <div class="env-form">
          <UiInput
            v-model="envName"
            :label="t('project.envName')"
            :placeholder="t('project.envNamePlaceholder')"
          />
          <UiInput
            v-model="envSlug"
            :label="t('project.envSlug')"
            :placeholder="t('project.envSlugPlaceholder')"
            mono
          />
          <div class="env-form-actions">
            <UiButton
              variant="primary"
              :loading="creating"
              :disabled="creating || !envName || !envSlug"
              @click="createEnv"
            >
              {{ creating ? t('project.creatingEnvironment') : t('project.addEnvironment') }}
            </UiButton>
          </div>
        </div>
      </UiCard>
    </template>
  </div>
</template>

<style scoped>
.page-alert {
  margin-bottom: var(--space-4);
}

.back-link {
  font-size: 13px;
  color: var(--text-dim);
  text-decoration: none;
  white-space: nowrap;
}

.back-link:hover {
  color: var(--accent);
  text-decoration: underline;
}

.creds-link {
  text-decoration: none;
}

.env-tabs {
  display: flex;
  flex-wrap: wrap;
  gap: var(--space-2);
  margin-bottom: var(--space-4);
}

.env-tab {
  padding: 6px 14px;
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  background: var(--surface);
  color: var(--text-dim);
  font: inherit;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  transition: background-color var(--transition-fast), color var(--transition-fast),
    border-color var(--transition-fast);
}

.env-tab:hover {
  background: var(--surface-2);
}

.env-tab.active {
  background: var(--accent-soft);
  border-color: var(--accent);
  color: var(--accent);
}

.section-title {
  margin: 0 0 var(--space-3);
  font-size: 15px;
  font-weight: 600;
}

.new-env {
  margin-top: var(--space-6);
}

.env-form {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
  align-items: end;
}

.env-form-actions {
  padding-bottom: var(--space-4);
}
</style>