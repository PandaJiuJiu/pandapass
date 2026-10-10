<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type Project } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiBadge from '@/components/ui/UiBadge.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const router = useRouter()
const { t } = useI18n()

const projects = ref<Project[]>([])
const loading = ref(true)
const error = ref('')

const creating = ref(false)
const name = ref('')
const slug = ref('')
const description = ref('')

/** Derive a slug from the name unless the user has typed their own. */
let slugTouched = false
function onNameInput(): void {
  if (slugTouched) return
  slug.value = name.value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
}

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    projects.value = await api.listProjects()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('dashboard.loading')
  } finally {
    loading.value = false
  }
}

async function create(): Promise<void> {
  if (!name.value || !slug.value) return
  creating.value = true
  error.value = ''
  try {
    await api.createProject(name.value, slug.value, description.value || undefined)
    name.value = ''
    slug.value = ''
    description.value = ''
    slugTouched = false
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.createFailed')
  } finally {
    creating.value = false
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="t('dashboard.title')">
      <template #actions>
        <UiButton variant="ghost" size="sm" :disabled="loading" @click="refresh">
          {{ t('common.refresh') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="outlined" padding>
      <UiTable
        :loading="loading"
        :empty="!projects.length"
        :empty-text="t('dashboard.noProjects')"
        :colspan="4"
      >
        <template #head>
          <tr>
            <th>{{ t('dashboard.projectName') }}</th>
            <th style="width: 18%">{{ t('dashboard.projectSlug') }}</th>
            <th style="width: 14%">{{ t('dashboard.yourRole') }}</th>
            <th style="width: 8%" />
          </tr>
        </template>

        <tr
          v-for="p in projects"
          :key="p.id"
          class="project-row"
          @click="router.push(`/projects/${p.slug}`)"
        >
          <td>
            <span class="project-name">{{ p.name }}</span>
            <div v-if="p.description" class="project-desc">{{ p.description }}</div>
          </td>
          <td>
            <code class="mono dim">{{ p.slug }}</code>
          </td>
          <td>
            <UiBadge variant="dim">{{ p.user_role ?? t('dashboard.noRole') }}</UiBadge>
          </td>
          <td @click.stop>
            <UiButton size="sm" @click="router.push(`/projects/${p.slug}`)">
              {{ t('dashboard.open') }}
            </UiButton>
          </td>
        </tr>
      </UiTable>
    </UiCard>

    <!-- New project -->
    <UiCard variant="elevated" class="new-project">
      <h2 class="section-title">{{ t('dashboard.newProject') }}</h2>
      <div class="form-grid">
        <UiInput
          v-model="name"
          :label="t('dashboard.projectName')"
          :placeholder="t('dashboard.projectName')"
          @input="onNameInput"
        />
        <UiInput
          v-model="slug"
          mono
          :label="t('dashboard.projectSlug')"
          :hint="t('dashboard.slugHint')"
          :placeholder="t('dashboard.projectSlug')"
          @input="slugTouched = true"
        />
        <UiInput
          v-model="description"
          :label="`${t('common.description')} ${t('common.optional')}`"
          class="span-2"
        />
      </div>
      <UiButton
        variant="primary"
        :loading="creating"
        :disabled="creating || !name || !slug"
        @click="create"
      >
        {{ creating ? t('dashboard.creating') : t('dashboard.createProject') }}
      </UiButton>
    </UiCard>
  </div>
</template>

<style scoped>
.page-alert {
  margin-bottom: var(--space-4);
}

.project-row {
  cursor: pointer;
}

.project-name {
  font-weight: 600;
}

.project-desc {
  font-size: 12px;
  color: var(--text-dim);
  margin-top: 2px;
}

.section-title {
  margin: 0 0 var(--space-4);
  font-size: 15px;
  font-weight: 600;
}

.new-project {
  margin-top: var(--space-6);
}

.form-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 0 var(--space-4);
}

.span-2 {
  grid-column: 1 / -1;
}
</style>