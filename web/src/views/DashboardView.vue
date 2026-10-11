<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type Project } from '@/api/client'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiBadge from '@/components/ui/UiBadge.vue'
import UiAlert from '@/components/ui/UiAlert.vue'

const router = useRouter()
const { t } = useI18n()

const projects = ref<Project[]>([])
const loading = ref(true)
const error = ref('')

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

function newProject(): void {
  router.push('/projects/new')
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
        <UiButton variant="primary" size="sm" @click="newProject">
          {{ t('dashboard.newProject') }}
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
</style>