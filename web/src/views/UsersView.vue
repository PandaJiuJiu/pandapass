<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { api, ApiError, type User } from '@/api/client'
import { useAuthStore } from '@/stores/auth'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiTable from '@/components/ui/UiTable.vue'
import UiAlert from '@/components/ui/UiAlert.vue'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiBadge from '@/components/ui/UiBadge.vue'

const auth = useAuthStore()
const router = useRouter()
const { t } = useI18n()
const users = ref<User[]>([])
const loading = ref(true)
const error = ref('')

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.adminListUsers()
    users.value = res.users
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.loadFailed')
  } finally {
    loading.value = false
  }
}

async function toggleDisabled(u: User): Promise<void> {
  error.value = ''
  try {
    if (u.disabled_at) {
      await api.adminEnableUser(u.id)
    } else {
      await api.adminDisableUser(u.id)
    }
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : t('common.updateFailed')
  }
}

function newUser(): void {
  router.push('/users/new')
}

onMounted(refresh)
</script>

<template>
  <div>
    <UiPageHeader :title="t('users.title')" :description="t('users.subtitle')">
      <template #actions>
        <UiButton variant="primary" size="sm" @click="newUser">
          {{ t('users.createUser') }}
        </UiButton>
      </template>
    </UiPageHeader>

    <UiAlert v-if="error" variant="error" class="page-alert">{{ error }}</UiAlert>

    <UiCard variant="outlined" padding>
      <UiTable
        :loading="loading"
        :empty="!users.length"
        :empty-text="t('users.noUsers')"
        :colspan="6"
      >
        <template #head>
          <tr>
            <th>{{ t('users.email') }}</th>
            <th style="width: 12%">{{ t('users.role') }}</th>
            <th style="width: 14%">{{ t('users.created') }}</th>
            <th style="width: 18%">{{ t('users.lastLogin') }}</th>
            <th style="width: 12%">{{ t('users.status') }}</th>
            <th style="width: 12%" />
          </tr>
        </template>

        <tr v-for="u in users" :key="u.id" :class="{ disabled: u.disabled_at }">
          <td>
            {{ u.email }}
            <span v-if="u.id === auth.user?.id" class="you-tag">· {{ t('users.you') }}</span>
          </td>
          <td class="dim">{{ u.global_role }}</td>
          <td class="dim mono small">
            {{ new Date(u.created_at).toLocaleDateString() }}
          </td>
          <td class="dim mono small">
            {{ u.last_login_at ? new Date(u.last_login_at).toLocaleString() : t('users.never') }}
          </td>
          <td>
            <UiBadge :variant="u.disabled_at ? 'danger' : 'ok'" :dot="true">
              {{ u.disabled_at ? t('users.disabled') : t('users.active') }}
            </UiBadge>
          </td>
          <td>
            <UiButton
              v-if="u.id !== auth.user?.id"
              size="sm"
              variant="danger"
              class="float-right"
              @click="toggleDisabled(u)"
            >
              {{ u.disabled_at ? t('users.enable') : t('users.disable') }}
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

.disabled {
  opacity: 0.5;
}

.you-tag {
  font-size: 12px;
  color: var(--text-dim);
}

.small {
  font-size: 12px;
}

.float-right {
  float: right;
}
</style>