<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError, type User } from '@/api/client'
import { useAuthStore } from '@/stores/auth'

const auth = useAuthStore()
const users = ref<User[]>([])
const loading = ref(true)
const error = ref('')

const email = ref('')
const password = ref('')
const creating = ref(false)

async function refresh(): Promise<void> {
  loading.value = true
  error.value = ''
  try {
    const res = await api.adminListUsers()
    users.value = res.users
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not load users'
  } finally {
    loading.value = false
  }
}

async function create(): Promise<void> {
  if (!email.value || !password.value) return
  creating.value = true
  error.value = ''
  try {
    await api.adminCreateUser(email.value, password.value)
    email.value = ''
    password.value = ''
    await refresh()
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Could not create user'
  } finally {
    creating.value = false
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
    error.value = e instanceof ApiError ? e.message : 'Could not update user'
  }
}

onMounted(refresh)
</script>

<template>
  <div>
    <h1 style="font-size: 20px; margin-top: 0">Users</h1>
    <p class="dim" style="font-size: 13px">
      Create accounts for your team and control who can sign in. New users are
      plain members — they become administrators only through promotion.
    </p>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-if="loading" class="dim">Loading…</p>

    <div v-else class="card" style="padding: 0">
      <table>
        <thead>
          <tr>
            <th>Email</th>
            <th style="width: 12%">Role</th>
            <th style="width: 14%">Created</th>
            <th style="width: 14%">Last login</th>
            <th style="width: 12%">Status</th>
            <th style="width: 12%" />
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id" :style="{ opacity: u.disabled_at ? 0.5 : 1 }">
            <td>
              {{ u.email }}
              <span v-if="u.id === auth.user?.id" class="dim" style="font-size: 12px">· you</span>
            </td>
            <td class="dim">{{ u.global_role }}</td>
            <td class="dim mono" style="font-size: 12px">
              {{ new Date(u.created_at).toLocaleDateString() }}
            </td>
            <td class="dim mono" style="font-size: 12px">
              {{ u.last_login_at ? new Date(u.last_login_at).toLocaleString() : 'never' }}
            </td>
            <td>
              <span v-if="u.disabled_at" class="danger" style="font-size: 12px">disabled</span>
              <span v-else class="dim" style="font-size: 12px">active</span>
            </td>
            <td>
              <button
                v-if="u.id !== auth.user?.id"
                class="danger"
                style="float: right"
                @click="toggleDisabled(u)"
              >
                {{ u.disabled_at ? 'Enable' : 'Disable' }}
              </button>
            </td>
          </tr>
          <tr v-if="!users.length">
            <td colspan="6" class="dim">No users yet.</td>
          </tr>
        </tbody>
      </table>
    </div>

    <div class="card">
      <strong style="font-size: 14px">Create a user</strong>
      <div style="margin-top: 12px">
        <div class="row">
          <label style="flex: 2">
            Email
            <input v-model="email" type="email" spellcheck="false" placeholder="teammate@example.com" />
          </label>
          <label style="flex: 2">
            Password
            <input v-model="password" type="text" placeholder="Set an initial password" />
          </label>
        </div>
        <button class="primary" :disabled="creating || !email || !password" @click="create">
          {{ creating ? 'Creating…' : 'Create user' }}
        </button>
      </div>
    </div>
  </div>
</template>
