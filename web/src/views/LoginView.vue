<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { api, ApiError } from '@/api/client'
import logoUrl from '@/assets/logo.svg?url'

const auth = useAuthStore()
const router = useRouter()

const isSetup = ref(false)
const setupChecked = ref(false)
const email = ref('')
const password = ref('')
const confirmPassword = ref('')
const totpCode = ref('')
const needsTotp = ref(false)
const error = ref('')
const busy = ref(false)

onMounted(async () => {
  try {
    const status = await api.setupStatus()
    isSetup.value = status.needs_setup
  } catch {
    // Server unreachable — fall back to the login form; the error will
    // surface when the user tries to sign in.
    isSetup.value = false
  } finally {
    setupChecked.value = true
  }
})

async function submit(): Promise<void> {
  error.value = ''
  busy.value = true
  try {
    if (isSetup.value) {
      if (password.value !== confirmPassword.value) {
        error.value = 'Passwords do not match'
        return
      }
      await auth.register(email.value, password.value)
      router.push('/projects')
    } else {
      const more = await auth.login(email.value, password.value, totpCode.value || undefined)
      if (more) {
        // The password was right; the account has TOTP on. Ask for the second
        // factor rather than reporting a failure.
        needsTotp.value = true
        return
      }
      router.push('/projects')
    }
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : isSetup.value ? 'Could not create the administrator account' : 'Sign-in failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div style="max-width: 380px; margin: 12vh auto">
    <div class="card">
      <h1 style="margin: 0 0 4px; font-size: 20px; display: inline-flex; align-items: center; gap: 8px">
        <img :src="logoUrl" alt="" style="width: 24px; height: 24px" />
        PandaPass
      </h1>

      <!-- Setup form: first run, no users yet -->
      <template v-if="isSetup">
        <p class="dim" style="margin: 0 0 20px; font-size: 13px">
          First run — create the administrator account. This will be the
          vault's admin.
        </p>

        <label>
          Email
          <input
            v-model="email"
            type="email"
            autocomplete="username"
            spellcheck="false"
            @keyup.enter="submit"
          />
        </label>

        <label>
          Password
          <input
            v-model="password"
            type="password"
            autocomplete="new-password"
            @keyup.enter="submit"
          />
        </label>

        <label>
          Confirm password
          <input
            v-model="confirmPassword"
            type="password"
            autocomplete="new-password"
            @keyup.enter="submit"
          />
        </label>

        <p v-if="error" class="error">{{ error }}</p>

        <button class="primary" style="width: 100%" :disabled="busy" @click="submit">
          {{ busy ? 'Creating…' : 'Create administrator account' }}
        </button>

        <p class="dim" style="font-size: 12px; margin: 16px 0 0">
          This first account is the vault administrator. Additional users are
          created later from the <span class="mono">Users</span> page.
        </p>
      </template>

      <!-- Login form: normal case -->
      <template v-else>
        <p class="dim" style="margin: 0 0 20px; font-size: 13px">
          Sign in to your vault
        </p>

        <label>
          Email
          <input
            v-model="email"
            type="email"
            autocomplete="username"
            spellcheck="false"
            @keyup.enter="submit"
          />
        </label>

        <label>
          Password
          <input
            v-model="password"
            type="password"
            autocomplete="current-password"
            @keyup.enter="submit"
          />
        </label>

        <label v-if="needsTotp">
          Authenticator code
          <input
            v-model="totpCode"
            inputmode="numeric"
            autocomplete="one-time-code"
            placeholder="123456"
            @keyup.enter="submit"
          />
        </label>

        <p v-if="error" class="error">{{ error }}</p>

        <button class="primary" style="width: 100%" :disabled="busy" @click="submit">
          {{ busy ? 'Signing in…' : 'Sign in' }}
        </button>

        <p v-if="setupChecked" class="dim" style="font-size: 12px; margin: 16px 0 0">
          Accounts are created by an administrator.
        </p>
      </template>
    </div>
  </div>
</template>
