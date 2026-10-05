<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { ApiError } from '@/api/client'

const auth = useAuthStore()
const router = useRouter()

const mode = ref<'login' | 'register'>('login')
const email = ref('')
const password = ref('')
const totpCode = ref('')
const needsTotp = ref(false)
const error = ref('')
const busy = ref(false)

async function submit(): Promise<void> {
  error.value = ''
  busy.value = true
  try {
    const more = await auth.login(email.value, password.value, totpCode.value || undefined)
    if (more) {
      // The password was right; the account has TOTP on. Ask for the second
      // factor rather than reporting a failure.
      needsTotp.value = true
      return
    }
    router.push('/projects')
  } catch (e) {
    error.value = e instanceof ApiError ? e.message : 'Sign-in failed'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div style="max-width: 380px; margin: 12vh auto">
    <div class="card">
      <h1 style="margin: 0 0 4px; font-size: 20px">🐼 PandaPass</h1>
      <p class="dim" style="margin: 0 0 20px; font-size: 13px">
        {{ mode === 'login' ? 'Sign in to your vault' : 'Create an account' }}
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

      <p class="dim" style="font-size: 12px; margin: 16px 0 0">
        Registration is closed by default. Accounts are created by an
        administrator, or by running <span class="mono">pandapass register</span>.
      </p>
    </div>
  </div>
</template>
