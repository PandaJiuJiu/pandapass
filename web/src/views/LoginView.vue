<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/auth'
import { api, ApiError } from '@/api/client'
import LogoMark from '@/components/ui/LogoMark.vue'
import UiInput from '@/components/ui/UiInput.vue'
import UiButton from '@/components/ui/UiButton.vue'
import UiCard from '@/components/ui/UiCard.vue'

const auth = useAuthStore()
const router = useRouter()
const { t, tm } = useI18n()

/**
 * `tm()` returns `unknown` without typed messages. `login.brandFeatures` is a
 * readonly string array in the dictionary; assert the shape once and recompute
 * on locale change so the brand panel reflects the active language.
 */
const features = computed<readonly string[]>(
  () => tm('login.brandFeatures') as readonly string[],
)

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
        error.value = t('login.passwordMismatch')
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
    error.value =
      e instanceof ApiError
        ? e.message
        : isSetup.value
          ? t('login.setupError')
          : t('login.signInFailed')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login-layout">
    <!-- Brand panel -->
    <div class="brand-panel">
      <div class="brand-inner">
        <div class="brand-logo">
          <LogoMark class="large" />
          <span class="brand-name">PandaPass</span>
        </div>
        <p class="tagline">{{ t('login.brandTagline') }}</p>
        <ul class="features">
          <li v-for="f in features" :key="f">{{ f }}</li>
        </ul>
      </div>
    </div>

    <!-- Form panel -->
    <div class="form-panel">
      <div class="form-card-wrap">
        <UiCard variant="outlined" class="form-card">
          <h1 class="form-title">
            {{ isSetup ? t('login.setupTitle') : t('login.signInTitle') }}
          </h1>
          <p class="form-subtitle">
            {{ isSetup ? t('login.setupSubtitle') : t('login.signInSubtitle') }}
          </p>

          <!-- Setup form: first run, no users yet -->
          <template v-if="isSetup">
            <UiInput
              v-model="email"
              :label="t('common.email')"
              type="email"
              autocomplete="username"
              :spellcheck="false"
              @keyup.enter="submit"
            />

            <UiInput
              v-model="password"
              :label="t('common.password')"
              type="password"
              autocomplete="new-password"
              @keyup.enter="submit"
            />

            <UiInput
              v-model="confirmPassword"
              :label="t('login.confirmPassword')"
              type="password"
              autocomplete="new-password"
              @keyup.enter="submit"
            />

            <p v-if="error" class="error">{{ error }}</p>

            <UiButton
              class="submit-btn"
              variant="primary"
              :loading="busy"
              :disabled="busy"
              @click="submit"
            >
              {{ busy ? t('login.creating') : t('login.createAdmin') }}
            </UiButton>

            <p class="footnote">{{ t('login.firstAccountNote') }}</p>
          </template>

          <!-- Login form: normal case -->
          <template v-else>
            <UiInput
              v-model="email"
              :label="t('common.email')"
              type="email"
              autocomplete="username"
              :spellcheck="false"
              @keyup.enter="submit"
            />

            <UiInput
              v-model="password"
              :label="t('common.password')"
              type="password"
              autocomplete="current-password"
              @keyup.enter="submit"
            />

            <UiInput
              v-if="needsTotp"
              v-model="totpCode"
              :label="t('login.totpLabel')"
              inputmode="numeric"
              autocomplete="one-time-code"
              :placeholder="t('login.totpPlaceholder')"
              @keyup.enter="submit"
            />

            <p v-if="error" class="error">{{ error }}</p>

            <UiButton
              class="submit-btn"
              variant="primary"
              :loading="busy"
              :disabled="busy"
              @click="submit"
            >
              {{ busy ? t('login.signingIn') : t('common.signIn') }}
            </UiButton>

            <p v-if="setupChecked" class="footnote">
              {{ t('login.accountsManaged') }}
            </p>
          </template>
        </UiCard>
      </div>
    </div>
  </div>
</template>

<style scoped>
.login-layout {
  display: flex;
  min-height: 100vh;
  background: var(--bg);
}

/* Brand panel */
.brand-panel {
  flex: 1 1 45%;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(160deg, var(--surface) 0%, var(--surface-2) 100%);
  border-right: 1px solid var(--border);
  padding: var(--space-8);
}

.brand-inner {
  max-width: 380px;
}

.brand-logo {
  display: flex;
  align-items: center;
  gap: var(--space-3);
  margin-bottom: var(--space-6);
}

.brand-name {
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.01em;
}

.tagline {
  font-size: 17px;
  line-height: 1.5;
  color: var(--text);
  margin: 0 0 var(--space-6);
}

.features {
  list-style: none;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.features li {
  font-size: 13.5px;
  color: var(--text-dim);
  padding-left: 20px;
  position: relative;
}

.features li::before {
  content: '✓';
  position: absolute;
  left: 0;
  color: var(--accent);
  font-weight: 700;
}

/* Form panel */
.form-panel {
  flex: 1 1 55%;
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--space-6);
}

.form-card-wrap {
  width: 100%;
  max-width: 400px;
}

.form-card {
  padding: var(--space-8);
}

.form-title {
  margin: 0;
  font-size: 22px;
  font-weight: 700;
  letter-spacing: -0.01em;
}

.form-subtitle {
  margin: var(--space-1) 0 var(--space-6);
  font-size: 13.5px;
  color: var(--text-dim);
}

.submit-btn {
  width: 100%;
  margin-top: var(--space-2);
}

.footnote {
  margin: var(--space-4) 0 0;
  font-size: 12px;
  color: var(--text-faint);
  line-height: 1.5;
}

/* Mobile: stack vertically */
@media (max-width: 768px) {
  .login-layout {
    flex-direction: column;
  }

  .brand-panel {
    flex: none;
    padding: var(--space-6);
    border-right: none;
    border-bottom: 1px solid var(--border);
  }

  .brand-inner {
    max-width: 100%;
  }

  .brand-logo {
    margin-bottom: var(--space-3);
  }

  .tagline,
  .features {
    display: none;
  }

  .form-panel {
    padding: var(--space-6);
  }
}
</style>