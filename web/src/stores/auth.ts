import { defineStore } from 'pinia'
import { ref } from 'vue'
import { api, setUnauthorizedHandler, type User } from '@/api/client'

/**
 * Session state. Deliberately holds no secret material — the session token is
 * an HttpOnly cookie the browser attaches on its own, so there is nothing here
 * for a script on the page to read, and nothing for us to leak by accident.
 */
export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const initialized = ref(false)

  async function fetchMe(): Promise<void> {
    if (user.value) {
      initialized.value = true
      return
    }
    try {
      user.value = await api.me()
    } catch {
      user.value = null
    } finally {
      initialized.value = true
    }
  }

  async function login(email: string, password: string, totpCode?: string): Promise<boolean> {
    const res = await api.login(email, password, totpCode)
    if (res.requires_totp && !totpCode) return true
    user.value = res.user
    initialized.value = true
    return false
  }

  async function register(email: string, password: string): Promise<void> {
    const res = await api.register(email, password)
    user.value = res.user
    initialized.value = true
  }

  async function logout(): Promise<void> {
    try {
      await api.logout()
    } finally {
      user.value = null
    }
  }

  // A 401 anywhere in the app means this session is over. Clear it once,
  // centrally, rather than letting each view rediscover it.
  setUnauthorizedHandler(() => {
    user.value = null
  })

  return { user, initialized, fetchMe, login, register, logout }
})
