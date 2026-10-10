<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import logoUrl from '@/assets/logo.svg?url'

const auth = useAuthStore()
const router = useRouter()

async function signOut(): Promise<void> {
  await auth.logout()
  router.push('/login')
}

onMounted(() => {
  if (!auth.user) auth.fetchMe()
})
</script>

<template>
  <div>
    <header class="spread" style="margin-bottom: 24px">
      <strong class="brand">
        <img :src="logoUrl" alt="" class="brand-logo" />
        PandaPass
      </strong>
      <nav class="row" style="gap: 16px">
        <router-link to="/projects">Projects</router-link>
        <router-link to="/tokens">Tokens</router-link>
        <router-link to="/audit">Audit</router-link>
        <router-link to="/policies">Policies</router-link>
        <router-link to="/pki">PKI</router-link>
        <router-link to="/scan">Scan</router-link>
        <router-link v-if="auth.user?.global_role === 'admin'" to="/users">Users</router-link>
      </nav>
      <div class="row">
        <span v-if="auth.user" class="dim mono" style="font-size: 12px">
          {{ auth.user.email }}
          <span v-if="auth.user.global_role === 'admin'" class="dim">· admin</span>
        </span>
        <button @click="signOut">Sign out</button>
      </div>
    </header>

    <main>
      <router-view />
    </main>
  </div>
</template>

<style scoped>
main {
  max-width: 1100px;
}
header {
  max-width: 1100px;
}
.brand {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 16px;
}
.brand-logo {
  width: 22px;
  height: 22px;
  display: block;
}
nav a {
  text-decoration: none;
  font-size: 14px;
  color: var(--text-dim);
}
nav a.router-link-active {
  color: var(--accent);
}
</style>
