<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { useRouter } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '@/stores/auth'
import { setLocale } from '@/i18n'
import LogoMark from '@/components/ui/LogoMark.vue'
import UiSidebar from '@/components/ui/UiSidebar.vue'
import UiSidebarItem from '@/components/ui/UiSidebarItem.vue'
import UiSidebarGroup from '@/components/ui/UiSidebarGroup.vue'
import UiBreadcrumb from '@/components/ui/UiBreadcrumb.vue'
import UiBadge from '@/components/ui/UiBadge.vue'
import UiButton from '@/components/ui/UiButton.vue'

const auth = useAuthStore()
const route = useRoute()
const router = useRouter()
const { t, locale } = useI18n()

const sidebarOpen = ref(false)

const isAdmin = computed(() => auth.user?.global_role === 'admin')

function currentLocale(): 'en' | 'zh-CN' {
  return locale.value === 'zh-CN' ? 'zh-CN' : 'en'
}

function switchLocale(l: 'en' | 'zh-CN'): void {
  setLocale(l)
  sidebarOpen.value = false
}

async function signOut(): Promise<void> {
  await auth.logout()
  router.push('/login')
}

/** Build breadcrumb items from route meta. */
const breadcrumbs = computed(() => {
  const items: { label: string; to?: string }[] = []
  const matched = route.matched.filter((r) => r.meta.title)

  matched.forEach((r, idx) => {
    const isLast = idx === matched.length - 1
    const labelKey = r.meta.title as string
    let label = t(labelKey)
    let to: string | undefined

    if (r.meta.paramLabel && route.params.slug) {
      label = String(route.params.slug)
    }

    if (!isLast) {
      // Link to the parent route if defined, else to the matched path.
      to = (r.meta.parent as string) ?? r.path
      // For parameterised parents, interpolate the slug.
      if (to && to.includes(':slug')) {
        to = to.replace(':slug', String(route.params.slug ?? ''))
      }
    }

    items.push({ label, to })
  })

  return items
})

onMounted(() => {
  if (!auth.user) auth.fetchMe()
})
</script>

<template>
  <div class="app-shell">
    <!-- Public routes (login) render without the shell. -->
    <template v-if="route.meta.public">
      <router-view />
    </template>

    <template v-else>
      <UiSidebar :open="sidebarOpen" @close="sidebarOpen = false">
        <template #brand>
          <LogoMark />
          <span>PandaPass</span>
        </template>

        <UiSidebarGroup :title="t('nav.workspace')">
          <UiSidebarItem to="/projects" @click="sidebarOpen = false">
            {{ t('nav.projects') }}
          </UiSidebarItem>
          <UiSidebarItem to="/tokens" @click="sidebarOpen = false">
            {{ t('nav.tokens') }}
          </UiSidebarItem>
        </UiSidebarGroup>

        <UiSidebarGroup :title="t('nav.security')">
          <UiSidebarItem to="/policies" @click="sidebarOpen = false">
            {{ t('nav.policies') }}
          </UiSidebarItem>
          <UiSidebarItem to="/pki" @click="sidebarOpen = false">
            {{ t('nav.pki') }}
          </UiSidebarItem>
          <UiSidebarItem to="/scan" @click="sidebarOpen = false">
            {{ t('nav.scan') }}
          </UiSidebarItem>
          <UiSidebarItem to="/audit" @click="sidebarOpen = false">
            {{ t('nav.audit') }}
          </UiSidebarItem>
        </UiSidebarGroup>

        <UiSidebarGroup v-if="isAdmin" :title="t('nav.admin')">
          <UiSidebarItem to="/users" @click="sidebarOpen = false">
            {{ t('nav.users') }}
          </UiSidebarItem>
        </UiSidebarGroup>

        <template #footer>
          <div class="user-card">
            <div class="user-email" :title="auth.user?.email ?? ''">
              {{ auth.user?.email }}
              <UiBadge v-if="isAdmin" variant="info">{{ t('common.roleAdmin') }}</UiBadge>
              <UiBadge v-else variant="dim">{{ t('common.roleMember') }}</UiBadge>
            </div>
            <div class="user-actions">
              <div class="locale-switch" role="group" aria-label="Language">
                <button
                  :class="{ active: currentLocale() === 'en' }"
                  @click="switchLocale('en')"
                >
                  EN
                </button>
                <button
                  :class="{ active: currentLocale() === 'zh-CN' }"
                  @click="switchLocale('zh-CN')"
                >
                  中文
                </button>
              </div>
              <UiButton variant="ghost" size="sm" @click="signOut">
                {{ t('nav.signOut') }}
              </UiButton>
            </div>
          </div>
        </template>
      </UiSidebar>

      <div class="app-main">
        <header class="topbar">
          <button class="menu-toggle" aria-label="Menu" @click="sidebarOpen = true">
            <span class="hamburger" aria-hidden="true" />
          </button>
          <UiBreadcrumb :items="breadcrumbs" />
        </header>

        <main class="content">
          <router-view />
        </main>
      </div>

      <!-- Mobile overlay -->
      <div
        v-if="sidebarOpen"
        class="sidebar-overlay"
        @click="sidebarOpen = false"
      />
    </template>
  </div>
</template>

<style scoped>
.app-shell {
  display: flex;
  min-height: 100vh;
}

.app-main {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
}

.topbar {
  position: sticky;
  top: 0;
  z-index: var(--z-sticky, 200);
  height: var(--topbar-height);
  display: flex;
  align-items: center;
  gap: var(--space-3);
  padding: 0 var(--space-6);
  background: var(--surface);
  border-bottom: 1px solid var(--border);
}

.content {
  flex: 1;
  width: 100%;
  max-width: var(--content-max-width);
  margin: 0 auto;
  padding: var(--space-6);
}

/* Mobile */
.menu-toggle {
  display: none;
  background: none;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  padding: 6px 8px;
  cursor: pointer;
  color: var(--text-dim);
}

.hamburger,
.hamburger::before,
.hamburger::after {
  display: block;
  width: 16px;
  height: 2px;
  background: currentColor;
  border-radius: 1px;
  position: relative;
}

.hamburger::before,
.hamburger::after {
  content: '';
  position: absolute;
  left: 0;
}

.hamburger::before {
  top: -5px;
}

.hamburger::after {
  top: 5px;
}

.sidebar-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(16, 24, 40, 0.4);
  z-index: 250;
}

@media (max-width: 768px) {
  .menu-toggle {
    display: inline-flex;
  }

  .sidebar-overlay {
    display: block;
  }
}

/* User card */
.user-card {
  display: flex;
  flex-direction: column;
  gap: var(--space-2);
}

.user-email {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-2);
  font-size: 12.5px;
  color: var(--text-dim);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}

.user-actions {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-2);
}

.locale-switch {
  display: inline-flex;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
}

.locale-switch button {
  background: var(--surface);
  border: none;
  padding: 4px 8px;
  font-size: 11.5px;
  font-weight: 600;
  color: var(--text-dim);
  cursor: pointer;
}

.locale-switch button.active {
  background: var(--accent-soft);
  color: var(--accent);
}
</style>