import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

import LoginView from '@/views/LoginView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ProjectView from '@/views/ProjectView.vue'
import TokensView from '@/views/TokensView.vue'
import AuditView from '@/views/AuditView.vue'
import DynamicCredsView from '@/views/DynamicCredsView.vue'
import PoliciesView from '@/views/PoliciesView.vue'
import PkiView from '@/views/PkiView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/projects' },
    { path: '/login', component: LoginView, meta: { public: true } },
    { path: '/projects', component: DashboardView },
    { path: '/projects/:slug', component: ProjectView, props: true },
    { path: '/tokens', component: TokensView },
    { path: '/audit', component: AuditView },
    { path: '/projects/:slug/dynamic-creds', component: DynamicCredsView, props: true },
    { path: '/policies', component: PoliciesView },
    { path: '/pki', component: PkiView },
  ],
})

/**
 * Gate every route on a valid session. The check calls the server rather than
 * trusting anything in the store: a page reload leaves the store empty, and a
 * client-side-only check would bounce a signed-in user to the login form on
 * every refresh.
 */
router.beforeEach(async (to) => {
  if (to.meta.public) return true

  const auth = useAuthStore()
  if (!auth.initialized) {
    try {
      await auth.fetchMe()
    } catch {
      // Not signed in, or the server is unreachable. Either way, the login
      // page is the honest destination.
      return { path: '/login' }
    }
  }

  if (!auth.user) return { path: '/login' }
  return true
})
