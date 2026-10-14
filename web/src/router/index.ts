import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

import LoginView from '@/views/LoginView.vue'
import DashboardView from '@/views/DashboardView.vue'
import ProjectCreateView from '@/views/ProjectCreateView.vue'
import ProjectView from '@/views/ProjectView.vue'
import EnvironmentCreateView from '@/views/EnvironmentCreateView.vue'
import SecretCreateView from '@/views/SecretCreateView.vue'
import TokensView from '@/views/TokensView.vue'
import TokenCreateView from '@/views/TokenCreateView.vue'
import AuditView from '@/views/AuditView.vue'
import DynamicCredsView from '@/views/DynamicCredsView.vue'
import PoliciesView from '@/views/PoliciesView.vue'
import PkiView from '@/views/PkiView.vue'
import ScanView from '@/views/ScanView.vue'
import UsersView from '@/views/UsersView.vue'
import UserCreateView from '@/views/UserCreateView.vue'
import HelpView from '@/views/HelpView.vue'

export const router = createRouter({
  history: createWebHistory(),
  routes: [
    { path: '/', redirect: '/projects' },
    { path: '/login', component: LoginView, meta: { public: true } },
    { path: '/projects', component: DashboardView, meta: { title: 'nav.projects' } },
    { path: '/projects/new', component: ProjectCreateView, meta: { title: 'nav.projects', parent: '/projects' } },
    {
      path: '/projects/:slug',
      component: ProjectView,
      props: true,
      meta: { title: 'nav.projects', paramLabel: true, parent: '/projects' },
    },
    {
      path: '/projects/:slug/envs/new',
      component: EnvironmentCreateView,
      props: true,
      meta: { title: 'nav.projects', parent: '/projects/:slug', paramLabel: true },
    },
    {
      path: '/projects/:slug/envs/:env/secrets/new',
      component: SecretCreateView,
      props: true,
      meta: { title: 'nav.projects', parent: '/projects/:slug', paramLabel: true },
    },
    { path: '/tokens', component: TokensView, meta: { title: 'nav.tokens' } },
    { path: '/tokens/new', component: TokenCreateView, meta: { title: 'nav.tokens', parent: '/tokens' } },
    { path: '/audit', component: AuditView, meta: { title: 'nav.audit' } },
    {
      path: '/projects/:slug/dynamic-creds',
      component: DynamicCredsView,
      props: true,
      meta: { title: 'nav.dynamicCreds', parent: '/projects/:slug', paramLabel: true },
    },
    { path: '/policies', component: PoliciesView, meta: { title: 'nav.policies' } },
    { path: '/pki', component: PkiView, meta: { title: 'nav.pki' } },
    { path: '/scan', component: ScanView, meta: { title: 'nav.scan' } },
    { path: '/users', component: UsersView, meta: { title: 'nav.users', admin: true } },
    { path: '/users/new', component: UserCreateView, meta: { title: 'nav.users', parent: '/users', admin: true } },
    { path: '/help', component: HelpView, meta: { title: 'nav.help' } },
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

  // Admin-only routes: a plain member is redirected to the project list.
  if (to.meta.admin && auth.user.global_role !== 'admin') {
    return { path: '/projects' }
  }

  return true
})