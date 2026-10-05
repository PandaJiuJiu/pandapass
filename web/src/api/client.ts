/**
 * Typed wrapper over the PandaPass HTTP API.
 *
 * Two rules shape this file.
 *
 * First, session auth is cookie-based, so every mutating request must carry the
 * CSRF token the server issued. `credentials: 'include'` alone is not enough —
 * the server requires the cookie *and* a matching `x-csrf-token` header, which
 * is what makes the double-submit pattern work.
 *
 * Second, nothing here may put a secret value anywhere it lingers. Values are
 * returned to callers and dropped; they are never cached, never logged, and
 * never written to storage.
 */

const BASE = '/api/v1'

/** The CSRF token the server set as a cookie at login. */
function csrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)pandapass_csrf=([^;]+)/)
  return match ? decodeURIComponent(match[1]) : null
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message)
    this.name = 'ApiError'
  }

  /** True when the session is gone and the user needs to sign in again. */
  get isUnauthenticated(): boolean {
    return this.status === 401
  }
}

/**
 * Called when the server rejects a request for want of a CSRF token. The token
 * is rotated at login, so a stale one means the session was replaced — the UI
 * needs to know rather than silently retrying into the same failure.
 */
type UnauthorizedHandler = () => void
let onUnauthorized: UnauthorizedHandler = () => {}

export function setUnauthorizedHandler(fn: UnauthorizedHandler): void {
  onUnauthorized = fn
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' }

  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const csrf = csrfToken()
  if (csrf) headers['x-csrf-token'] = csrf

  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    // Session lives in an HttpOnly cookie, so it rides along automatically.
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (!res.ok) {
    // The error body is `{"error":{"code","message"}}`. Anything else — an HTML
    // 502 from a proxy, say — is reported verbatim rather than parsed wrongly.
    const payload = await res.json().catch(() => null)
    const code = payload?.error?.code ?? 'unknown'
    const message = payload?.error?.message ?? `Request failed (${res.status})`

    if (res.status === 401) onUnauthorized()
    throw new ApiError(res.status, code, message)
  }

  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

const get = <T>(path: string) => request<T>('GET', path)
const post = <T>(path: string, body?: unknown) => request<T>('POST', path, body)
const patch = <T>(path: string, body?: unknown) => request<T>('PATCH', path, body)
const del = <T>(path: string) => request<T>('DELETE', path)

// ── types ──────────────────────────────────────────────────────────────────

export type ProjectRole = 'owner' | 'editor' | 'viewer'
export type GlobalRole = 'admin' | 'user'

export interface User {
  id: string
  email: string
  global_role: GlobalRole
  totp_enabled: boolean
  created_at: string
  last_login_at: string | null
}

export interface Project {
  id: string
  name: string
  slug: string
  description: string | null
  created_at: string
  updated_at: string
  user_role: ProjectRole | null
}

export interface Environment {
  id: string
  project_id: string
  name: string
  slug: string
  description: string | null
  created_at: string
  updated_at: string
}

export interface SecretMeta {
  id: string
  project_id: string
  env_id: string
  key: string
  version: number
  created_by: string
  created_at: string
  updated_at: string
  deleted_at: string | null
}

export interface SecretValue {
  key: string
  value: string
  version: number
  updated_at: string
}

export interface AuditEntry {
  id: string
  ts: string
  user_id: string | null
  action: string
  project_id: string | null
  env_id: string | null
  secret_key: string | null
  ip: string | null
  user_agent: string | null
  outcome: 'success' | 'failure' | 'denied' | 'error'
  meta: Record<string, unknown> | null
}

export interface Paginated<T> {
  items: T[]
  total: number
  page: number
  per_page: number
}

export interface ServiceToken {
  id: string
  name: string
  project_id: string | null
  env_id: string | null
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  created_at: string
  revoked_at: string | null
}

// ── auth ───────────────────────────────────────────────────────────────────

export interface LoginResponse {
  user: User
  session_token: string
  requires_totp: boolean
}

export const api = {
  register: (email: string, password: string, agePublicKey?: string) =>
    post<LoginResponse>('/auth/register', {
      email,
      password,
      age_public_key: agePublicKey ?? null,
    }),

  login: (email: string, password: string, totpCode?: string) =>
    post<LoginResponse>('/auth/login', {
      email,
      password,
      totp_code: totpCode ?? null,
    }),

  logout: () => post<void>('/auth/logout'),
  me: () => get<User>('/auth/me'),

  enrollKey: (agePublicKey: string, rotate: boolean) =>
    post<{ ok: boolean }>('/auth/key/enroll', {
      age_public_key: agePublicKey,
      rotate,
    }),

  // ── projects & environments ──

  listProjects: () => get<Project[]>('/projects'),
  getProject: (slug: string) => get<Project>(`/projects/${encodeURIComponent(slug)}`),
  createProject: (name: string, slug: string, description?: string) =>
    post<Project>('/projects', { name, slug, description: description || null }),
  updateProject: (slug: string, name?: string, description?: string) =>
    patch<Project>(`/projects/${encodeURIComponent(slug)}`, { name, description }),
  deleteProject: (slug: string) => del<void>(`/projects/${encodeURIComponent(slug)}`),

  listEnvs: (project: string) =>
    get<Environment[]>(`/projects/${encodeURIComponent(project)}/envs`),
  createEnv: (project: string, name: string, slug: string, description?: string) =>
    post<Environment>(`/projects/${encodeURIComponent(project)}/envs`, {
      name,
      slug,
      description: description || null,
    }),
  deleteEnv: (project: string, env: string) =>
    del<void>(`/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}`),

  // ── secrets ──

  listSecrets: (project: string, env: string) =>
    get<Paginated<SecretMeta>>(
      `/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/secrets`,
    ),

  /**
   * Read a secret's value. The result is handed straight to the caller; this
   * module keeps no reference to it beyond the return, so nothing accumulates
   * in a store or a cache.
   */
  getSecret: (project: string, env: string, key: string) =>
    get<SecretValue>(
      `/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/secrets/${encodeURIComponent(key)}`,
    ),

  setSecret: (project: string, env: string, key: string, value: string) =>
    post<SecretValue>(
      `/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/secrets`,
      { key, value },
    ),

  deleteSecret: (project: string, env: string, key: string) =>
    del<void>(
      `/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/secrets/${encodeURIComponent(key)}`,
    ),

  // ── tokens ──

  listTokens: () => get<ServiceToken[]>('/tokens'),
  createToken: (body: {
    name: string
    project_id?: string | null
    env_id?: string | null
    scopes: string[]
    expires_at?: string | null
  }) => post<{ token: ServiceToken; plain_token: string }>('/tokens', body),
  revokeToken: (id: string) => del<void>(`/tokens/${id}`),

  // ── audit ──

  listAudit: (projectId?: string, page = 1, perPage = 50) => {
    const params = new URLSearchParams({ page: String(page), per_page: String(perPage) })
    if (projectId) params.set('project_id', projectId)
    return get<Paginated<AuditEntry>>(`/audit?${params}`)
  },
}
