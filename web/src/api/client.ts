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
  disabled_at: string | null
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

// ── dynamic credentials (M2) ──

export type DynamicCredKind = 'postgres' | 'mysql' | 'redis'

export interface DynamicCred {
  id: string
  project_id: string
  env_id: string
  kind: DynamicCredKind
  username: string
  password_enc: EncryptedSecret
  ttl_seconds: number
  issued_at: string
  expires_at: string
  revoked_at: string | null
  created_by: string
}

export interface CreateDynamicCredRequest {
  kind: DynamicCredKind
  username: string
  ttl_seconds: number
}

// ── policies (M3) ──

export interface Policy {
  id: string
  name: string
  rego_source: string
  enabled: boolean
  created_at: string
  updated_at: string
}

export interface PolicyBinding {
  id: string
  policy_id: string
  project_id: string | null
  env_id: string | null
  created_at: string
}

// ── PKI/CA (M4) ──

export type CaKeyType = 'root' | 'intermediate'

export interface CaKey {
  id: string
  kind: CaKeyType
  key_enc: EncryptedSecret
  cert_pem: string
  not_before: string
  not_after: string
  revoked_at: string | null
  created_by: string
  created_at: string
}

export type SshKeyType = 'rsa' | 'ed25519' | 'ecdsa'

export interface SshCert {
  id: string
  user_id: string
  project_id: string | null
  principal: string
  cert_pem: string
  key_type: SshKeyType
  valid_before: string
  valid_after: string
  revoked_at: string | null
  created_by: string
  created_at: string
}

// ── secret scanning (M4) ──

export type ScanSeverity = 'high' | 'medium' | 'low'

/**
 * A persisted scan finding. Deliberately contains NO plaintext fragment —
 * only the secret key's name, the rule that fired, and the byte offsets of
 * the match inside the scanned value.
 */
export interface ScanFinding {
  id: string
  project_id: string
  env_id: string
  secret_key: string
  rule_id: string
  rule_name: string
  severity: ScanSeverity
  match_start: number
  match_end: number
  detected_at: string
}

/** Aggregate summary of a scan run (also stored in the audit meta). */
export interface ScanRunResult {
  secrets_scanned: number
  findings: number
  projects: number
  envs: number
  errors: number
}

// ── encrypted secret type (shared with core) ──

export interface EncryptedSecret {
  nonce: string
  ciphertext: string
}

// ── auth ───────────────────────────────────────────────────────────────────

export interface LoginResponse {
  user: User
  session_token: string
  requires_totp: boolean
  key_enrolled: boolean
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

  // ── setup & admin user management ──

  /** True on a fresh vault: no users exist, so the login page becomes a
   *  "create administrator" form. */
  setupStatus: () => get<{ needs_setup: boolean }>('/setup/status'),

  adminListUsers: () => get<{ users: User[] }>('/admin/users'),
  adminCreateUser: (email: string, password: string) =>
    post<{ user: User }>('/admin/users', { email, password }),
  adminDisableUser: (id: string) => post<{ success: boolean }>(`/admin/users/${id}/disable`),
  adminEnableUser: (id: string) => post<{ success: boolean }>(`/admin/users/${id}/enable`),

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

  // ── dynamic credentials (M2) ──

  listDynamicCreds: (project: string, env: string) =>
    get<DynamicCred[]>(`/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/creds`),

  createDynamicCred: (project: string, env: string, body: CreateDynamicCredRequest) =>
    post<DynamicCred>(`/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/creds`, body),

  revokeDynamicCred: (project: string, env: string, id: string) =>
    del<void>(`/projects/${encodeURIComponent(project)}/envs/${encodeURIComponent(env)}/creds/${encodeURIComponent(id)}`),

  // ── policies (M3) ──

  listPolicies: (enabledOnly = true) =>
    get<Policy[]>(`/policies?enabled_only=${enabledOnly}`),

  createPolicy: (name: string, regoSource: string) =>
    post<Policy>('/policies', { name, rego_source: regoSource }),

  getPolicy: (id: string) => get<Policy>(`/policies/${id}`),

  updatePolicy: (id: string, name?: string, regoSource?: string, enabled?: boolean) =>
    patch<void>(`/policies/${id}`, { name, rego_source: regoSource, enabled }),

  deletePolicy: (id: string) => del<void>(`/policies/${id}`),

  listPolicyBindings: (projectId?: string, envId?: string) => {
    const params = new URLSearchParams()
    if (projectId) params.set('project_id', projectId)
    if (envId) params.set('env_id', envId)
    return get<PolicyBinding[]>(`/policies/bindings?${params}`)
  },

  bindPolicy: (policyId: string, projectId?: string, envId?: string) =>
    post<PolicyBinding>('/policies/bindings', { policy_id: policyId, project_id: projectId, env_id: envId }),

  unbindPolicy: (id: string) => del<void>(`/policies/bindings/${id}`),

  // ── PKI/CA (M4) ──

  listCaKeys: (includeRevoked = false) =>
    get<CaKey[]>(`/ca?include_revoked=${includeRevoked}`),

  createCaKey: (kind: CaKeyType, keyPem: string, certPem: string, notBefore: string, notAfter: string) =>
    post<CaKey>('/ca', { kind, key_pem: keyPem, cert_pem: certPem, not_before: notBefore, not_after: notAfter }),
  generateCaKey: (kind: CaKeyType, subjectDn: string, notBefore: string, notAfter: string, parentCaId?: string) =>
    post<CaKey>('/ca/generate', {
      kind,
      subject_dn: subjectDn,
      not_before: notBefore,
      not_after: notAfter,
      ...(parentCaId ? { parent_ca_id: parentCaId } : {}),
    }),

  getCaKey: (id: string) => get<CaKey>(`/ca/${id}`),

  revokeCaKey: (id: string) => del<void>(`/ca/${id}`),

  listSshCerts: (userId?: string, projectId?: string, includeRevoked = false) => {
    const params = new URLSearchParams()
    if (userId) params.set('user_id', userId)
    if (projectId) params.set('project_id', projectId)
    params.set('include_revoked', String(includeRevoked))
    return get<SshCert[]>(`/ssh-certs?${params}`)
  },

  createSshCert: (userId: string, principal: string, certPem: string, keyType: SshKeyType, validBefore: string, validAfter: string, projectId?: string) =>
    post<SshCert>('/ssh-certs', { user_id: userId, project_id: projectId, principal, cert_pem: certPem, key_type: keyType, valid_before: validBefore, valid_after: validAfter }),

  revokeSshCert: (id: string) => del<void>(`/ssh-certs/${id}`),

  // ── secret scanning (M4) ──

  /** Trigger a full scan of every active secret. Admin only. */
  triggerScan: () => post<ScanRunResult>('/scan'),

  /** List persisted scan findings. Admin only. */
  getScanResults: (projectId?: string, envId?: string, page = 1, perPage = 50) => {
    const params = new URLSearchParams({
      page: String(page),
      per_page: String(perPage),
    })
    if (projectId) params.set('project_id', projectId)
    if (envId) params.set('env_id', envId)
    return get<Paginated<ScanFinding>>(`/scan/results?${params}`)
  },
}
