/**
 * Shared helpers for the browser e2e suite.
 *
 * Accounts are created through the API (with an age public key so they can
 * store secrets), then the test signs in through the real UI. This keeps the
 * browser flow honest while avoiding the chicken-and-egg of a fresh vault:
 * the first account would otherwise bootstraps as admin and lock the vault.
 */

import { readFileSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { APIRequestContext, Page, expect } from '@playwright/test'
import type { ServerInfo } from './global-setup'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const INFO_PATH = path.join(__dirname, '.server-info.json')

let cached: ServerInfo | null = null

export function getServerInfo(): ServerInfo {
  if (!cached) {
    cached = JSON.parse(readFileSync(INFO_PATH, 'utf8')) as ServerInfo
  }
  return cached
}

export function serverBaseUrl(): string {
  return `http://127.0.0.1:${getServerInfo().serverPort}`
}

export interface TestAccount {
  email: string
  password: string
}

/** The first-registered admin account (created in global setup). */
export function adminAccount(): TestAccount {
  const info = getServerInfo()
  return { email: info.adminEmail, password: info.adminPassword }
}

/** Create an account through the API and return its credentials. */
export async function registerAccount(
  request: APIRequestContext,
  prefix = 'user',
): Promise<TestAccount> {
  const { userAgePublicKey } = getServerInfo()
  const email = `${prefix}-${Date.now()}-${Math.floor(Math.random() * 1e6)}@example.com`
  const password = 'correct horse battery staple'

  const res = await request.post(`${serverBaseUrl()}/api/v1/auth/register`, {
    data: {
      email,
      password,
      age_public_key: userAgePublicKey,
    },
  })
  expect(res.ok(), `register failed (${res.status()}): ${await res.text()}`).toBeTruthy()
  return { email, password }
}

/** Sign in through the real login form. */
export async function loginViaUi(page: Page, account: TestAccount): Promise<void> {
  await page.goto('/login')
  await page.getByLabel('Email').fill(account.email)
  await page.getByLabel('Password').fill(account.password)
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page).toHaveURL(/\/projects$/)
}

/** Register an account via API and sign in through the UI. */
export async function signupAndLogin(
  page: Page,
  request: APIRequestContext,
  prefix = 'user',
): Promise<TestAccount> {
  const account = await registerAccount(request, prefix)
  await loginViaUi(page, account)
  return account
}

/** Create a project through the API (returns its slug). */
export async function createProjectViaApi(
  request: APIRequestContext,
  account: TestAccount,
  name: string,
  slug: string,
): Promise<void> {
  const res = await request.post(`${serverBaseUrl()}/api/v1/projects`, {
    headers: { authorization: `Bearer ${await sessionTokenFor(request, account)}` },
    data: { name, slug },
  })
  expect(res.ok(), `create project failed (${res.status()}): ${await res.text()}`).toBeTruthy()
}

/**
 * Obtain a session token for an account by logging in through the API.
 * The CLI agent header is required for the token to appear in the response
 * body (the web client never gets one).
 */
export async function sessionTokenFor(
  request: APIRequestContext,
  account: TestAccount,
): Promise<string> {
  const res = await request.post(`${serverBaseUrl()}/api/v1/auth/login`, {
    headers: { 'x-pandapass-agent': 'cli' },
    data: { email: account.email, password: account.password },
  })
  expect(res.ok(), `login failed (${res.status()}): ${await res.text()}`).toBeTruthy()
  const body = (await res.json()) as { session_token?: string }
  const token = body.session_token
  expect(token, 'session token in response body').toBeTruthy()
  return token as string
}

/** Create a secret through the API. */
export async function createSecretViaApi(
  request: APIRequestContext,
  account: TestAccount,
  project: string,
  env: string,
  key: string,
  value: string,
): Promise<void> {
  const res = await request.post(
    `${serverBaseUrl()}/api/v1/projects/${project}/envs/${env}/secrets`,
    {
      headers: { authorization: `Bearer ${await sessionTokenFor(request, account)}` },
      data: { key, value },
    },
  )
  expect(res.ok(), `set secret failed (${res.status()}): ${await res.text()}`).toBeTruthy()
}