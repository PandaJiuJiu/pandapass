import { test, expect } from '@playwright/test'
import {
  signupAndLogin,
  createProjectViaApi,
  createSecretViaApi,
} from './fixtures'

test.describe('secrets', () => {
  test('add a secret through the UI and see it listed', async ({ page, request }) => {
    const account = await signupAndLogin(page, request, 'sec')
    const slug = `sec-${Date.now()}`
    await createProjectViaApi(request, account, 'Secret App', slug)

    await page.goto(`/projects/${slug}`)
    // Default env is the first one (dev). Click "Add or replace a secret".
    await page.getByRole('button', { name: /add or replace a secret/i }).click()
    await expect(page).toHaveURL(new RegExp(`/projects/${slug}/envs/[^/]+/secrets/new$`))

    const key = `API_KEY_${Date.now()}`
    await page.getByLabel(/^Key/).fill(key)
    // The value input is labelled by its placeholder text "value" (lowercase).
    await page.getByLabel('value', { exact: true }).fill('sk-live-super-secret')
    await page.getByRole('button', { name: /^Save$/ }).click()

    // Back on the project page, the secret is listed.
    await expect(page).toHaveURL(new RegExp(`/projects/${slug}$`))
    await expect(page.locator('code.mono', { hasText: key })).toBeVisible()
  })

  test('reveal shows the secret value and hide clears it', async ({ page, request }) => {
    const account = await signupAndLogin(page, request, 'reveal')
    const slug = `reveal-${Date.now()}`
    await createProjectViaApi(request, account, 'Reveal App', slug)
    await createSecretViaApi(request, account, slug, 'dev', 'TOKEN', 'shh-value-123')

    await page.goto(`/projects/${slug}`)
    const row = page.locator('tr', { hasText: 'TOKEN' })
    await row.getByRole('button', { name: /reveal/i }).click()
    await expect(row.locator('.value')).toHaveText('shh-value-123')
    await row.getByRole('button', { name: /hide/i }).click()
    await expect(row.locator('.value')).toHaveCount(0)
  })

  test('delete a secret removes it from the list', async ({ page, request }) => {
    const account = await signupAndLogin(page, request, 'del')
    const slug = `del-${Date.now()}`
    await createProjectViaApi(request, account, 'Del App', slug)
    await createSecretViaApi(request, account, slug, 'dev', 'GONE', 'value')

    await page.goto(`/projects/${slug}`)
    const row = page.locator('tr', { hasText: 'GONE' })
    // The native confirm dialog needs handling. Register the handler BEFORE
    // clicking, otherwise the synchronous dialog event is missed.
    page.once('dialog', (d) => void d.accept())
    await row.getByRole('button', { name: /^Delete$/ }).click()
    await expect(page.locator('code.mono', { hasText: 'GONE' })).toHaveCount(0)
  })
})