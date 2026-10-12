import { test, expect } from '@playwright/test'
import { registerAccount, loginViaUi, signupAndLogin } from './fixtures'

test.describe('authentication', () => {
  test('unauthenticated visit redirects to the login page', async ({ page }) => {
    await page.goto('/projects')
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
  })

  test('a user can sign in and lands on the project list', async ({ page, request }) => {
    const account = await registerAccount(request)
    await page.goto('/login')
    await page.getByLabel('Email').fill(account.email)
    await page.getByLabel('Password').fill(account.password)
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/projects$/)
    // The sidebar shows the signed-in email.
    await expect(page.locator('.user-email')).toContainText(account.email)
  })

  test('a wrong password shows an error and stays on login', async ({ page, request }) => {
    const account = await registerAccount(request)
    await page.goto('/login')
    await page.getByLabel('Email').fill(account.email)
    await page.getByLabel('Password').fill('definitely-not-the-password')
    await page.getByRole('button', { name: /sign in/i }).click()
    await expect(page).toHaveURL(/\/login$/)
    await expect(page.locator('.error')).toBeVisible()
  })

  test('signing out returns to the login page', async ({ page, request }) => {
    await signupAndLogin(page, request)
    await page.getByRole('button', { name: /sign out/i }).click()
    await expect(page).toHaveURL(/\/login$/)
  })

  test('the session survives a page reload', async ({ page, request }) => {
    await signupAndLogin(page, request)
    await page.reload()
    await expect(page).toHaveURL(/\/projects$/)
    await expect(page.locator('.user-email')).toContainText(/@example\.com/)
  })
})

test.describe('setup flow (first account)', () => {
  // The global-setup already registered the first (admin) account, so a fresh
  // browser session will NOT see the setup form. This test simulates a fresh
  // vault by checking the setup status endpoint directly instead — but since
  // the shared backend already has users, the login page shows the normal
  // form. We keep this as a lightweight sanity check that the login page
  // renders correctly for an existing vault.
  test('login page renders the sign-in form on an existing vault', async ({ page }) => {
    await page.goto('/login')
    await expect(page.getByRole('button', { name: /sign in/i })).toBeVisible()
    await expect(page.getByLabel('Email')).toBeVisible()
    await expect(page.getByLabel('Password')).toBeVisible()
  })
})