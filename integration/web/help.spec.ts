import { test, expect } from '@playwright/test'
import { adminAccount, loginViaUi } from './fixtures'

test.describe('help / quick start page', () => {
  // The Quick Start entry lives under the Admin group (below Users), so these
  // tests sign in with the admin account created in global setup.
  test('sidebar shows a Quick Start entry and the help page renders', async ({
    page,
  }) => {
    await loginViaUi(page, adminAccount())

    // Sidebar entry is visible (under Admin group, after Users).
    await expect(page.getByRole('link', { name: /quick start/i })).toBeVisible()

    // Navigate to /help.
    await page.getByRole('link', { name: /quick start/i }).click()
    await expect(page).toHaveURL(/\/help$/)

    // Page header renders.
    await expect(page.getByRole('heading', { name: 'Quick Start', exact: true })).toBeVisible()

    // First section is the AI Agent quick start.
    await expect(page.getByRole('heading', { name: /ai agent/i })).toBeVisible()

    // Download links for all four platforms.
    const downloadLinks = page.locator('.download-link')
    await expect(downloadLinks).toHaveCount(4)

    // Code blocks render with copy buttons.
    await expect(page.locator('.code-block').first()).toBeVisible()
    await expect(page.getByRole('button', { name: /copy/i }).first()).toBeVisible()

    // The server URL section is present.
    await expect(page.locator('.server-section')).toBeVisible()
  })

  test('copy button copies a command to the clipboard', async ({ page }) => {
    await loginViaUi(page, adminAccount())
    await page.goto('/help')

    const firstCopy = page.getByRole('button', { name: /^copy$/i }).first()
    await firstCopy.click()
    // Button flips to "Copied".
    await expect(page.getByRole('button', { name: /copied/i }).first()).toBeVisible()
  })

  test('download links point to the GitHub release', async ({ page }) => {
    await loginViaUi(page, adminAccount())
    await page.goto('/help')

    const firstLink = page.locator('.download-link').first()
    const href = await firstLink.getAttribute('href')
    expect(href).toContain('https://github.com/PandaJiuJiu/pandapass/releases/download/v0.0.1/')
  })
})