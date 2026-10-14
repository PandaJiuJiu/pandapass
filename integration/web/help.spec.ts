import { test, expect } from '@playwright/test'
import { signupAndLogin } from './fixtures'

test.describe('help / quick start page', () => {
  test('sidebar shows a Quick Start entry and the help page renders', async ({
    page,
    request,
  }) => {
    await signupAndLogin(page, request)

    // Sidebar entry is visible.
    await expect(page.getByRole('link', { name: /quick start/i })).toBeVisible()

    // Navigate to /help.
    await page.getByRole('link', { name: /quick start/i }).click()
    await expect(page).toHaveURL(/\/help$/)

    // Page header renders.
    await expect(page.getByRole('heading', { name: /quick start/i })).toBeVisible()

    // Download links for all four platforms.
    const downloadLinks = page.locator('.download-link')
    await expect(downloadLinks).toHaveCount(4)

    // Code blocks render with copy buttons.
    await expect(page.locator('.code-block').first()).toBeVisible()
    await expect(page.getByRole('button', { name: /copy/i }).first()).toBeVisible()

    // The server URL section is present.
    await expect(page.locator('.server-section')).toBeVisible()
  })

  test('copy button copies a command to the clipboard', async ({ page, request }) => {
    await signupAndLogin(page, request)
    await page.goto('/help')

    const firstCopy = page.getByRole('button', { name: /^copy$/i }).first()
    await firstCopy.click()
    // Button flips to "Copied".
    await expect(page.getByRole('button', { name: /copied/i }).first()).toBeVisible()
  })

  test('download links point to the GitHub release', async ({ page, request }) => {
    await signupAndLogin(page, request)
    await page.goto('/help')

    const firstLink = page.locator('.download-link').first()
    const href = await firstLink.getAttribute('href')
    expect(href).toContain('https://github.com/PandaJiuJiu/pandapass/releases/download/v0.0.1/')
  })
})