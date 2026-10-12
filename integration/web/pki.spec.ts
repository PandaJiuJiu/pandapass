import { test, expect } from '@playwright/test'
import { loginViaUi, adminAccount } from './fixtures'

test.describe('PKI / CA', () => {
  test('an admin can generate a root CA on the server without uploading a private key', async ({ page }) => {
    await loginViaUi(page, adminAccount())
    await page.goto('/pki')
    await expect(page).toHaveURL(/\/pki$/)

    // Open the Create CA modal.
    await page.getByRole('button', { name: /add ca key/i }).click()

    // Generate mode is the default — no private-key textarea is shown.
    await expect(page.getByRole('button', { name: /generate on server/i })).toHaveClass(/active/)
    await expect(page.getByLabel('Private Key (PEM)')).not.toBeVisible()

    // Choose root and fill in the subject DN.
    await page.getByLabel('Kind').selectOption('root')
    await page.getByLabel('Subject DN').fill('CN=PandaPass E2E Root,O=PandaPass')

    // Submit.
    await page.getByRole('button', { name: 'Add', exact: true }).click()

    // The modal closes and the new root CA appears in the table.
    await expect(page.getByText('ROOT', { exact: true })).toBeVisible()
  })

  test('generating an intermediate CA requires choosing a parent root', async ({ page }) => {
    await loginViaUi(page, adminAccount())
    await page.goto('/pki')

    // Open the Create CA modal.
    await page.getByRole('button', { name: /add ca key/i }).click()

    // Default kind is intermediate; with no root CA yet, submitting without a
    // parent shows the required-message.
    await page.getByLabel('Subject DN').fill('CN=PandaPass E2E Issuing,O=PandaPass')
    await page.getByRole('button', { name: 'Add', exact: true }).click()
    await expect(page.getByText(/parent root ca is required/i)).toBeVisible()
  })
})