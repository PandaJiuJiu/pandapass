import { test, expect } from '@playwright/test'
import { signupAndLogin, createProjectViaApi } from './fixtures'

test.describe('projects', () => {
  test('create a project through the UI and see it in the list', async ({ page, request }) => {
    await signupAndLogin(page, request, 'proj')
    await page.goto('/projects')

    await page.getByRole('button', { name: /new project/i }).click()
    await expect(page).toHaveURL(/\/projects\/new$/)

    const name = `My App ${Date.now()}`
    const slug = `my-app-${Date.now()}`
    await page.getByLabel('Project name').fill(name)
    // The dashboard form labels this field "Slug" (see i18n dashboard.projectSlug).
    await page.getByLabel('Slug', { exact: true }).fill(slug)
    // The submit button reads just "Create" (i18n dashboard.createProject).
    await page.getByRole('button', { name: /^Create$/ }).click()

    // Lands back on the list, which now shows the project. Name and slug are
    // separate cells of the same row, so assert each substring on the row
    // itself (an array passed to toContainText expects one element per value).
    await expect(page).toHaveURL(/\/projects$/)
    const row = page.locator('.project-row', { hasText: slug })
    await expect(row).toContainText(name)
    await expect(row.locator('code.mono')).toHaveText(slug)
  })

  test('slug validation blocks an invalid slug', async ({ page, request }) => {
    await signupAndLogin(page, request, 'slug')
    await page.goto('/projects/new')

    await page.getByLabel('Project name').fill('Bad Slug')
    await page.getByLabel('Slug', { exact: true }).fill('UPPER CASE and spaces!')
    // The create button stays disabled while the slug is invalid.
    await expect(page.getByRole('button', { name: /^Create$/ })).toBeDisabled()
  })

  test('a created project opens and shows its environments', async ({ page, request }) => {
    const account = await signupAndLogin(page, request, 'open')
    const slug = `open-${Date.now()}`
    await createProjectViaApi(request, account, 'Open Project', slug)

    await page.goto('/projects')
    await page.locator('.project-row', { hasText: slug }).click()
    await expect(page).toHaveURL(new RegExp(`/projects/${slug}$`))

    // create_project seeds dev/staging/prod; the env tabs should render.
    await expect(page.locator('.env-tab', { hasText: 'prod' })).toBeVisible()
  })
})