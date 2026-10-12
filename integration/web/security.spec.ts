import { test, expect } from '@playwright/test'
import { signupAndLogin, adminAccount, loginViaUi, serverBaseUrl } from './fixtures'

test.describe('session & CSRF', () => {
  test('session cookie is HttpOnly; CSRF cookie is not', async ({ page, request }) => {
    await signupAndLogin(page, request)
    const cookies = await page.context().cookies()
    const session = cookies.find((c) => c.name === 'pandapass_session')
    const csrf = cookies.find((c) => c.name === 'pandapass_csrf')
    expect(session, 'session cookie exists').toBeTruthy()
    expect(session!.httpOnly, 'session cookie must be HttpOnly').toBe(true)
    expect(csrf, 'csrf cookie exists').toBeTruthy()
    expect(csrf!.httpOnly, 'csrf cookie must NOT be HttpOnly (read by JS)').toBe(false)
  })

  test('a mutating fetch without the CSRF header is rejected', async ({ page, request }) => {
    const account = await signupAndLogin(page, request)
    const slug = `csrf-${Date.now()}`
    // Create a project through the API so the page has something to mutate.
    const res = await page.evaluate(
      async ({ projectSlug, email }) => {
        const headers: Record<string, string> = { 'Content-Type': 'application/json' }
        // Deliberately NO x-csrf-token header.
        const r = await fetch('/api/v1/projects', {
          method: 'POST',
          headers,
          credentials: 'same-origin',
          body: JSON.stringify({ name: 'CSRF', slug: projectSlug }),
        })
        return { status: r.status }
      },
      { projectSlug: slug, email: account.email },
    )
    expect(res.status).toBe(403)
  })

  test('a mutating fetch WITH the CSRF header succeeds', async ({ page, request }) => {
    await signupAndLogin(page, request)
    const slug = `csrf-ok-${Date.now()}`
    const res = await page.evaluate(async ({ projectSlug }) => {
      const csrfMatch = document.cookie.match(/(?:^|;\s*)pandapass_csrf=([^;]+)/)
      const csrf = csrfMatch ? decodeURIComponent(csrfMatch[1]) : ''
      const r = await fetch('/api/v1/projects', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-csrf-token': csrf },
        credentials: 'same-origin',
        body: JSON.stringify({ name: 'CSRF OK', slug: projectSlug }),
      })
      return { status: r.status }
    }, { projectSlug: slug })
    expect(res.status).toBe(200)
  })
})

test.describe('admin boundaries', () => {
  test('a regular user is redirected away from /users', async ({ page, request }) => {
    await signupAndLogin(page, request, 'member')
    await page.goto('/users')
    await expect(page).toHaveURL(/\/projects$/)
  })

  test('an admin can reach /users', async ({ page }) => {
    await loginViaUi(page, adminAccount())
    await page.goto('/users')
    await expect(page).toHaveURL(/\/users$/)
    // The Users page action is labelled "Create a user".
    await expect(page.getByRole('button', { name: /create a user/i })).toBeVisible()
  })
})

test.describe('locale', () => {
  test('switching locale to Chinese re-renders the sidebar', async ({ page, request }) => {
    await signupAndLogin(page, request)
    await page.locator('.locale-switch').getByRole('button', { name: '中文' }).click()
    await expect(page.locator('.app-shell')).toContainText('项目')
  })
})