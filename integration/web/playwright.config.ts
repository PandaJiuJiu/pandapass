import { readFileSync, existsSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig, devices } from '@playwright/test'

/**
 * PandaPass browser end-to-end tests.
 *
 * The tests run against a real backend: global-setup starts a throwaway
 * `pandapass-server` on an ephemeral port with a fresh SQLite database and a
 * fresh age identity, plus a Vite dev server on another ephemeral port. Every
 * spec shares that backend, but each test registers its own account so there
 * is no cross-test state.
 *
 * Servers are torn down in global-teardown. The whole suite is local-only:
 * there is no CI wiring here on purpose.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const INFO_PATH = path.join(__dirname, '.server-info.json')

// The baseURL is the Vite dev server started by global-setup on an ephemeral
// port. Playwright loads this config before globalSetup runs, so we read the
// port back from the info file the *previous* run's globalSetup wrote. On the
// first run there is no file yet; globalSetup runs before any test, so the
// value is replaced before any page is opened. A stale file from a crashed run
// is fine too: globalSetup overwrites it (and the ports are re-randomised).
function resolveBaseUrl(): string {
  if (existsSync(INFO_PATH)) {
    try {
      const info = JSON.parse(readFileSync(INFO_PATH, 'utf8')) as { vitePort?: number }
      if (typeof info.vitePort === 'number') {
        return `http://127.0.0.1:${info.vitePort}`
      }
    } catch {
      // Fall through to the placeholder below.
    }
  }
  return 'http://127.0.0.1:0'
}

export default defineConfig({
  testDir: '.',
  fullyParallel: false,
  workers: 1,
  // Each spec gets its own backend state via its own account. A single worker
  // keeps the shared server from being hammered by parallel tests.
  timeout: 60_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 2 : 0,
  reporter: [['list']],
  use: {
    baseURL: resolveBaseUrl(),
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    locale: 'en-US',
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  globalSetup: './global-setup',
  globalTeardown: './global-teardown',
})
