/**
 * Global teardown for the browser e2e suite.
 *
 * Reads `e2e/.server-info.json`, sends SIGTERM to the server and Vite child
 * processes, waits for them to exit, then removes the temp data directory.
 */

import { existsSync, readFileSync, rmSync } from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import type { ServerInfo } from './global-setup'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const INFO_PATH = path.join(__dirname, '.server-info.json')

export default async function globalTeardown(): Promise<void> {
  if (!existsSync(INFO_PATH)) {
    console.warn('[e2e] no .server-info.json found, nothing to tear down')
    return
  }

  const info: ServerInfo = JSON.parse(readFileSync(INFO_PATH, 'utf8'))

  for (const [name, pid] of [
    ['server', info.serverPid],
    ['vite', info.vitePid],
  ] as const) {
    try {
      process.kill(pid, 'SIGTERM')
    } catch (err) {
      const e = err as NodeJS.ErrnoException
      if (e.code !== 'ESRCH') {
        console.warn(`[e2e] failed to signal ${name} (pid ${pid}): ${e.message}`)
      }
    }
  }

  // Wait for both processes to actually exit, so no orphaned server or Vite
  // keeps holding its port (a previous run's orphan on the baseURL port is how
  // stale state used to leak into later runs). Poll with a hard deadline.
  const deadline = Date.now() + 10_000
  for (const pid of [info.serverPid, info.vitePid]) {
    while (Date.now() < deadline) {
      try {
        process.kill(pid, 0) // throws ESRCH when the process is gone
        await new Promise((resolve) => setTimeout(resolve, 100))
      } catch {
        break // process exited
      }
    }
  }

  // Best-effort cleanup of the temp data dir.
  if (info.dataDir) {
    try {
      rmSync(info.dataDir, { recursive: true, force: true })
    } catch {
      // Non-fatal.
    }
  }

  try {
    rmSync(INFO_PATH, { force: true })
  } catch {
    // Non-fatal.
  }

  console.log('[e2e] teardown complete')
}