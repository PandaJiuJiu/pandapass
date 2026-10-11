/**
 * Global setup for the browser e2e suite.
 *
 * Starts a throwaway PandaPass backend:
 *   - `pandapass-server` on an ephemeral port, fresh SQLite database and age
 *     identity, registration open, rate limit high enough to never trip.
 *   - Vite dev server on another ephemeral port, proxying /api to the server.
 *
 * Also generates a fresh user age identity (for test accounts) and registers
 * the first (admin) account.
 *
 * Server state is written to `e2e/.server-info.json`; global-teardown reads
 * it to shut both processes down. Each test creates its own account, so the
 * shared backend holds no test-specific state.
 */

import { spawn, type ChildProcess } from 'node:child_process'
import { mkdirSync, writeFileSync } from 'node:fs'
import { randomUUID } from 'node:crypto'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import os from 'node:os'
import net from 'node:net'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

export interface ServerInfo {
  serverPid: number
  vitePid: number
  serverPort: number
  vitePort: number
  dbDir: string
  dataDir: string
  serverAgeFile: string
  /** Path to a fresh user age identity (private key) used by test accounts. */
  userAgeIdentityFile: string
  /** The age1... public key derived from the user age identity. */
  userAgePublicKey: string
  /** Credentials of the first-registered (admin) account. */
  adminEmail: string
  adminPassword: string
}

const INFO_PATH = path.join(__dirname, '.server-info.json')

const root = path.resolve(__dirname, '..', '..')
const serverBin = path.join(root, 'target', 'debug', 'pandapass-server')
const cliBin = path.join(root, 'target', 'debug', 'pandapass-cli')

function getFreePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = net.createServer()
    srv.unref()
    srv.on('error', reject)
    srv.listen(0, '127.0.0.1', () => {
      const port = (srv.address() as net.AddressInfo).port
      srv.close(() => resolve(port))
    })
  })
}

function waitForHttp(url: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  return new Promise((resolve, reject) => {
    const attempt = (): void => {
      if (Date.now() > deadline) {
        reject(new Error(`timed out waiting for ${url}`))
        return
      }
      fetch(url)
        .then((res) => {
          if (res.ok) resolve()
          else setTimeout(attempt, 250)
        })
        .catch(() => setTimeout(attempt, 250))
    }
    attempt()
  })
}

function startProcess(
  bin: string,
  args: string[],
  opts: { cwd?: string; env?: NodeJS.ProcessEnv; detached?: boolean } = {},
): ChildProcess {
  return spawn(bin, args, {
    cwd: opts.cwd,
    env: opts.env ?? process.env,
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: opts.detached ?? false,
  })
}

function runAndExit(bin: string, args: string[], env: NodeJS.ProcessEnv): Promise<number | null> {
  return new Promise((resolve) => {
    const child = startProcess(bin, args, { env })
    child.stdout?.on('data', () => {})
    child.stderr?.on('data', () => {})
    child.on('exit', (code) => resolve(code))
    child.on('error', (err) => {
      console.error(`[e2e] failed to spawn ${bin}:`, err)
      resolve(-1)
    })
  })
}

export default async function globalSetup(): Promise<void> {
  const serverPort = await getFreePort()
  const vitePort = await getFreePort()

  const dataDir = path.join(os.tmpdir(), `pandapass-e2e-${randomUUID()}`)
  mkdirSync(dataDir, { recursive: true })
  const dbDir = dataDir
  const dbPath = path.join(dataDir, 'pandapass.db')
  const serverAgeFile = path.join(dataDir, 'server.age')
  const userAgeIdentityFile = path.join(dataDir, 'user.age')

  const baseEnv: NodeJS.ProcessEnv = {
    ...process.env,
    PANDAPASS_LISTEN: `127.0.0.1:${serverPort}`,
    PANDAPASS_DB_URL: `sqlite://${dbPath}?mode=rwc`,
    PANDAPASS_SERVER_AGE_IDENTITY_FILE: serverAgeFile,
    PANDAPASS_PUBLIC_URL: `http://127.0.0.1:${vitePort}`,
    PANDAPASS_ALLOW_REGISTRATION: 'true',
    PANDAPASS_AUTH_RATE_LIMIT_MAX: '100000',
    PANDAPASS_AUTH_RATE_LIMIT_WINDOW_SECS: '60',
    PANDAPASS_REQUIRE_TOTP: 'false',
    PANDAPASS_COOKIE_SECURE: 'false',
    PANDAPASS_BOOTSTRAP: 'false',
    RUST_LOG: 'pandapass_server=warn',
  }

  // 0. Generate a fresh user age identity for test accounts.
  const keygenExit = await runAndExit(cliBin, ['keygen', '--out', userAgeIdentityFile], baseEnv)
  if (keygenExit !== 0) {
    throw new Error(`pandapass-cli keygen exited with ${keygenExit}`)
  }
  const userAgePublicKey = await new Promise<string>((resolve, reject) => {
    const print = startProcess(cliBin, ['keygen', '--print'], { env: baseEnv })
    let out = ''
    print.stdout?.on('data', (d) => {
      out += String(d)
    })
    print.on('exit', (code) => {
      if (code !== 0) reject(new Error(`keygen --print exited with ${code}`))
      else resolve(out.trim())
    })
    print.on('error', reject)
  })

  // 1. Generate the server age identity (idempotent).
  const initExit = await runAndExit(serverBin, ['--init'], baseEnv)
  if (initExit !== 0) {
    throw new Error(`pandapass-server --init exited with ${initExit}`)
  }

  // 2. Start the real server.
  const server = startProcess(serverBin, [], { env: baseEnv })
  server.stdout?.on('data', (d) => process.stdout.write(`[pandapass-server] ${d}`))
  server.stderr?.on('data', (d) => process.stderr.write(`[pandapass-server] ${d}`))
  const serverReady = childExit(server)
  try {
    await waitForHttp(`http://127.0.0.1:${serverPort}/api/v1/health`, 20_000)
  } catch (err) {
    console.error('[e2e] server did not become healthy')
    server.kill('SIGTERM')
    throw err
  }

  // 2.5 Register the first (admin) account through the API.
  const adminEmail = `admin-${randomUUID()}@example.com`
  const adminPassword = 'correct horse battery staple'
  const regRes = await fetch(`http://127.0.0.1:${serverPort}/api/v1/auth/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      email: adminEmail,
      password: adminPassword,
      age_public_key: userAgePublicKey,
    }),
  })
  if (!regRes.ok) {
    console.error('[e2e] admin registration failed:', await regRes.text())
    server.kill('SIGTERM')
    throw new Error(`admin register returned ${regRes.status}`)
  }

  // 3. Start Vite dev server proxying /api to the backend.
  const vite = startProcess(
    'npm',
    ['run', 'dev', '--', '--port', String(vitePort), '--strictPort', '--host', '127.0.0.1'],
    {
      cwd: path.join(root, 'web'),
      env: {
        ...baseEnv,
        CI: 'true',
        VITE_API_PROXY_TARGET: `http://127.0.0.1:${serverPort}`,
      },
    },
  )
  vite.stdout?.on('data', (d) => process.stdout.write(`[vite] ${d}`))
  vite.stderr?.on('data', (d) => process.stderr.write(`[vite] ${d}`))
  try {
    await waitForHttp(`http://127.0.0.1:${vitePort}/`, 30_000)
  } catch (err) {
    console.error('[e2e] vite did not become healthy')
    server.kill('SIGTERM')
    vite.kill('SIGTERM')
    throw err
  }

  const info: ServerInfo = {
    serverPid: server.pid,
    vitePid: vite.pid,
    serverPort,
    vitePort,
    dbDir: dataDir,
    dataDir,
    serverAgeFile,
    userAgeIdentityFile,
    userAgePublicKey,
    adminEmail,
    adminPassword,
  }
  writeFileSync(INFO_PATH, JSON.stringify(info, null, 2))

  console.log(`[e2e] backend ready: server :${serverPort}, vite :${vitePort}`)

  // Keep the child processes alive; this promise only lets us fail fast if a
  // child exits early.
  void serverReady
}

function childExit(child: ChildProcess): Promise<void> {
  return new Promise((resolve) => {
    child.on('exit', () => resolve())
    child.on('error', () => resolve())
  })
}