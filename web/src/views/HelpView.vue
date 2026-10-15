<script setup lang="ts">
import { computed, ref } from 'vue'
import { useI18n } from 'vue-i18n'
import UiPageHeader from '@/components/ui/UiPageHeader.vue'
import UiCard from '@/components/ui/UiCard.vue'
import UiButton from '@/components/ui/UiButton.vue'

const { t, locale } = useI18n()

const copied = ref<string | null>(null)

/** Server base URL shown in docs — derived from the current page origin. */
const serverBase = computed(() => window.location.origin)

async function copy(cmd: string, id: string): Promise<void> {
  let ok = false
  try {
    // Secure contexts (HTTPS or localhost) get the async clipboard API.
    await navigator.clipboard.writeText(cmd)
    ok = true
  } catch {
    ok = false
  }
  if (!ok) {
    // Fallback for plain HTTP on a LAN: select a hidden textarea and exec
    // the old copy command. Works in every browser, no permissions needed.
    try {
      const ta = document.createElement('textarea')
      ta.value = cmd
      ta.style.position = 'fixed'
      ta.style.opacity = '0'
      document.body.appendChild(ta)
      ta.select()
      ok = document.execCommand('copy')
      document.body.removeChild(ta)
    } catch {
      ok = false
    }
  }
  if (ok) {
    copied.value = id
    setTimeout(() => {
      if (copied.value === id) copied.value = null
    }, 1500)
  }
}

const isZh = computed(() => locale.value === 'zh-CN')

/** Release download base URL (GitHub). */
const releaseBase = 'https://github.com/PandaJiuJiu/pandapass/releases/download/v0.0.1'

const downloads = [
  { label: 'Linux x86_64', file: 'pandapass-cli-0.0.1-linux-x86_64.tar.gz' },
  { label: 'macOS Apple Silicon', file: 'pandapass-cli-0.0.1-macos-aarch64.tar.gz' },
  { label: 'macOS Intel', file: 'pandapass-cli-0.0.1-macos-x86_64.tar.gz' },
  { label: 'Windows x86_64', file: 'pandapass-cli-0.0.1-windows-x86_64.zip' },
]

interface DocStep {
  title: string
  body: string[]
  code?: { label: string; cmd: string }[]
  note?: string
}

const zh: DocStep[] = [
  {
    title: '1. AI Agent 快速使用',
    body: [
      '想让 AI 助手（如 Claude Code）自动学会管理 PandaPass 吗？把下面这句话发送给你的 AI 助手，它会访问这个帮助页面，并自动创建一个 PandaPass SKILL。',
    ],
    code: [
      {
        label: '发送给 AI 的一句话',
        cmd: `请访问 ${serverBase.value}/help 获取 PandaPass 的完整使用说明，然后创建一个 PandaPass SKILL，让我能通过命令行管理密钥——包括登录、创建项目/环境、设置/读取密钥，以及用 run 注入密钥执行命令。`,
      },
    ],
  },
  {
    title: '2. 下载 CLI',
    body: [
      '从 GitHub Release 下载对应平台的压缩包。解压后把二进制放到 PATH 中（例如 ~/.local/bin，无需 sudo）。',
    ],
    code: [
      { label: 'Linux / macOS', cmd: `curl -L -o pandapass-cli.tar.gz ${releaseBase}/pandapass-cli-0.0.1-linux-x86_64.tar.gz\ntar -xzf pandapass-cli.tar.gz\nmkdir -p ~/.local/bin\nmv pandapass-cli ~/.local/bin/` },
      { label: 'macOS (Apple Silicon)', cmd: `curl -L -o pandapass-cli.tar.gz ${releaseBase}/pandapass-cli-0.0.1-macos-aarch64.tar.gz\ntar -xzf pandapass-cli.tar.gz\nmkdir -p ~/.local/bin\nmv pandapass-cli ~/.local/bin/` },
      { label: 'Windows (PowerShell)', cmd: `Invoke-WebRequest -Uri "${releaseBase}/pandapass-cli-0.0.1-windows-x86_64.zip" -OutFile pandapass-cli.zip\nExpand-Archive pandapass-cli.zip\nMove-Item pandapass-cli.exe $env:LOCALAPPDATA\\pandapass\\` },
    ],
  },
  {
    title: '3. 生成 age 密钥',
    body: [
      'age 密钥对用于加解密你的密钥。运行 keygen 生成身份文件，它会输出公钥——注册账户时需要填写。',
    ],
    code: [
      { label: '生成并保存到默认路径', cmd: 'pandapass-cli keygen' },
      { label: '只打印公钥', cmd: 'pandapass-cli keygen --print' },
    ],
  },
  {
    title: '4. 注册 / 登录',
    body: [
      '使用 Web 界面或 CLI 注册账户。注册时需要提供 age 公钥（来自上一步）。',
    ],
    code: [
      { label: '注册（需先在 Web 界面创建管理员账户）', cmd: `pandapass-cli login --server ${serverBase.value.replace(':15173', ':18233')} --email you@example.com --password-stdin` },
    ],
  },
  {
    title: '5. 配置 CLI',
    body: [
      '把服务器地址写入配置，后续命令就不用每次带 --server 了。',
    ],
    code: [
      { label: '设置服务器地址', cmd: `pandapass-cli config set-server ${serverBase.value.replace(':15173', ':18233')}` },
      { label: '设置 age 身份文件', cmd: 'pandapass-cli config set-age-identity ~/.pandapass/age.key' },
      { label: '查看当前配置', cmd: 'pandapass-cli config show' },
    ],
  },
  {
    title: '6. 管理项目、环境与密钥',
    body: [
      '密钥按 项目(Project) → 环境(Environment) → 密钥(Secret) 三级组织。先创建项目和环境，再写入密钥。',
    ],
    code: [
      { label: '创建项目', cmd: 'pandapass-cli project create --name myapp --slug myapp' },
      { label: '创建环境', cmd: 'pandapass-cli env create --project myapp --name prod --slug prod' },
      { label: '写入密钥', cmd: 'pandapass-cli secret set --project myapp --env prod --key DATABASE_URL --value "postgres://..."' },
      { label: '读取密钥', cmd: 'pandapass-cli secret get --project myapp --env prod --key DATABASE_URL' },
      { label: '列出密钥', cmd: 'pandapass-cli secret list --project myapp --env prod' },
    ],
  },
  {
    title: '7. 在命令中注入密钥（run）',
    body: [
      'run 子命令会把指定密钥注入环境变量后执行命令，适合 CI/CD 或脚本。',
    ],
    code: [
      { label: '注入密钥并运行命令', cmd: 'pandapass-cli run --project myapp --env prod --only DATABASE_URL -- echo "$DATABASE_URL"' },
    ],
    note: '出于安全考虑，run 默认受服务端命令白名单限制。如需放开，请联系管理员调整 PANDAPASS_COMMAND_ALLOWLIST。',
  },
]

const en: DocStep[] = [
  {
    title: '1. AI Agent Quick Start',
    body: [
      'Want an AI assistant (e.g. Claude Code) to manage PandaPass for you? Send the prompt below to your AI assistant — it will visit this help page and create a PandaPass SKILL automatically.',
    ],
    code: [
      {
        label: 'One-line prompt for your AI',
        cmd: `Visit ${serverBase.value}/help for the PandaPass guide, then create a SKILL for PandaPass so I can manage secrets from the command line — login, project/env/secret operations, and run injection.`,
      },
    ],
  },
  {
    title: '2. Download the CLI',
    body: [
      'Download the archive for your platform from the GitHub Release. Extract it and put the binary on your PATH (e.g. ~/.local/bin, no sudo needed).',
    ],
    code: [
      { label: 'Linux / macOS', cmd: `curl -L -o pandapass-cli.tar.gz ${releaseBase}/pandapass-cli-0.0.1-linux-x86_64.tar.gz\ntar -xzf pandapass-cli.tar.gz\nmkdir -p ~/.local/bin\nmv pandapass-cli ~/.local/bin/` },
      { label: 'macOS (Apple Silicon)', cmd: `curl -L -o pandapass-cli.tar.gz ${releaseBase}/pandapass-cli-0.0.1-macos-aarch64.tar.gz\ntar -xzf pandapass-cli.tar.gz\nmkdir -p ~/.local/bin\nmv pandapass-cli ~/.local/bin/` },
      { label: 'Windows (PowerShell)', cmd: `Invoke-WebRequest -Uri "${releaseBase}/pandapass-cli-0.0.1-windows-x86_64.zip" -OutFile pandapass-cli.zip\nExpand-Archive pandapass-cli.zip\nMove-Item pandapass-cli.exe $env:LOCALAPPDATA\\pandapass\\` },
    ],
  },
  {
    title: '3. Generate an age key',
    body: [
      'The age keypair seals and unseals your secrets. Run keygen to create an identity file; it prints the public key you need when registering.',
    ],
    code: [
      { label: 'Generate and save to default path', cmd: 'pandapass-cli keygen' },
      { label: 'Print the public key only', cmd: 'pandapass-cli keygen --print' },
    ],
  },
  {
    title: '4. Register / Log in',
    body: [
      'Register through the Web UI or the CLI. Registration requires your age public key from the previous step.',
    ],
    code: [
      { label: 'Log in (admin account must be created in the Web UI first)', cmd: `pandapass-cli login --server ${serverBase.value.replace(':15173', ':18233')} --email you@example.com --password-stdin` },
    ],
  },
  {
    title: '5. Configure the CLI',
    body: [
      'Persist the server URL in your config so later commands do not need --server every time.',
    ],
    code: [
      { label: 'Set server URL', cmd: `pandapass-cli config set-server ${serverBase.value.replace(':15173', ':18233')}` },
      { label: 'Set age identity file', cmd: 'pandapass-cli config set-age-identity ~/.pandapass/age.key' },
      { label: 'Show current config', cmd: 'pandapass-cli config show' },
    ],
  },
  {
    title: '6. Manage projects, environments and secrets',
    body: [
      'Secrets are organised as Project → Environment → Secret. Create a project and environment first, then write secrets.',
    ],
    code: [
      { label: 'Create a project', cmd: 'pandapass-cli project create --name myapp --slug myapp' },
      { label: 'Create an environment', cmd: 'pandapass-cli env create --project myapp --name prod --slug prod' },
      { label: 'Write a secret', cmd: 'pandapass-cli secret set --project myapp --env prod --key DATABASE_URL --value "postgres://..."' },
      { label: 'Read a secret', cmd: 'pandapass-cli secret get --project myapp --env prod --key DATABASE_URL' },
      { label: 'List secrets', cmd: 'pandapass-cli secret list --project myapp --env prod' },
    ],
  },
  {
    title: '7. Inject secrets into commands (run)',
    body: [
      'The run subcommand injects selected secrets into the environment and executes a command — ideal for CI/CD or scripts.',
    ],
    code: [
      { label: 'Inject a secret and run', cmd: 'pandapass-cli run --project myapp --env prod --only DATABASE_URL -- echo "$DATABASE_URL"' },
    ],
    note: 'For security, run is restricted by the server-side command allowlist. Ask an administrator to adjust PANDAPASS_COMMAND_ALLOWLIST if needed.',
  },
]

const steps = computed(() => (isZh.value ? zh : en))

const copyLabel = computed(() => (isZh.value ? '复制' : 'Copy'))
const copiedLabel = computed(() => (isZh.value ? '已复制' : 'Copied'))
const serverLabel = computed(() =>
  isZh.value ? '服务器地址' : 'Server URL',
)
</script>

<template>
  <div class="help-page">
    <UiPageHeader
      :title="t('nav.help')"
      :description="isZh ? '在局域网中安装并使用 PandaPass CLI 的快速指南。' : 'Quick guide to installing and using the PandaPass CLI on your LAN.'"
    />

    <UiCard variant="outlined" padding>
      <!-- Download links -->
      <section class="help-section">
        <h2>{{ steps[0].title }}</h2>
        <p v-for="(line, i) in steps[0].body" :key="i">{{ line }}</p>
        <div v-for="(c, i) in steps[0].code ?? []" :key="`code-${i}`" class="code-block">
          <div class="code-head">
            <span class="code-label">{{ c.label }}</span>
            <UiButton variant="ghost" size="sm" @click="copy(c.cmd, `step0-${i}`)">
              {{ copied === `step0-${i}` ? copiedLabel : copyLabel }}
            </UiButton>
          </div>
          <pre class="code-body"><code>{{ c.cmd }}</code></pre>
        </div>
      </section>

      <!-- Download links -->
      <section class="help-section">
        <h2>{{ steps[1].title }}</h2>
        <p v-for="(line, i) in steps[1].body" :key="i">{{ line }}</p>
        <div class="download-grid">
          <a
            v-for="d in downloads"
            :key="d.file"
            class="download-link"
            :href="`${releaseBase}/${d.file}`"
            target="_blank"
            rel="noopener noreferrer"
          >
            <span class="dl-name">{{ d.label }}</span>
            <span class="dl-file mono">{{ d.file.replace('pandapass-cli-0.0.1-', '') }}</span>
          </a>
        </div>
        <div v-for="(c, i) in steps[1].code ?? []" :key="`code-${i}`" class="code-block">
          <div class="code-head">
            <span class="code-label">{{ c.label }}</span>
            <UiButton variant="ghost" size="sm" @click="copy(c.cmd, `step1-${i}`)">
              {{ copied === `step1-${i}` ? copiedLabel : copyLabel }}
            </UiButton>
          </div>
          <pre class="code-body"><code>{{ c.cmd }}</code></pre>
        </div>
      </section>

      <!-- Remaining steps -->
      <section v-for="(step, idx) in steps.slice(2)" :key="idx" class="help-section">
        <h2>{{ step.title }}</h2>
        <p v-for="(line, i) in step.body" :key="i">{{ line }}</p>
        <div v-for="(c, i) in step.code ?? []" :key="`code-${i}`" class="code-block">
          <div class="code-head">
            <span class="code-label">{{ c.label }}</span>
            <UiButton variant="ghost" size="sm" @click="copy(c.cmd, `step${idx + 2}-${i}`)">
              {{ copied === `step${idx + 2}-${i}` ? copiedLabel : copyLabel }}
            </UiButton>
          </div>
          <pre class="code-body"><code>{{ c.cmd }}</code></pre>
        </div>
        <p v-if="step.note" class="note">{{ step.note }}</p>
      </section>

      <section class="help-section server-section">
        <h2>{{ serverLabel }}</h2>
        <div class="code-block">
          <div class="code-head">
            <span class="code-label mono">{{ serverBase.replace(':15173', ':18233') }}</span>
            <UiButton variant="ghost" size="sm" @click="copy(serverBase.replace(':15173', ':18233'), 'server-url')">
              {{ copied === 'server-url' ? copiedLabel : copyLabel }}
            </UiButton>
          </div>
        </div>
        <p class="note">
          {{ isZh ? 'CLI 连接的是 API 服务（端口 18233），不是 Web 界面（端口 15173）。' : 'The CLI talks to the API service (port 18233), not the Web UI (port 15173).' }}
        </p>
      </section>
    </UiCard>
  </div>
</template>

<style scoped>
.help-page {
  max-width: 1200px;
  margin: 0 auto;
}

/* Override UiPageHeader description max-width */
:deep(.ui-page-header .description) {
  max-width: none;
}

.help-section {
  margin-bottom: var(--space-8);
  padding-bottom: var(--space-8);
  border-bottom: 1px solid var(--border);
  text-align: center;
}

.help-section:last-child {
  border-bottom: none;
  margin-bottom: 0;
  padding-bottom: 0;
}

.help-section h2 {
  margin: 0 0 var(--space-3);
  font-size: 16px;
  font-weight: 600;
}

.help-section p {
  margin: 0 0 var(--space-3);
  font-size: 13.5px;
  line-height: 1.6;
  color: var(--text-dim);
  max-width: 1200px;
  margin-left: auto;
  margin-right: auto;
}

.download-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: var(--space-3);
  margin: var(--space-4) auto;
  max-width: 1200px;
}

.download-link {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  padding: var(--space-3);
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  background: var(--surface-2);
  text-decoration: none;
  color: var(--text);
  text-align: center;
  transition: border-color var(--transition-fast),
    background-color var(--transition-fast);
}

.download-link:hover {
  border-color: var(--accent);
  background: var(--accent-soft);
}

.dl-name {
  font-weight: 600;
  font-size: 13px;
}

.dl-file {
  font-size: 11.5px;
  color: var(--text-dim);
}

.code-block {
  margin: var(--space-3) auto;
  max-width: 1200px;
  border: 1px solid var(--border);
  border-radius: var(--radius-md);
  overflow: hidden;
  text-align: left;
}

.code-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--space-2);
  padding: var(--space-2) var(--space-3);
  background: var(--surface-2);
  border-bottom: 1px solid var(--border);
}

.code-label {
  font-size: 12px;
  font-weight: 500;
  color: var(--text-dim);
}

.code-body {
  margin: 0;
  padding: var(--space-3);
  background: var(--surface);
  overflow-x: auto;
  font-family: var(--font-mono);
  font-size: 12.5px;
  line-height: 1.6;
  color: var(--text);
}

.note {
  font-size: 12.5px;
  color: var(--warn);
}

.server-section {
  margin-top: var(--space-4);
}
</style>