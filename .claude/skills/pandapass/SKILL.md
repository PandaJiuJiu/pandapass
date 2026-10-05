---
name: pandapass
description: Retrieve and use team secrets from PandaPass without exposing values in context. Use when the user mentions secrets, credentials, API keys, tokens, .env files, database URLs, or asks to run a command that needs credentials. Triggers on "pandapass", "secret", "api key", "credential", "env var", "run with secrets", "AGENT_INTEGRATION".
---

# PandaPass

PandaPass is a team secrets vault. This skill covers the CLI.

## The one rule that matters

**Never fetch a secret's value into your context.** If you read a secret and
then use it, the value is now in the conversation — visible in `/context`,
in the transcript, and in any logs. It does not matter that you meant to be
careful.

Instead, run the command with the secret already in its environment:

```bash
pandapass run --project myapp --env prod --only DB_URL -- ./migrate.sh
pandapass run --project myapp --env prod -- psql -h db.internal -U postgres
```

Everything after `--` is the command and its arguments, passed as an argv
array — never through a shell. The child sees the variables; you do not.

Note that a variable written in your own command line is *not* substituted:
`-- psql "$DB_URL"` fails, because your shell expands `$DB_URL` before
PandaPass is involved, and your shell does not have it. Pass arguments
literally and let the child read its own environment.

## Reading a value directly

Only when there is genuinely no way to run a command — and say why first:

```bash
pandapass secret get demo prod API_KEY
```

This prints the value to stdout, so it lands in your context. Prefer `run`.

## Listing what exists

Safe — returns names and versions, never values.

```bash
pandapass secret list demo prod
```

## Setup

The server and account must already exist. If commands fail with 401 or
"Not authenticated", the user needs to log in — do not attempt to run
`login` yourself, it needs a password and possibly a TOTP code.

```bash
pandapass login --email user@corp.local      # prompts for password + TOTP
pandapass keygen                              # once, writes ~/.pandapass/age.key
```

An account with no age key exists but cannot store or read any secret. The
CLI says so at registration; if you see writes failing with 403, this is
why.

## Writing secrets

Only when the user explicitly asks to store a value.

```bash
pandapass secret set demo prod API_KEY 'the-value'
```

A value given as an argument is visible in `ps` for the life of the command.
This is unavoidable for `set` — the value has to reach the process somehow —
but prefer having the user run it themselves when the value is sensitive.

## Choosing the project and environment

Both are required everywhere. If the user didn't say, ask rather than
guessing — reading from the wrong environment is how a dev credential gets
used against production.

## Exit codes

`run` exits with the child's status. A non-zero exit means the command
failed; read its stderr rather than retrying blindly.

## What not to do

- Do not `cat`, `echo`, or otherwise print a secret to inspect it.
- Do not write a secret to a file, even a temp one.
- Do not pass a secret as a command argument when `run` can inject it.
- Do not run `secret get` to "check" a value; use `run` with a command that
  validates it instead (e.g. `run ... -- ./healthcheck.sh`).
- Do not retry a 403 from a write by guessing. It usually means no age key
  is enrolled on that account.
