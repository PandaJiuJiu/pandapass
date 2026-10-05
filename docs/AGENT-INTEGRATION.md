# Giving an agent access to PandaPass

## What "safe" means here

The failure this whole design exists to prevent is a secret ending up in an LLM
context. Once it is there it is in the transcript permanently — visible in
`/context`, in logs, in anything that captures the session. At-rest encryption
does not help, because the leak already happened.

So the rule an agent must follow is narrow and absolute:

> Name the keys you need. Run the command. Never read the value.

## The mechanism

```bash
pandapass run --project myapp --env prod --only DB_URL,API_KEY -- ./deploy.sh
```

1. The agent asks for key **names**.
2. The CLI decrypts them.
3. The values land in a child process's environment.
4. The child runs. The values are dropped when it exits.

The agent's context contains `--only DB_URL,API_KEY` and the command's exit
code. It never contains a value.

The child is spawned as an argv array, never through a shell, so a stored value
of `$(rm -rf /)` is passed as a literal string. That is covered by a test.

## Setting it up

### 1. A service token for the agent, not a human session

Agents and CI get their own token, scoped as narrowly as the job allows:

```bash
pandapass token create \
  --name agent-deploy \
  --project myapp --env prod \
  --scopes read:secret --scopes list:secret \
  --expires-days 30
```

Scopes are enforced server-side, not advisory. A token carrying only
`read:secret` cannot write, delete, read the audit log, or mint another token —
verified over HTTP, with tests in `crates/pandapass-core/src/rbac.rs`. A token
that can mint tokens could grant itself `write:secret`, so token creation is
reserved for human sessions.

Two consequences worth knowing:

- **A token that can write can rotate a production credential.** That is what
  `write:secret` means. Do not hand it to an agent that only needs to read.
- **A token cannot be reused to escalate.** Revoked and expired tokens grant
  nothing regardless of scopes.

### 2. Put the token where the CLI can read it

```bash
export PANDAPASS_TOKEN='…'
```

Do **not** pass it as a command-line argument — `ps` shows it to every user on
the host for the life of the process.

For a long-lived agent, `~/.pandapass/config.json` (mode 0600, written
atomically) holds the session token after `pandapass login`.

### 3. Register the skill

Copy `.claude/skills/pandapass/SKILL.md` into the agent's skills directory. It
is advisory — it tells the agent the rule, it does not enforce it. See
"Limits" below.

## Why not MCP

The project started with an MCP server exposing `get_secret`, `list_secrets`,
and `run_with_secret`. It was removed in favour of the CLI plus this skill.

The reason is the one above, and it cuts an unexpected way. An MCP tool result
is **tool output**, which lands in the model's context. `get_secret` over MCP is
therefore identical to `pandapass secret get` — both put the value in the
transcript. The tool boundary does not create a security boundary; it is a
formatting decision.

The CLI can do the thing MCP could not: spawn a child process and inject into
its `environ`, so the value exists in the child's address space and nowhere
else. That is `pandapass run`.

The audit actions keep their original `mcp_*` names in the database. Renaming
the stored strings would silently rewrite history, so the variants stay and new
actions are added instead.

## Choosing between the two read paths

The server can be configured **not** to be a recipient of user envelopes. The
trade-off:

| Setup | `pandapass run` | `pandapass secret get` | Stolen database |
|---|---|---|---|
| Server is a recipient | works | works | ciphertext only |
| Server is not a recipient | works | **fails** | ciphertext only |

The CLI path works either way, because the member unwraps their own envelope.
What you lose without the server is the read-only fallback — and it is worth
losing if the threat model includes a compromised running server. See
`SECURITY.md`.

## Limits, stated plainly

**The skill is advice, not a control.** Nothing stops an agent from running
`secret get`, or from `cat`-ing a value into a tool call. The skill tells it
not to.

A real guarantee needs the API to refuse: an agent's token should be unable to
call the plaintext read path at all — a scope that permits `run` and denies
`get_secret`. The scopes here separate *operations* (read, write, list, audit,
manage) but not *delivery mechanism*. Until a `run:secret` scope exists that
`read:secret` cannot buy, the boundary is behavioural, and behaviour is not a
security property.

The other limit is not a bug: **root on the host wins.** The server can unwrap
every envelope it is addressed to.

## Verifying it worked

After a session where an agent used the vault:

```bash
pandapass audit list --project myapp
```

You should see `run_command` entries naming the executable and the key names
used, and `secret_read` entries for any direct read. **No entry should contain
a value** — the log stores names only, and there are tests asserting exactly
that.

If you want to check the stronger property, that the value is absent from the
agent's own transcript, that is `/context` in Claude Code. It should show key
names and exit codes, never values.
