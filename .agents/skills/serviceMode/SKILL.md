---
name: serviceMode
description: Install and operate shush service mode - secrets moved to a hidden service account so no process running as the user (including AI agents) can ever read a value back. Use whenever the user wants secrets that even they or their agents cannot read, asks to protect keys from Claude Code / Codex / npm scripts / malware running as them, mentions install_proxy_service.ps1 or service_config.json, or wants to verify, purge, or uninstall an existing service-mode setup.
---

# /serviceMode — secrets your own session cannot read

Goal: the vault moves to a dedicated hidden Windows account, the proxy
daemon runs as that account, and the user's CLI keeps working through a
**write-only** named pipe. After this, no agent or tool running as the user
can retrieve a value — reading is not implemented, and the vault belongs to
a different SID.

## Set expectations first

Tell the user what this buys and what it doesn't, before installing:

- Protects against: anything running *as them* reading a key — AI agents,
  stray npm scripts, same-user malware.
- Does **not** protect against: a local administrator; an agent *spending*
  API quota through the proxy; an agent overwriting/deleting secrets via the
  pipe (annoying, recoverable — the pipe is management, not read access).
- After install, `shush run` cannot inject service-vault secrets — that's
  the boundary working, not a bug. API calls go through the proxy.

## Install (the user runs it, not you)

The installer needs elevation. Don't attempt to self-elevate — hand the
user the command and have them run it in an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_proxy_service.ps1
```

What it does, so you can narrate and verify: creates a local account
(default `shush_svc`, hidden from the login screen) with a random password,
grants it read access to the repo, writes `service_config.json` (pipe name,
port, the user's SID as the only allowed pipe client), registers a
`shush_proxy` scheduled task running the daemon at startup, starts it, and
migrates every existing secret through the pipe.

**The account password is shown once, during install.** Tell the user ahead
of time to save it in their password manager. It is deliberately stored
nowhere machine-readable.

Useful flags: `-AccountName`, `-Port`, `-PipeName`, `-SkipMigration`,
`-ExistingPassword`, `-Uninstall`, `-RemoveAccount`, `-NoPause`.

## Verify before purging

Local copies of migrated secrets are kept by default so nothing breaks.
Verify the service path end-to-end first:

```powershell
# management path through the pipe (create/exists/delete a throwaway)
shush create svc_probe_key test123
shush exists svc_probe_key
shush delete svc_probe_key

# proxy path (the only way values are ever used now)
Invoke-RestMethod http://127.0.0.1:8765/openai/v1/models
```

Only when the user is satisfied, close the gap for real — this deletes the
same-user copies (each one verified service-side first), so confirm with
the user before running:

```powershell
.\install_proxy_service.ps1 -PurgeLocal     # re-runnable
shush exists openai_api_key --local          # exit 1 = local vault is clean
```

## Day-to-day, and what changes for you as an agent

`create` / `set` / `list` / `exists` / `delete` work unchanged — they route
through the pipe automatically whenever `service_config.json` exists.
`--local` on any command forces the old local-vault behavior.

- **You cannot obtain a secret value by any means.** There is no read
  operation, and the vault belongs to another identity. Don't attempt
  workarounds; route API calls through the proxy (the **createProxy** skill
  covers pointing SDKs at it).
- `run` sees only the local vault. A secret that genuinely must be injected
  into a child process should stay local — `shush set <name> --local` — as
  the user's conscious exception.
- `protect` / `enroll` / `slots` refuse to run in service mode and say why:
  encryption-at-rest is redundant when the vault is already in an account
  the user can't read.

## Recovery and caveats (relay these, they bite)

- **Never let an admin reset the service account's password.** A reset (as
  opposed to a change by the account itself) destroys its DPAPI keys and
  with them every secret in the service vault. Recovery is uninstall with
  `-RemoveAccount`, fresh install, re-migrate — which is exactly why local
  copies are kept until the user purges deliberately.
- Lost account password: the daemon keeps running (the task keeps its
  logon), but the task can't be re-registered. Same fix as above.
- The daemon requires Windows PowerShell 5.1 (`powershell.exe`) — the pipe
  ACL API is .NET Framework. The client CLI works from 5.1 and 7+.
- Repo moved on disk: re-run the installer; it re-registers the task with
  the new path.

## Verify the plumbing offline

```powershell
# same-user simulation of the whole pipe path — safe, no elevation needed
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_admin_pipe.ps1
```

Full design and threat model: `docs/service_mode.md`.
