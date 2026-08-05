# Service Mode

Service mode is the answer to one question: **how do you stop AI agents and
CLI tools running as you from reading your secrets?** On Windows, Credential
Manager is DPAPI-scoped per user, so any process running under your account
can read your vault. No same-user design fixes that. Service mode moves the
secrets to a *different* Windows identity and leaves you a write-only
management channel.

```text
 You / your agents (user: you)          Service account (shush_svc)
 ------------------------------         ---------------------------
 shush create/list/delete  ----pipe---> daemon writes ITS vault
 HTTP client               ----http---> proxy injects key upstream
                                        |
 (no operation returns a value)         +--> provider API over HTTPS
```

## What it gives you

- Agents (Claude Code, Codex, scripts) **cannot read secret values** at all:
  the service vault belongs to another SID, and the admin pipe has no read
  operation by construction.
- The UX is unchanged: `shush create name value`, `set`, `list`, `exists`,
  `delete` all work exactly as before; they transparently route through the
  daemon's named pipe.
- API access happens only through the proxy, bounded by its existing
  controls (per-provider domain lock, method allowlist, size limits,
  redacted logs).

## What it still does not protect against

- A local **administrator** (can dump the daemon's memory or re-register
  the task).
- An agent **using** the proxy: it can spend your API quota through allowed
  providers. It just cannot exfiltrate the key.
- An agent **overwriting or deleting** secrets through the pipe (annoying,
  recoverable; the pipe is management, not read access).

## Install

One elevated run:

```powershell
powershell -ExecutionPolicy Bypass -File .\install_proxy_service.ps1
```

What it does, in order:

1. Creates a local account (default `shush_svc`) with a random generated
   password, hidden from the Windows login screen. **The password is shown
   once — save it in your password manager.** It is deliberately not stored
   anywhere machine-readable (a recoverable password would let same-user
   code log on as the account and read the vault).
2. Grants the account read access to the repo folder.
3. Writes `service_config.json` (gitignored): pipe name, port, and the SID
   allowed to connect to the pipe (you).
4. Registers a `shush_proxy` scheduled task running the daemon as the
   service account at startup, and starts it now.
5. **Migrates every secret from your vault into the service vault** through
   the pipe, and reports each one.

Local copies are kept by default so nothing breaks while you verify. When
satisfied, remove same-user read access for real:

```powershell
.\install_proxy_service.ps1 -PurgeLocal     # re-runnable; verifies each
                                            # service copy before deleting
```

Flags: `-AccountName`, `-Port`, `-PipeName`, `-SkipMigration`,
`-ExistingPassword` (reuse an account you know the password for),
`-Uninstall`, `-RemoveAccount` (destroys the service vault; asks for
confirmation), `-NoPause`.

## Day-to-day usage

Nothing changes:

```powershell
shush create stripe_key sk_live_...   # -> service vault, via pipe
shush list                            # names only, via pipe
shush delete old_key                  # via pipe
shush proxy ... already running as the service; just use the HTTP routes
```

`--local` on any command forces the old local-vault behavior (your own
vault). That is also where `run` looks: **`run` cannot inject service-vault
secrets** — handing the plaintext to a child in your session is exactly
what the boundary forbids. Secrets that must be used via `run` should stay
local (`set <name> --local`), consciously.

## The admin pipe

- Named pipe `\\.\pipe\shush_admin`, created by the daemon with an ACL that
  admits exactly one client SID (recorded at install).
- Ops: `ping`, `create`, `list`, `exists`, `delete`. Anything else —
  including any hypothetical `get` — is rejected with `UNSUPPORTED_OP`
  before dispatch. Values flow in; only names flow out.
- One request per connection, newline-delimited JSON, 16KB cap, read
  timeouts so a hung client cannot stall the daemon.
- The daemon logs `admin <op> <name>` lines only — request bodies (which
  contain plaintext on create) are never logged.

## Recovery and caveats

- **Do not let an admin reset the service account's password.** A reset
  (as opposed to a change by the account itself) destroys its DPAPI keys
  and with them every secret in the service vault. If that happens:
  uninstall with `-RemoveAccount`, reinstall fresh, re-migrate (which is
  why keeping local copies until you trust the setup is the default).
- Lost the account password? You can keep running (the task keeps its
  logon), but you cannot re-register the task. Fix: `-Uninstall
  -RemoveAccount`, then fresh install and re-`create` the secrets.
- The daemon must run under Windows PowerShell 5.1 (`powershell.exe`) —
  the pipe ACL API is .NET Framework. The client CLI works from both
  Windows PowerShell and PowerShell 7.
- Repo moved? Re-run the installer (it re-registers the task with the new
  path).

## Verify it works

```powershell
# management path
shush create probe_key test123 && shush exists probe_key && shush delete probe_key

# the boundary itself: local vault no longer has the secret (after purge)
shush exists <name> --local        # exit 1 = your vault is clean

# offline harness (same-user simulation of the whole pipe path)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_admin_pipe.ps1
```
