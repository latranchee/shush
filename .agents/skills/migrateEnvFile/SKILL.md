---
name: migrateEnvFile
description: Move plaintext API keys out of .env files, shell profiles, and scripts into the shush vault, then rewire the launch commands to shush run - without the values ever entering the agent's context. Use whenever the user wants keys out of a .env file, asks to "clean up" or secure their API keys, worries a key is committed or exposed in a repo, or mentions secrets sitting in dotfiles, config files, or environment blocks.
---

# /migrateEnvFile — get plaintext keys into the vault

Goal: every secret currently sitting in a `.env` file (or profile, or script)
ends up in the shush vault, the commands that needed them use `shush run`,
and the plaintext copies are gone — **without you ever reading a value**.

The discipline that makes this skill different from a generic refactor: the
values must not pass through your context. If you `cat` the `.env`, the keys
are now in the transcript, which may be logged or summarized — you'd be
creating the leak you were asked to fix. Read *names*, pipe *values*.

## Step 1 — find the plaintext, look at names only

List candidate files (`.env`, `.env.*`, PowerShell profiles, docker-compose
env blocks). To see what's inside a `.env` without exposing values, print
keys only:

```powershell
Get-Content .\.env | Where-Object { $_ -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=' } |
  ForEach-Object { ($_ -split '=', 2)[0].Trim() }
```

Show the user this list and confirm which entries are actually secrets.
`PORT=3000` and `NODE_ENV=production` are configuration, not secrets — leave
those in the file (or move them to a committed `.env.example`).

## Step 2 — pipe each value into the vault, unseen

Vault names are lowercase snake_case: `OPENAI_API_KEY` → `openai_api_key`.
For each secret, extract the value in-shell and pipe it straight to
`set --from-stdin` — it never hits your output:

```powershell
$line = Get-Content .\.env | Where-Object { $_ -match '^\s*OPENAI_API_KEY\s*=' } | Select-Object -First 1
($line -split '=', 2)[1].Trim().Trim('"').Trim("'") | shush set openai_api_key --from-stdin
```

Or all confirmed entries in one pass:

```powershell
$secrets = @('OPENAI_API_KEY', 'GITHUB_TOKEN')   # from step 1, user-confirmed
foreach ($k in $secrets) {
  $line = Get-Content .\.env | Where-Object { $_ -match "^\s*$k\s*=" } | Select-Object -First 1
  $name = $k.ToLower()
  ($line -split '=', 2)[1].Trim().Trim('"').Trim("'") | shush set $name --from-stdin
}
```

If a vault name already exists, `set` refuses rather than overwrite. Ask the
user whether the `.env` copy or the vault copy is current before adding
`--force`.

Verify by name, never by value:

```powershell
shush exists openai_api_key   # exit 0 for each migrated key
shush list
```

## Step 3 — rewire the launch commands

Wherever the tool was started relying on the `.env` (npm scripts, README
instructions, task runners, `docker compose`), change the launch to inject
from the vault:

```powershell
shush run node .\app.js --env OPENAI_API_KEY=openai_api_key --env GITHUB_TOKEN=github_token
```

Two things to check while rewiring:

- **dotenv loaders**: code calling `dotenv.config()` (or equivalent) is
  harmless once the file has no secrets — process env wins in most loaders —
  but if the `.env` file is deleted outright, make sure the loader tolerates
  its absence.
- **Scrubbed environment**: `shush run` passes only OS essentials plus your
  declared mappings. Non-secret variables the app needs (`NODE_ENV`, ports)
  must stay in the file the app reads, or be declared too. The
  **runWithSecrets** skill has the details.

## Step 4 — retire the plaintext, with the user's say-so

Only after every `exists` check passes and the rewired command has actually
run once:

1. Confirm with the user, then remove the secret lines from `.env` (leave
   the non-secret config), or delete the file if nothing remains.
2. Check `.gitignore` covers `.env*` regardless — the next tool may recreate
   one.
3. If the file was ever committed, say so plainly: the keys live in git
   history and rotating them is the only real fix. Offer to check:
   `git log --oneline --all -- .env`.

Deleting the file does not unleak a committed key. Rotation does.

## Troubleshooting

- **Value contains `=`** (base64, connection strings): the `-split '=', 2`
  above splits only on the first `=`, which handles this. Don't "simplify"
  it to a plain split.
- **Multiline or quoted-with-spaces values**: `.env` dialects vary. For an
  odd entry, have the user store it themselves with `shush set <name>` at
  the secure prompt instead of scripting around the edge case.
- **Value over 1280 bytes**: the vault refuses it (Windows credential blob
  ceiling). That's usually a certificate or JSON blob, not an API key — those
  belong in a file with tight ACLs, not in shush.
