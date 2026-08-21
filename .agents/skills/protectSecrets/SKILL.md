---
name: protectSecrets
description: Encrypt shush secrets at rest with unlock factors - passphrase, Windows Hello, FIDO2 security key (YubiKey), or keyfile thumbdrive - including enrollment, factor choice, and recovery. Use whenever the user mentions a shared, public, family, or lab computer, wants keys encrypted or locked, wants to set up a YubiKey / Windows Hello / hardware unlock, or asks what happens if someone else reads their Credential Manager.
---

# /protectSecrets — encrypt secrets at rest with unlock factors

Goal: the user's chosen secrets become ciphertext in Credential Manager,
openable only with an enrolled unlock factor — with **two** factors enrolled
so a lost one is an inconvenience, not a lost vault.

## When this is the right layer

Credential Manager scopes secrets per Windows user, so anyone who can act as
that user — a family member on a shared login, the next person at a lab
machine — can read them. `protect` fixes exactly that: the value at rest.

Be honest about the edges before setting anything up:

- It does **not** protect a session that's already unlocked; the plaintext is
  in memory by definition once used.
- In **service mode** (`service_config.json` present) `enroll`/`protect`/
  `slots` refuse to run — service-vault secrets are already unreadable from
  the user's session. Nothing to do here.
- **Never propose TOTP/Google Authenticator** as a factor, even if the user
  asks. TOTP verifies, it doesn't encrypt, and verification needs the seed
  stored next to the very secrets it would guard. The docs explain this;
  don't relitigate it.

## Step 1 — choose factors (help the user pick two)

| Factor | Enroll with | Unlock feels like | Best when |
|--------|-------------|-------------------|-----------|
| Passphrase | `enroll --passphrase` | typing (~2s on PS 5.1) | always — it can't be left at home; the natural second factor |
| Windows Hello | `enroll --hello` | PIN/fingerprint/face | this machine has a TPM; bonus: a copied vault is inert elsewhere |
| FIDO2 key | `enroll --yubikey` | physical touch, every time | strongest: the secret never leaves the token, a copy is impossible |
| Keyfile | `enroll --keyfile` | nothing — plug in the drive | zero-friction; but it's a **bearer file** — anyone who copies it holds the vault |

Sensible default: one convenient factor (Hello, key, or keyfile) plus a
passphrase as backup. For a keyfile on a machine the user doesn't trust,
offer `--keyfile --with-passphrase`, which makes a copied drive useless
alone — at the cost of the typing the factor exists to avoid.

## Step 2 — enroll (two, not one)

```powershell
shush enroll --hello                              # or --yubikey, --keyfile
shush enroll --passphrase --label "backup"
```

The first enrollment creates the vault master key; each later one re-wraps
it, so an already-enrolled factor must unlock first — enroll the convenient
factor before the backup and the order takes care of itself. `--hello` and
`--yubikey` report specifically why they can't enroll (no TPM, no Hello PIN,
no key attached, no hmac-secret support) — relay that reason, don't guess.

If only one factor is enrolled when you're done, say so explicitly: a lost
sole factor means the protected secrets are unrecoverable and the API keys
must be re-issued. shush refuses to remove the *last* slot, but it can't
refuse a thumbdrive being lost.

## Step 3 — protect the secrets that matter

```powershell
shush protect openai_api_key
shush list                        # shows: openai_api_key  [protected]
```

Protection is per-secret — a low-value key can stay friction-free while the
production one requires a touch. `protect` verifies the ciphertext decrypts
back to the original before overwriting, and later `set --force` overwrites
re-encrypt rather than silently downgrading to plaintext.

Limit: protected values cap at 895 bytes (1280 unprotected). API keys are
far below this.

## How unlocking behaves afterward

Any command reading a protected value (`run`, `proxy start`) unlocks first;
the master key lives in that process only and is never cached to disk. With
several factors enrolled the cheapest available one wins: plugged-in keyfile
→ attached security key → Hello → passphrase. Force one with `--passphrase`,
`--hello`, `--yubikey`, `--keyfile`, or `--slot <id>`.

Two consequences worth telling the user:

- Unlocks need a human (gesture, touch, typing) unless a keyfile is plugged
  in — so a protected secret under an unattended script means pairing with
  `proxy start`, which unlocks once and holds the key for the session.
- As an agent, never try to script around an unlock, and never suggest
  caching a passphrase to a file. `--passphrase-stdin` exists for automation
  the *user* sets up, not for you to bypass a prompt.

## Step 4 — recovery posture, before walking away

- `vault_keys.json` (next to `secret_manager.ps1`, gitignored) holds only
  wrapped key material — safe at rest, and **worth backing up**: losing it
  locks every protected secret.
- A keyfile is just a file: copy it to a second drive kept somewhere safe.
  Both copies open the same slot. (And never copy one onto non-removable
  storage or "somewhere convenient" — bearer token.)
- `shush slots` lists enrolled factors; `shush slots --slot <id>` removes
  one. Removal that would strand protected secrets is refused.

## Verify

```powershell
# offline proof the stored blob is ciphertext and run still decrypts —
# uses a throwaway secret and throwaway slot file, touches nothing real
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_protected_secrets.ps1

# interactive hardware check (skips absent hardware, never fails on it)
powershell -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1
```

Note: Hello and FIDO2 are not yet verified against real hardware by CI — run
the interactive check on this machine before the user relies on either as
their only convenient factor. Design and threat model:
`docs/protected_secrets.md`.
