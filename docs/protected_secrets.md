# Protected Secrets

Protection encrypts a secret at rest so that reading it costs an unlock: a
passphrase, a Windows Hello gesture, or a touch on a FIDO2 security key.

This exists for the shared-machine case. Everything else in shush assumes the
Windows user account is yours; Credential Manager scopes secrets per user, so
anyone who can act as you can read them. On a public or shared computer that
assumption breaks, and a stored key is one `CredRead` call away from anyone who
sits down at the machine.

## What a password can and cannot do here

A password prompt bolted onto the CLI would be theatre. The stored value would
still be plaintext in Credential Manager, reachable through the Credential
Manager GUI or three lines of PowerShell that never touch `shush` at all. The
prompt would guard the front door of a house with no walls.

So the passphrase is not a check - it is the encryption key. What sits in
Credential Manager becomes ciphertext, and the key to it exists only in the
memory of the process you unlocked, for as long as that process runs.

This is also why **TOTP (Google Authenticator) cannot be used**. TOTP verifies,
it does not encrypt. A six-digit code that rotates every 30 seconds cannot
derive a stable key, and verifying a code requires the shared seed to sit on
the verifying machine - the same machine, in the same vault, next to the keys
it is supposed to protect. Anyone who can read the secrets can read the seed
and mint codes. TOTP's real security comes from a remote verifier that
rate-limits guesses and that the attacker does not control; on a single local
box, that property does not exist.

## Design

One random 32-byte **master key** encrypts every protected secret. That master
key is never stored bare. Each enrolled factor wraps its own copy under a
key-encryption key (KEK) that only that factor can reproduce - the same
arrangement as LUKS key slots, and for the same reason: enroll two factors, and
losing one is an inconvenience rather than a lost vault.

```text
passphrase --PBKDF2--> KEK-1 --wraps--> master key --encrypts--> secret values
Hello      --TPM sig-> KEK-2 --wraps--/
YubiKey    --hmac----> KEK-3 --wraps--/
keyfile    --SHA-256-> KEK-4 --wraps--/
```

**Value encryption.** AES-256-CBC with HMAC-SHA256 in encrypt-then-MAC order.
Not AES-GCM: that lives in `AesGcm`, which is .NET Core only, and this repo
supports Windows PowerShell 5.1 on .NET Framework. The MAC is verified before
any decryption happens, so a wrong key or a tampered blob never reaches the CBC
padding check - that check is a padding oracle if you let it run. Encryption
and authentication use separate subkeys derived from the master key, so the
same bytes never serve both roles.

Stored form is `shush.v1:<base64>` over `[version][iv][ciphertext][mac]`. A
value without that prefix is a legacy plaintext secret and is read as-is, so
protected and unprotected secrets coexist in one vault.

**Slot file.** `vault_keys.json`, next to `secret_manager.ps1`, gitignored, and
override-able with `SHUSH_VAULT_KEYS`. It holds only wrapped key material and
public KDF parameters, so it is safe at rest; it lives outside Credential
Manager because three slots of JSON exceed the 2560-byte credential blob
ceiling. Writes go through a temp file and a rename, because a half-written
slot file would lock every protected secret out permanently.

## The four factors

### Passphrase

PBKDF2-SHA256 at 600,000 iterations (the OWASP-recommended level) over a
per-slot 16-byte random salt.

Measured cost: about 0.2s on PowerShell 7, about **2.1s on Windows PowerShell
5.1**, whose .NET Framework implementation is roughly ten times slower. That
delay is deliberate. Lowering the iteration count to hide it would weaken every
passphrase slot on both hosts; enroll a Hello or FIDO2 slot instead if the wait
is annoying, since neither uses PBKDF2.

Works everywhere, needs no hardware, and is the only factor that cannot be
left at home.

### Windows Hello

Hello gives a TPM-backed key that releases a signature only after a gesture
(PIN, fingerprint, face). RSA PKCS#1 v1.5 signing is deterministic, so signing
one fixed random challenge yields the same bytes every time - which is what
lets a signature serve as a KEK. `KEK = SHA-256(signature || label)`.

The private key never leaves the TPM, so **a vault file copied to another
machine is inert**, which is the strongest property of this factor.

Enrollment signs the challenge twice and refuses to enroll if the two
signatures differ. An authenticator that ever signs with a randomized scheme
would otherwise produce a slot that looks fine today and can never be opened
again.

Requires a TPM and an enrolled Hello PIN (Settings > Accounts > Sign-in
options). `enroll --hello` reports exactly why if either is missing.

WinRT projection exists only on Windows PowerShell 5.1, so on PowerShell 7 the
Hello step runs in a short-lived `powershell.exe` child process
(`modules/hello_helper.ps1`) and the signature returns over its stdout pipe.
Same user, same process tree, and the parent already holds the master key in
memory, so this adds no new reader.

### FIDO2 security key (YubiKey and compatible)

Uses the CTAP2 `hmac-secret` extension. The token holds a per-credential secret
it will never disclose; given a fixed 32-byte salt it returns a stable 32-byte
HMAC output, which becomes the KEK. The credential is non-resident, so the
token stores nothing and the credential id lives in the slot file - useless
without the token.

**Physical touch is required on every unlock.** That is the point: a key in
your pocket cannot be used by someone sitting at the machine, which is the one
threat model where a shared computer is genuinely survivable.

Windows exposes no API for `hmac-secret`, and libfido2 would mean shipping
native binaries, so `modules/fido2_native.psm1` speaks CTAP2 over USB HID
directly - device enumeration by FIDO usage page (0xF1D0), CTAPHID framing,
CBOR, ECDH P-256 key agreement, and PIN/UV auth protocol one. Scope is limited
to `getInfo`, `clientPIN`, `makeCredential`, and `getAssertion`.

If the key has a PIN set, it is required and prompted for. Enrollment derives
the secret twice and compares, because `hmac-secret` output differs between
verified and unverified assertions - catching a PIN/UV mismatch at enrollment
instead of at the next unlock, when the secret would already be encrypted under
an unreachable key.

### Keyfile (thumbdrive)

A file holding 32 random bytes becomes the KEK: `KEK = SHA-256(key bytes ||
label)`. Plug the drive in and protected secrets open with no typing and no
touch; unplug it and the vault is shut. This is the zero-friction factor.

```powershell
.\secret_manager.ps1 enroll --keyfile              # finds the removable drive
.\secret_manager.ps1 enroll --keyfile E:\shush.key # or name the path
```

Bare `--keyfile` writes `shush.key` to the root of the first ready removable
drive. An existing keyfile on that drive is reused rather than replaced, so one
thumbdrive can unlock several machines' vaults. `--force` overwrites it, which
orphans any slot still relying on the old file.

Slots record a random keyfile **id**, not a path, because drive letters move
between sessions. Unlock scans removable drives and matches on that id;
`--keyfile <path>` skips the scan, and `SHUSH_KEYFILE` overrides it (useful
when the drive is not removable, and what the test suite uses).

**Understand what this is: a bearer token.** Unlike a FIDO2 token, whose secret
never leaves the hardware, a keyfile is a file. Anyone who copies it holds the
vault, and copying leaves no trace. Plugging it into a machine is enough to
expose it to anything running there - which is worth thinking about on exactly
the public computers this feature is for.

For something-you-have plus something-you-know, bind a passphrase to it:

```powershell
.\secret_manager.ps1 enroll --keyfile --with-passphrase
```

The KEK then becomes an HMAC of the key bytes under the PBKDF2-stretched
passphrase, so a copied keyfile alone will not open the slot. It costs the
typing the factor exists to avoid, so it is off by default.

## Commands

```powershell
# Enroll factors. Do at least two, or a lost key is a lost vault.
.\secret_manager.ps1 enroll --passphrase
.\secret_manager.ps1 enroll --yubikey --label "pocket key"
.\secret_manager.ps1 enroll --hello
.\secret_manager.ps1 enroll --keyfile --label "blue thumbdrive"

.\secret_manager.ps1 protect openai_api_key      # encrypt one secret
.\secret_manager.ps1 unprotect openai_api_key    # back to plain storage
.\secret_manager.ps1 slots                       # list enrolled factors
.\secret_manager.ps1 slots --slot a1b2c3d4e5f6   # remove one
```

Protection is per-secret, so a low-value key can stay friction-free while the
production one requires a touch. `list` marks protected secrets:

```text
github_token
openai_api_key  [protected]
```

## Unlocking

Any command that reads a protected value unlocks first, and the master key is
held **for that process only**. Nothing is cached to disk and nothing outlives
the command - which is the entire point on a shared machine.

When several factors are enrolled, the cheapest available one wins: a
plugged-in keyfile (no interaction at all), then an attached security key (a
touch beats typing, and beats 2 seconds of PBKDF2 on 5.1), then Hello, then a
passphrase-bound keyfile, then a passphrase. Force one with `--passphrase`,
`--hello`, `--yubikey`, `--keyfile`, or a specific slot with `--slot <id>`.

`proxy start` unlocks **before** the listener starts, and only when a
configured provider actually uses a protected secret. A prompt inside a request
handler would hang that request instead of asking anyone. The proxy then holds
the master key for its lifetime, which makes it the natural pairing: unlock
once per session, and no tool ever holds the key.

`--passphrase-stdin` reads the passphrase from a pipe for automation. Same
trade-off as `--from-stdin` for values: it keeps the passphrase out of shell
history, but a pipe is readable by anything that can already see the process.
Prefer the prompt when a human is present.

## What this does and does not protect against

Protects against:

- Someone using the machine later, or a shared local account, dumping
  Credential Manager.
- A copied or backed-up credential store, or a roaming profile.
- With Hello: the vault being opened on any other machine at all.
- With a security key: anyone who does not physically have the key.
- With a keyfile: anyone at the machine while the drive is unplugged - but
  only until someone copies the file.

Does **not** protect against:

- Someone using your session while it is unlocked. Nothing can - the plaintext
  is in memory by definition, and `run` puts it in a child environment.
- A keylogger capturing the passphrase as you type it. Hello and FIDO2 are
  materially better here, since neither replays a typed secret.
- A keyfile being copied off the drive while it is plugged in. Only FIDO2
  resists that, because its secret never leaves the token.
- Anything already listed in `security_model.md` for values in flight.

## Recovery and limits

- **Enroll two factors.** Removing the only slot while secrets are protected is
  refused, but a YubiKey lost - or a thumbdrive lost, reformatted, or chewed by
  a laptop bag - with no second slot means the secrets are unrecoverable by
  design. Re-issue those API keys.
- A keyfile is worth copying to a second drive kept somewhere safe. It is just
  a file, and both copies open the same slot.
- Losing `vault_keys.json` has the same effect. Back it up: it holds only
  wrapped key material, so a copy is safe at rest.
- Protected values are limited to **895 bytes** (against 1280 for unprotected
  ones). Encryption overhead plus base64 has to fit the 2560-byte Windows
  credential blob ceiling. Oversized values are refused with a clear error, not
  truncated. API keys are far below this.
- Protection applies to the **local vault**. In service mode the secrets live
  in a separate account's vault and are already unreadable from your session,
  so `protect`, `enroll`, and `slots` refuse to run there and say why. See
  `service_mode.md`.

## Testing

```powershell
# Unit tests (crypto, slot logic, keyfile; no hardware, no vault access)
Invoke-Pester -Path .\tests\vault_crypto.Tests.ps1, .\tests\vault_keyslots.Tests.ps1, .\tests\factor_keyfile.Tests.ps1

# End-to-end against the real vault with a throwaway secret and slot file
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_protected_secrets.ps1

# Hardware factors - INTERACTIVE, asks for a gesture and for touches.
# Skips (does not fail) whichever hardware is absent.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1 -Only fido2
```
