# Encrypted backup and transfer

`backup_vault.ps1` creates portable `.shushbak` files for transferring unprotected
local or service-vault credentials between Windows PCs. Run it with Windows
PowerShell 5.1 or PowerShell 7. It prompts privately for an archive passphrase;
there is no passphrase argument or plaintext export mode.

Names and values are encrypted together. Keep the archive passphrase in your
password manager, separately from the archive. A lost passphrase means the
archive cannot be restored. Source credentials are never removed.

## Local vault

From the shush checkout, in your normal Windows session:

```powershell
.\backup_vault.ps1 -Action Backup -Vault Local -Path "$env:USERPROFILE\Desktop\transfer.shushbak"
```

Enter a strong, unique passphrase (minimum 12 characters) twice. To include only
selected credentials, add `-Names openai_api_key,anthropic_api_key` when invoking
the script from PowerShell. Existing archive files are never overwritten.

Protected local credentials (`shush.v1:`) make backup fail before creating any
file. This version does not transfer unlock factors or decrypt protected
credentials. You can explicitly select unprotected names with `-Names`.

## Service vault: source PC

Service export must run **as the configured service account**, with its Windows
profile loaded. An ordinary user or elevated administrator running under their
own identity cannot export that account's credentials. The daemon has no backup,
export, or read-value operation; its management interface stays write-only.

You need the service account password saved during installation. If it is lost,
this release cannot export the service vault. Do not reset that account's
password: an administrator reset can destroy access to its DPAPI vault. Recover
the original API keys from your password manager or providers instead.

Open PowerShell in the source checkout. Read the configured account name:

```powershell
$config = Get-Content .\service_config.json -Raw | ConvertFrom-Json
$account = "$env:COMPUTERNAME\$($config.account)"
$repo = $PWD.Path
$credential = Get-Credential -UserName $account -Message 'Enter the saved shush service account password'
Start-Process powershell.exe -Credential $credential -LoadUserProfile -WorkingDirectory $repo -ArgumentList '-NoProfile -NoExit -ExecutionPolicy Bypass' -WindowStyle Normal
$credential = $null
```

In the new service-account window, run:

```powershell
$env:PSModulePath = [Environment]::GetEnvironmentVariable('PSModulePath', 'Machine')
.\backup_vault.ps1 -Action Backup -Vault Service -Path "C:\Users\$env:USERNAME\transfer.shushbak"
```

The new window inherits the launching shell's environment variables.
`-ExecutionPolicy Bypass` covers the service account's default Restricted
policy, and resetting `PSModulePath` stops Windows PowerShell 5.1 from trying to
load PowerShell 7 modules. `USERPROFILE` and `TEMP` still point at the launching
user, so pass an explicit archive path. The script moves `TEMP` into the
service account's own profile on its own.

The archive is written inside the service account's profile. Copy the resulting
encrypted file out using an administrator session, then transfer it to the
destination PC. Close the service-account PowerShell window when finished.
The script does not grant access to the service profile or change its ACLs.

Launching a window uses Windows interactive-logon policy. If Windows reports
that the service account lacks the requested logon type, a Windows administrator
must temporarily grant that account **Allow log on locally** under Local Security
Policy / Local Policies / User Rights Assignment, then remove that grant after
backup. This script does not change account rights or scheduled tasks. Other
Windows logon restrictions may also prevent this route.

## Destination PC

Install shush. Choose the destination vault explicitly. For a service vault,
install service mode first, and run restore as the ordinary user authorized to
manage that service:

```powershell
.\backup_vault.ps1 -Action Restore -Vault Service -Path C:\Transfer\transfer.shushbak
```

For a local vault:

```powershell
.\backup_vault.ps1 -Action Restore -Vault Local -Path C:\Transfer\transfer.shushbak
```

Enter the archive passphrase at the secure prompt. The complete archive is
authenticated and its records validated before checking the destination and
writing credentials. If any name already exists, restore stops without writing.
To keep existing values and add only missing names, use `-SkipExisting`.
Restore never overwrites existing credentials, including during concurrent writes.

Credential Manager has no multi-record transaction. A write failure after
preflight can leave a partial restore; the command reports the names already
written and stops. Resolve the failure and retry with `-SkipExisting`. It never
deletes credentials to roll back a partial restore.

Verify names with `shush list` (service) or `shush list --local` (local), then test
the destination integrations before retiring the source. Provider configuration
(`proxy.json`), account setup, and unlock factors are not included in an archive.
Copy/review provider configuration separately; do not copy `service_config.json`
between PCs because its account/SID settings belong to the source machine.

## File format and limits

Version 1: ASCII `SHUSHBAK1`, 32 random salt bytes, then the existing shush
authenticated envelope (`version | IV | ciphertext | HMAC`). PBKDF2-SHA256 with
600,000 iterations derives a 32-byte master key. The existing `vault_crypto`
module derives separate AES-256-CBC and HMAC-SHA256 subkeys. Authentication is
checked before decryption. Changing the salt changes the key and fails
authentication; the magic/version has one accepted value. Costs are fixed,
so an untrusted archive cannot request an unbounded KDF iteration count.

The encrypted UTF-8 JSON contains `format: "shush-backup"`, `version: 1`, and a
`secrets` array of `{name, value}` records. Limits: 8 MiB archive, 4,096 records,
256-character names, and the Windows 2,560-byte UTF-16 credential value limit.
Duplicate names and malformed records are rejected. A failed archive write can
leave a partial encrypted file; select a new filename when retrying.

Passphrases and decrypted strings exist transiently in process memory. Byte
buffers containing plaintext and derived keys are cleared; .NET strings cannot
be reliably zeroized. Never run backup under a debugger or process-memory capture.
This is the repository's existing unaudited cryptography, not a new security audit.

## Tests

```powershell
Invoke-Pester .\tests\vault_backup.Tests.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_backup.ps1
```

Tests use synthetic credentials, temporary archives, and an isolated same-user
pipe simulation. They never export production secrets. The service-account login
and cross-PC transfer still require an interactive acceptance check on Windows.
