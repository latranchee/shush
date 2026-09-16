# Portable, passphrase-encrypted archives. No credential access in this module.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'vault_crypto.psm1') -DisableNameChecking

function backup_failure {
    param([string]$Code, [string]$Message)
    return @{ success = $false; data = $null; error = @{ code = $Code; message = $Message } }
}

function test_backup_records {
    param([object[]]$Records)
    try {
        if ($null -eq $Records -or $Records.Count -gt 4096) { throw 'Invalid count' }
        $seen = @{}
        foreach ($record in $Records) {
            if ($record.name -isnot [string] -or $record.name -cnotmatch '^[a-z][a-z0-9_]*\z' -or
                $record.name.Length -gt 256 -or $seen.ContainsKey($record.name)) { throw 'Invalid name' }
            if ($record.value -isnot [string] -or $record.value.Length -eq 0 -or
                [Text.Encoding]::Unicode.GetByteCount($record.value) -gt 2560) { throw 'Invalid value' }
            # A wrapped local credential cannot be used on the destination without
            # its original unlock factors. Refuse rather than export an unusable vault.
            if (test_protected_value -Value $record.value) {
                return (backup_failure 'PROTECTED_SECRET' 'Protected local secrets are not supported by portable backup. No archive was created or restored.')
            }
            $seen[$record.name] = $true
        }
        return @{ success = $true; data = $null; error = $null }
    } catch {
        return (backup_failure 'INVALID_RECORDS' 'Archive records are invalid, duplicated, or exceed supported limits.')
    }
}

function protect_backup_archive {
    param([object[]]$Records, [string]$Passphrase)
    $key = $null
    $plaintext = $null
    try {
        if ([string]::IsNullOrEmpty($Passphrase) -or $Passphrase.Length -lt 12) {
            return (backup_failure 'WEAK_PASSPHRASE' 'Use a backup passphrase of at least 12 characters.')
        }
        $check = test_backup_records -Records $Records
        if (-not $check.success) { return $check }
        $plaintext = [Text.Encoding]::UTF8.GetBytes((@{ format = 'shush-backup'; version = 1; secrets = @($Records) } | ConvertTo-Json -Depth 5 -Compress))
        if ($plaintext.Length -gt 8MB - 128) { return (backup_failure 'TOO_LARGE' 'Archive exceeds the 8 MiB limit.') }
        $salt = new_random_bytes -Count 32
        $derived = derive_key_from_passphrase -Passphrase $Passphrase -Salt $salt -Iterations 600000
        if (-not $derived.success) { return (backup_failure 'KDF_FAILED' 'Could not derive the backup encryption key.') }
        $key = $derived.data
        $encrypted = protect_bytes -Plaintext $plaintext -MasterKey $key
        if (-not $encrypted.success) { return (backup_failure 'ENCRYPT_FAILED' 'Could not encrypt the archive.') }
        $magic = [Text.Encoding]::ASCII.GetBytes('SHUSHBAK1')
        $archive = New-Object byte[] ($magic.Length + $salt.Length + $encrypted.data.Length)
        [Array]::Copy($magic, 0, $archive, 0, 9)
        [Array]::Copy($salt, 0, $archive, 9, 32)
        [Array]::Copy($encrypted.data, 0, $archive, 41, $encrypted.data.Length)
        return @{ success = $true; data = $archive; error = $null }
    } catch {
        return (backup_failure 'BACKUP_FAILED' 'Could not create the encrypted archive.')
    } finally {
        clear_bytes -Bytes $plaintext
        clear_bytes -Bytes $key
    }
}

function unprotect_backup_archive {
    param([byte[]]$Archive, [string]$Passphrase)
    $key = $null
    $plaintext = $null
    try {
        if ($null -eq $Archive -or $Archive.Length -lt 106 -or $Archive.Length -gt 8MB -or
            [Text.Encoding]::ASCII.GetString($Archive, 0, 9) -cne 'SHUSHBAK1') {
            return (backup_failure 'INVALID_ARCHIVE' 'Not a supported shush backup, or archive exceeds 8 MiB.')
        }
        $salt = New-Object byte[] 32
        [Array]::Copy($Archive, 9, $salt, 0, 32)
        $derived = derive_key_from_passphrase -Passphrase $Passphrase -Salt $salt -Iterations 600000
        if (-not $derived.success) { return (backup_failure 'KDF_FAILED' 'Could not derive the backup encryption key.') }
        $key = $derived.data
        $envelope = New-Object byte[] ($Archive.Length - 41)
        [Array]::Copy($Archive, 41, $envelope, 0, $envelope.Length)
        $opened = unprotect_bytes -Envelope $envelope -MasterKey $key
        if (-not $opened.success) { return (backup_failure 'AUTH_FAILED' 'Wrong passphrase or damaged archive. Nothing was restored.') }
        $plaintext = $opened.data
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $payload = $utf8.GetString($plaintext) | ConvertFrom-Json
        if ($payload.format -cne 'shush-backup' -or $payload.version -ne 1 -or $payload.secrets -isnot [Array]) {
            return (backup_failure 'INVALID_ARCHIVE' 'Archive payload has an unsupported format.')
        }
        $check = test_backup_records -Records $payload.secrets
        if (-not $check.success) { return $check }
        return @{ success = $true; data = @($payload.secrets); error = $null }
    } catch {
        # Never include parser exceptions: they can contain decrypted payload text.
        return (backup_failure 'INVALID_ARCHIVE' 'Archive payload is invalid. Nothing was restored.')
    } finally {
        clear_bytes -Bytes $plaintext
        clear_bytes -Bytes $key
    }
}

Export-ModuleMember -Function test_backup_records, protect_backup_archive, unprotect_backup_archive
