# vault_keyslots.psm1
# Key slots for the protected vault.
#
# One random 32-byte master key encrypts every protected secret. That master
# key is never stored bare: each enrolled unlock factor (passphrase, Windows
# Hello, FIDO2 token) wraps its own copy under a key-encryption key only that
# factor can reproduce. Same idea as LUKS key slots - enroll a YubiKey and a
# passphrase, lose the YubiKey, still get in.
#
# The slot file holds only wrapped key material and public KDF parameters, so
# it is safe at rest. It lives outside Credential Manager because three slots
# of JSON exceed the 2560-byte credential blob ceiling.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Nested imports deliberately omit -Force: it unloads the module first, which
# strips those functions from the scope of anything that already imported it.
Import-Module (Join-Path $PSScriptRoot 'vault_crypto.psm1') -DisableNameChecking

$script:vaultKeysVersion = 1
$script:masterKeyBytes = 32
# PBKDF2-SHA256 cost, at the OWASP-recommended level. Measured: ~0.2s on
# PowerShell 7 and ~2.1s on Windows PowerShell 5.1, whose .NET Framework
# implementation is roughly ten times slower. The 5.1 delay is deliberate -
# lowering the count to hide it would weaken every passphrase slot on both
# hosts. Hello and FIDO2 slots skip PBKDF2 entirely (their factors already
# supply high-entropy key material), so enroll one of those if the wait
# bothers you on 5.1.
$script:defaultKdfIterations = 600000
$script:supportedSlotTypes = @('passphrase', 'hello', 'fido2')

function get_vault_keys_path {
    if ($env:SHUSH_VAULT_KEYS) { return $env:SHUSH_VAULT_KEYS }
    return (Join-Path (Split-Path $PSScriptRoot -Parent) 'vault_keys.json')
}

function get_default_kdf_iterations {
    return $script:defaultKdfIterations
}

function new_vault_keys {
    return @{
        version = $script:vaultKeysVersion
        slots = @()
        protected = @()
    }
}

function read_vault_keys {
    param([string]$Path)

    if (-not $Path) { $Path = get_vault_keys_path }
    if (-not (Test-Path $Path)) {
        return @{ success = $true; data = $null; error = $null }
    }

    try {
        $raw = Get-Content -Path $Path -Raw -ErrorAction Stop
        $parsed = $raw | ConvertFrom-Json -ErrorAction Stop
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYS_UNREADABLE'; message = "Cannot read vault key file '$Path': $($_.Exception.Message)" }
        }
    }

    if ([int]$parsed.version -ne $script:vaultKeysVersion) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYS_VERSION'; message = "Vault key file '$Path' is version $($parsed.version); this build understands $script:vaultKeysVersion" }
        }
    }

    # Normalize the JSON projection into hashtables so callers can mutate
    # slots without fighting PSCustomObject immutability.
    $slots = @()
    foreach ($slot in @($parsed.slots)) {
        if ($null -eq $slot) { continue }
        $entry = @{}
        foreach ($prop in $slot.PSObject.Properties) { $entry[$prop.Name] = $prop.Value }
        $slots += $entry
    }

    $protected = @()
    if ($parsed.PSObject.Properties.Match('protected').Count -gt 0) {
        $protected = @($parsed.protected | Where-Object { $_ })
    }

    return @{
        success = $true
        data = @{ version = [int]$parsed.version; slots = $slots; protected = $protected }
        error = $null
    }
}

function write_vault_keys {
    param($Keys, [string]$Path)

    if (-not $Path) { $Path = get_vault_keys_path }

    try {
        $json = [ordered]@{
            version = $script:vaultKeysVersion
            slots = @($Keys.slots)
            protected = @($Keys.protected | Sort-Object -Unique)
        } | ConvertTo-Json -Depth 6

        # Write through a temp file so an interrupted write cannot leave a
        # truncated slot file - that would lock every protected secret out.
        $temp = "$Path.tmp"
        Set-Content -Path $temp -Value $json -Encoding UTF8 -NoNewline -ErrorAction Stop
        Move-Item -Path $temp -Destination $Path -Force -ErrorAction Stop
        return @{ success = $true; data = @{ path = $Path }; error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYS_WRITE_FAILED'; message = "Cannot write vault key file '$Path': $($_.Exception.Message)" }
        }
    }
}

function test_vault_initialized {
    param($Keys)

    return ($null -ne $Keys -and @($Keys.slots).Count -gt 0)
}

function test_secret_marked_protected {
    param($Keys, [string]$Name)

    if ($null -eq $Keys) { return $false }
    return (@($Keys.protected) -contains $Name)
}

function new_master_key {
    return ,(new_random_bytes -Count $script:masterKeyBytes)
}

function wrap_master_key {
    param([byte[]]$MasterKey, [byte[]]$Kek)

    $result = protect_bytes -Plaintext $MasterKey -MasterKey $Kek
    if (-not $result.success) { return $result }
    return @{ success = $true; data = [Convert]::ToBase64String($result.data); error = $null }
}

function unwrap_master_key {
    param([string]$WrappedKey, [byte[]]$Kek)

    try {
        $envelope = [Convert]::FromBase64String($WrappedKey)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'SLOT_MALFORMED'; message = 'Key slot contains invalid base64' }
        }
    }

    $result = unprotect_bytes -Envelope $envelope -MasterKey $Kek
    clear_bytes -Bytes $envelope
    if (-not $result.success) {
        # AUTH_FAILED here means the factor produced the wrong KEK - a bad
        # passphrase, the wrong token, a different Hello identity.
        if ($result.error.code -eq 'AUTH_FAILED') {
            return @{
                success = $false
                data = $null
                error = @{ code = 'UNLOCK_FAILED'; message = 'Unlock failed: wrong passphrase, key, or identity for this slot' }
            }
        }
        return $result
    }
    return $result
}

function new_slot_id {
    return ([guid]::NewGuid().ToString('n').Substring(0, 12))
}

function build_passphrase_slot {
    param(
        [string]$Passphrase,
        [byte[]]$MasterKey,
        [string]$Label,
        [int]$Iterations
    )

    if ([string]::IsNullOrEmpty($Passphrase)) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'EMPTY_PASSPHRASE'; message = 'Passphrase is empty' }
        }
    }
    if (-not $Iterations) { $Iterations = $script:defaultKdfIterations }

    $salt = new_random_bytes -Count 16
    $kek = $null
    try {
        $derived = derive_key_from_passphrase -Passphrase $Passphrase -Salt $salt -Iterations $Iterations
        if (-not $derived.success) { return $derived }
        $kek = $derived.data

        $wrapped = wrap_master_key -MasterKey $MasterKey -Kek $kek
        if (-not $wrapped.success) { return $wrapped }

        return @{
            success = $true
            data = @{
                id = new_slot_id
                type = 'passphrase'
                label = $(if ($Label) { $Label } else { 'passphrase' })
                created_utc = (Get-Date).ToUniversalTime().ToString('o')
                kdf = 'pbkdf2-sha256'
                kdf_salt = [Convert]::ToBase64String($salt)
                kdf_iterations = $Iterations
                wrapped_key = $wrapped.data
            }
            error = $null
        }
    } finally {
        clear_bytes -Bytes $kek
    }
}

function open_passphrase_slot {
    param($Slot, [string]$Passphrase)

    $kek = $null
    try {
        $salt = [Convert]::FromBase64String([string]$Slot.kdf_salt)
        $derived = derive_key_from_passphrase -Passphrase $Passphrase -Salt $salt -Iterations ([int]$Slot.kdf_iterations)
        if (-not $derived.success) { return $derived }
        $kek = $derived.data
        return (unwrap_master_key -WrappedKey ([string]$Slot.wrapped_key) -Kek $kek)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'SLOT_MALFORMED'; message = "Passphrase slot is malformed: $($_.Exception.Message)" }
        }
    } finally {
        clear_bytes -Bytes $kek
    }
}

function add_key_slot {
    param($Keys, $Slot)

    $Keys.slots = @(@($Keys.slots) + @($Slot))
    return $Keys
}

function remove_key_slot {
    param($Keys, [string]$SlotId)

    $remaining = @(@($Keys.slots) | Where-Object { [string]$_.id -ne $SlotId })
    if ($remaining.Count -eq @($Keys.slots).Count) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'SLOT_NOT_FOUND'; message = "No key slot with id '$SlotId'" }
        }
    }
    # Removing the last slot would orphan every protected secret: the master
    # key exists only inside the slots.
    if ($remaining.Count -eq 0 -and @($Keys.protected).Count -gt 0) {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'LAST_SLOT'
                message = "Refusing to remove the only key slot while $(@($Keys.protected).Count) secret(s) are protected. Unprotect them first, or enroll another factor."
            }
        }
    }

    $Keys.slots = $remaining
    return @{ success = $true; data = @{ id = $SlotId; remaining = $remaining.Count }; error = $null }
}

function get_slots_by_type {
    param($Keys, [string]$Type)

    return @(@($Keys.slots) | Where-Object { [string]$_.type -eq $Type })
}

function mark_secret_protected {
    param($Keys, [string]$Name)

    $Keys.protected = @(@(@($Keys.protected) + @($Name)) | Sort-Object -Unique)
    return $Keys
}

function unmark_secret_protected {
    param($Keys, [string]$Name)

    $Keys.protected = @(@($Keys.protected) | Where-Object { $_ -ne $Name })
    return $Keys
}

function get_supported_slot_types {
    return $script:supportedSlotTypes
}

Export-ModuleMember -Function @(
    'get_vault_keys_path',
    'get_default_kdf_iterations',
    'new_vault_keys',
    'read_vault_keys',
    'write_vault_keys',
    'test_vault_initialized',
    'test_secret_marked_protected',
    'new_master_key',
    'wrap_master_key',
    'unwrap_master_key',
    'new_slot_id',
    'build_passphrase_slot',
    'open_passphrase_slot',
    'add_key_slot',
    'remove_key_slot',
    'get_slots_by_type',
    'mark_secret_protected',
    'unmark_secret_protected',
    'get_supported_slot_types'
)
