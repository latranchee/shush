# factor_keyfile.psm1
# Keyfile unlock factor - a thumbdrive you plug in to start working.
#
# The keyfile holds 32 random bytes that become the key-encryption key for
# this slot. Plug the drive in and any protected secret opens with no typing;
# unplug it and the vault is shut.
#
# Be clear about what this is: a bearer token. Unlike a FIDO2 token, whose
# secret never leaves the hardware, a keyfile is a file - anyone who copies it
# holds the vault, and copying leaves no trace. It is convenience-first, which
# is why enrollment can optionally bind a passphrase to it (--with-passphrase),
# turning it into something-you-have plus something-you-know.
#
# Slots record a random keyfile id rather than a path, because drive letters
# move. Unlock scans removable drives and matches on that id.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Nested imports deliberately omit -Force: it unloads the module first, which
# strips those functions from the scope of anything that already imported it.
Import-Module (Join-Path $PSScriptRoot 'vault_crypto.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'vault_keyslots.psm1') -DisableNameChecking

$script:keyfileKekLabel = 'shush-keyfile-kek-v1'
$script:keyfileMagic = 'shush-keyfile-v1'
$script:defaultKeyfileName = 'shush.key'
$script:keyfileKeyBytes = 32

function get_default_keyfile_name {
    return $script:defaultKeyfileName
}

# Candidate locations, most specific first: an explicit path, the
# SHUSH_KEYFILE override (also what the test suites use), then shush.key at
# the root of every ready removable drive.
function get_keyfile_candidates {
    param([string]$ExplicitPath)

    $candidates = @()
    if ($ExplicitPath -and $ExplicitPath -ne 'auto') {
        $candidates += $ExplicitPath
    }
    if ($env:SHUSH_KEYFILE) {
        $candidates += $env:SHUSH_KEYFILE
    }

    try {
        foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
            if (-not $drive.IsReady) { continue }
            if ($drive.DriveType -ne [System.IO.DriveType]::Removable) { continue }
            $candidates += (Join-Path $drive.RootDirectory.FullName $script:defaultKeyfileName)
        }
    } catch {
        # A drive that vanishes mid-enumeration is not an error; the
        # remaining candidates still stand.
    }

    return @($candidates | Where-Object { $_ } | Select-Object -Unique)
}

function read_keyfile {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_NOT_FOUND'; message = "No keyfile at '$Path'" }
        }
    }

    try {
        $lines = @(Get-Content -Path $Path -ErrorAction Stop)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_UNREADABLE'; message = "Cannot read keyfile '$Path': $($_.Exception.Message)" }
        }
    }

    if (@($lines).Count -eq 0 -or [string]$lines[0] -ne $script:keyfileMagic) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_MALFORMED'; message = "'$Path' is not a shush keyfile" }
        }
    }

    $id = $null
    $encodedKey = $null
    foreach ($line in $lines) {
        $text = [string]$line
        if ($text.StartsWith('id=')) { $id = $text.Substring(3).Trim() }
        elseif ($text.StartsWith('key=')) { $encodedKey = $text.Substring(4).Trim() }
    }

    if (-not $id -or -not $encodedKey) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_MALFORMED'; message = "Keyfile '$Path' is missing its id or key line" }
        }
    }

    try {
        $keyBytes = [Convert]::FromBase64String($encodedKey)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_MALFORMED'; message = "Keyfile '$Path' has an unreadable key" }
        }
    }

    if ($keyBytes.Length -ne $script:keyfileKeyBytes) {
        clear_bytes -Bytes $keyBytes
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_MALFORMED'; message = "Keyfile '$Path' holds $($keyBytes.Length) key bytes; expected $script:keyfileKeyBytes" }
        }
    }

    return @{ success = $true; data = @{ id = $id; key = $keyBytes; path = $Path }; error = $null }
}

function write_keyfile {
    param([string]$Path, [switch]$Force)

    if ((Test-Path $Path) -and -not $Force) {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'KEYFILE_EXISTS'
                message = "A keyfile already exists at '$Path'. Overwriting it would orphan any slot that uses it; pass --force if that is intended."
            }
        }
    }

    $keyBytes = new_random_bytes -Count $script:keyfileKeyBytes
    $id = [guid]::NewGuid().ToString('n')
    try {
        $content = @(
            $script:keyfileMagic
            "id=$id"
            "key=$([Convert]::ToBase64String($keyBytes))"
            "# shush vault keyfile. Anyone holding a copy of this file can"
            "# unlock the secrets it protects. Do not sync it to the cloud."
        ) -join "`r`n"

        $directory = Split-Path $Path -Parent
        if ($directory -and -not (Test-Path $directory)) {
            [void](New-Item -ItemType Directory -Path $directory -Force)
        }
        Set-Content -Path $Path -Value $content -Encoding ASCII -ErrorAction Stop

        return @{ success = $true; data = @{ id = $id; key = $keyBytes; path = $Path }; error = $null }
    } catch {
        clear_bytes -Bytes $keyBytes
        return @{
            success = $false
            data = $null
            error = @{ code = 'KEYFILE_WRITE_FAILED'; message = "Cannot write keyfile '$Path': $($_.Exception.Message)" }
        }
    }
}

# Finds the keyfile matching a slot's recorded id. The path in the slot is a
# hint for the error message only - drive letters move between sessions, so
# the id is what actually identifies the file.
function find_keyfile_by_id {
    param([string]$KeyfileId, [string]$ExplicitPath)

    foreach ($candidate in (get_keyfile_candidates -ExplicitPath $ExplicitPath)) {
        $result = read_keyfile -Path $candidate
        if (-not $result.success) { continue }
        if ($result.data.id -eq $KeyfileId) { return @{ success = $true; data = $result.data; error = $null } }
        clear_bytes -Bytes $result.data.key
    }

    return @{
        success = $false
        data = $null
        error = @{
            code = 'KEYFILE_NOT_PRESENT'
            message = 'The enrolled keyfile was not found. Plug in the drive holding it, or pass --keyfile <path>.'
        }
    }
}

function test_keyfile_available {
    param([string]$ExplicitPath, [string]$KeyfileId)

    if ($KeyfileId) {
        $found = find_keyfile_by_id -KeyfileId $KeyfileId -ExplicitPath $ExplicitPath
        if ($found.success) {
            clear_bytes -Bytes $found.data.key
            return @{ success = $true; data = @{ available = $true; reason = 'ready'; path = $found.data.path }; error = $null }
        }
        return @{ success = $true; data = @{ available = $false; reason = $found.error.message; path = $null }; error = $null }
    }

    $candidates = @(get_keyfile_candidates -ExplicitPath $ExplicitPath)
    if ($candidates.Count -eq 0) {
        return @{
            success = $true
            data = @{
                available = $false
                reason = 'No removable drive detected. Plug one in, or pass --keyfile <path>.'
                path = $null
            }
            error = $null
        }
    }
    return @{ success = $true; data = @{ available = $true; reason = 'ready'; path = $candidates[0] }; error = $null }
}

# KEK = SHA-256(keyfile bytes || label), or when a passphrase is bound,
# HMAC-SHA256 of the same input under the PBKDF2-stretched passphrase. Both
# factors are then required: the file alone will not open the slot.
function derive_keyfile_kek {
    param(
        [byte[]]$KeyBytes,
        [string]$Passphrase,
        [byte[]]$Salt,
        [int]$Iterations
    )

    $label = [System.Text.Encoding]::ASCII.GetBytes($script:keyfileKekLabel)
    $input = New-Object byte[] ($KeyBytes.Length + $label.Length)
    [Array]::Copy($KeyBytes, 0, $input, 0, $KeyBytes.Length)
    [Array]::Copy($label, 0, $input, $KeyBytes.Length, $label.Length)

    $stretched = $null
    try {
        if ([string]::IsNullOrEmpty($Passphrase)) {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                return @{ success = $true; data = $sha.ComputeHash($input); error = $null }
            } finally {
                $sha.Dispose()
            }
        }

        $derived = derive_key_from_passphrase -Passphrase $Passphrase -Salt $Salt -Iterations $Iterations
        if (-not $derived.success) { return $derived }
        $stretched = $derived.data

        $hmac = [System.Security.Cryptography.HMACSHA256]::new($stretched)
        try {
            return @{ success = $true; data = $hmac.ComputeHash($input); error = $null }
        } finally {
            $hmac.Dispose()
        }
    } finally {
        clear_bytes -Bytes $input
        clear_bytes -Bytes $stretched
    }
}

function build_keyfile_slot {
    param(
        [byte[]]$MasterKey,
        [string]$Path,
        [string]$Label,
        [string]$Passphrase,
        [int]$Iterations,
        [switch]$Force
    )

    $target = $Path
    if (-not $target -or $target -eq 'auto') {
        $candidates = @(get_keyfile_candidates -ExplicitPath $null)
        if ($candidates.Count -eq 0) {
            return @{
                success = $false
                data = $null
                error = @{
                    code = 'KEYFILE_NO_TARGET'
                    message = 'No removable drive detected. Plug in the drive, or name the location with --keyfile <path>.'
                }
            }
        }
        $target = $candidates[0]
    }

    # An existing keyfile is reused rather than replaced, so one drive can
    # unlock several machines' vaults.
    $existing = read_keyfile -Path $target
    if ($existing.success -and -not $Force) {
        $material = $existing.data
        Write-Host "Using the keyfile already on this drive: $target"
    } else {
        $created = write_keyfile -Path $target -Force:$Force
        if (-not $created.success) { return $created }
        $material = $created.data
        Write-Host "Wrote a new keyfile: $target"
    }

    # Named apart from the $Iterations parameter on purpose: PowerShell
    # variable names are case-insensitive, so a local $iterations would BE the
    # parameter, and zeroing it here would silently discard the caller's value.
    $salt = $null
    $kdfIterations = 0
    if (-not [string]::IsNullOrEmpty($Passphrase)) {
        $salt = new_random_bytes -Count 16
        $kdfIterations = if ($Iterations) { $Iterations } else { get_default_kdf_iterations }
    }

    $kek = $null
    try {
        $derived = derive_keyfile_kek -KeyBytes $material.key -Passphrase $Passphrase -Salt $salt -Iterations $kdfIterations
        if (-not $derived.success) { return $derived }
        $kek = $derived.data

        $wrapped = wrap_master_key -MasterKey $MasterKey -Kek $kek
        if (-not $wrapped.success) { return $wrapped }

        $slot = @{
            id = new_slot_id
            type = 'keyfile'
            label = $(if ($Label) { $Label } else { 'keyfile' })
            created_utc = (Get-Date).ToUniversalTime().ToString('o')
            keyfile_id = $material.id
            last_known_path = $material.path
            uses_passphrase = (-not [string]::IsNullOrEmpty($Passphrase))
            wrapped_key = $wrapped.data
        }
        if ($null -ne $salt) {
            $slot['kdf'] = 'pbkdf2-sha256'
            $slot['kdf_salt'] = [Convert]::ToBase64String($salt)
            $slot['kdf_iterations'] = $kdfIterations
        }

        return @{ success = $true; data = $slot; error = $null }
    } finally {
        clear_bytes -Bytes $material.key
        clear_bytes -Bytes $kek
        clear_bytes -Bytes $salt
    }
}

function open_keyfile_slot {
    param($Slot, [string]$Path, [string]$Passphrase)

    $found = find_keyfile_by_id -KeyfileId ([string]$Slot.keyfile_id) -ExplicitPath $Path
    if (-not $found.success) { return $found }

    $kek = $null
    try {
        $salt = $null
        $kdfIterations = 0
        if ([bool]$Slot.uses_passphrase) {
            $salt = [Convert]::FromBase64String([string]$Slot.kdf_salt)
            $kdfIterations = [int]$Slot.kdf_iterations
        }

        $derived = derive_keyfile_kek -KeyBytes $found.data.key -Passphrase $Passphrase -Salt $salt -Iterations $kdfIterations
        if (-not $derived.success) { return $derived }
        $kek = $derived.data

        return (unwrap_master_key -WrappedKey ([string]$Slot.wrapped_key) -Kek $kek)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'SLOT_MALFORMED'; message = "Keyfile slot is malformed: $($_.Exception.Message)" }
        }
    } finally {
        clear_bytes -Bytes $found.data.key
        clear_bytes -Bytes $kek
    }
}

Export-ModuleMember -Function @(
    'get_default_keyfile_name',
    'get_keyfile_candidates',
    'read_keyfile',
    'write_keyfile',
    'find_keyfile_by_id',
    'test_keyfile_available',
    'derive_keyfile_kek',
    'build_keyfile_slot',
    'open_keyfile_slot'
)
