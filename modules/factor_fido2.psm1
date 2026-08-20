# factor_fido2.psm1
# FIDO2 security key (YubiKey and compatible) unlock factor.
#
# Uses the CTAP2 hmac-secret extension: the token holds a per-credential
# secret it will never disclose, and given a fixed 32-byte salt it returns a
# stable 32-byte HMAC output. That output becomes the key-encryption key for
# this slot. The credential is non-resident, so the token stores nothing and
# the credential id lives in the slot file - useless without the token, which
# is exactly the property we want.
#
# Physical touch is required on every unlock. That is the point: a key in
# your pocket cannot be used by someone sitting at the machine.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Nested imports deliberately omit -Force: it unloads the module first, which
# strips those functions from the scope of anything that already imported it.
Import-Module (Join-Path $PSScriptRoot 'vault_crypto.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'vault_keyslots.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'fido2_native.psm1') -DisableNameChecking

$script:fido2KekLabel = 'shush-fido2-kek-v1'
$script:relyingPartyId = 'shush.local'
$script:touchTimeoutMs = 30000

function get_fido2_relying_party_id {
    return $script:relyingPartyId
}

function test_fido2_available {
    $devices = get_fido2_devices
    if (-not $devices.success) {
        return @{ success = $true; data = @{ available = $false; reason = $devices.error.message; devices = @() }; error = $null }
    }

    $list = @($devices.data)
    if ($list.Count -eq 0) {
        return @{
            success = $true
            data = @{
                available = $false
                reason = 'No FIDO2 security key detected. Plug the key in and try again.'
                devices = @()
            }
            error = $null
        }
    }

    return @{
        success = $true
        data = @{ available = $true; reason = 'ready'; devices = $list }
        error = $null
    }
}

# KEK = SHA-256(hmac-secret output || label). The token's output is already
# 32 uniformly random bytes, so no password stretching is wanted here.
function derive_fido2_kek {
    param([byte[]]$Secret)

    $label = [System.Text.Encoding]::ASCII.GetBytes($script:fido2KekLabel)
    $input = New-Object byte[] ($Secret.Length + $label.Length)
    [Array]::Copy($Secret, 0, $input, 0, $Secret.Length)
    [Array]::Copy($label, 0, $input, $Secret.Length, $label.Length)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ,$sha.ComputeHash($input)
    } finally {
        $sha.Dispose()
        clear_bytes -Bytes $input
    }
}

function select_fido2_device {
    $availability = test_fido2_available
    if (-not $availability.data.available) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'FIDO2_UNAVAILABLE'; message = $availability.data.reason }
        }
    }

    $list = @($availability.data.devices)
    if ($list.Count -gt 1) {
        Write-Host "Multiple FIDO2 keys detected; using '$($list[0].Product)'. Unplug the others to pick a different one."
    }
    return @{ success = $true; data = $list[0]; error = $null }
}

function test_fido2_pin_required {
    param([string]$DevicePath)

    $opened = open_fido2_device -Path $DevicePath
    if (-not $opened.success) { return $opened }
    $device = $opened.data
    try {
        return @{ success = $true; data = @{ pin_required = [bool]$device.HasClientPin() }; error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'FIDO2_INFO_FAILED'; message = "Cannot query the security key: $($_.Exception.Message)" }
        }
    } finally {
        $device.Dispose()
    }
}

function build_fido2_slot {
    param(
        [byte[]]$MasterKey,
        [string]$Label,
        [string]$Pin
    )

    $selected = select_fido2_device
    if (-not $selected.success) { return $selected }
    $deviceInfo = $selected.data

    $opened = open_fido2_device -Path $deviceInfo.Path
    if (-not $opened.success) { return $opened }
    $device = $opened.data

    $salt = new_random_bytes -Count 32
    $first = $null
    $second = $null
    $kek = $null
    try {
        if (-not $device.SupportsHmacSecret()) {
            return @{
                success = $false
                data = $null
                error = @{
                    code = 'FIDO2_NO_HMAC_SECRET'
                    message = "Security key '$($deviceInfo.Product)' does not support the hmac-secret extension, so it cannot derive an encryption key. A FIDO2 (not U2F-only) key is required."
                }
            }
        }

        Write-Host "Touch your security key to create the vault credential..."
        $credentialId = $device.MakeHmacSecretCredential($script:relyingPartyId, $env:USERNAME, $Pin, $script:touchTimeoutMs)

        Write-Host "Touch your security key again (1 of 2, verifying repeatability)..."
        $first = $device.GetHmacSecret($script:relyingPartyId, $credentialId, $salt, $Pin, $script:touchTimeoutMs)

        Write-Host "Touch your security key again (2 of 2)..."
        $second = $device.GetHmacSecret($script:relyingPartyId, $credentialId, $salt, $Pin, $script:touchTimeoutMs)

        # hmac-secret is deterministic per spec, but the output differs
        # between verified and unverified assertions. Confirming it here
        # catches a PIN/UV mismatch now instead of at the next unlock, when
        # the secret would already be encrypted under an unreachable key.
        if (-not (compare_bytes_constant_time -Left $first -Right $second)) {
            return @{
                success = $false
                data = $null
                error = @{
                    code = 'FIDO2_NONDETERMINISTIC'
                    message = 'The security key returned two different secrets for the same salt, so it cannot be used as an unlock factor. This usually means user verification was applied inconsistently.'
                }
            }
        }

        $kek = derive_fido2_kek -Secret $first
        $wrapped = wrap_master_key -MasterKey $MasterKey -Kek $kek
        if (-not $wrapped.success) { return $wrapped }

        return @{
            success = $true
            data = @{
                id = new_slot_id
                type = 'fido2'
                label = $(if ($Label) { $Label } else { "security key ($($deviceInfo.Product))" })
                created_utc = (Get-Date).ToUniversalTime().ToString('o')
                rp_id = $script:relyingPartyId
                credential_id = [Convert]::ToBase64String($credentialId)
                hmac_salt = [Convert]::ToBase64String($salt)
                uses_pin = [bool]$Pin
                device_product = [string]$deviceInfo.Product
                wrapped_key = $wrapped.data
            }
            error = $null
        }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'FIDO2_ENROLL_FAILED'; message = $_.Exception.Message }
        }
    } finally {
        clear_bytes -Bytes $first
        clear_bytes -Bytes $second
        clear_bytes -Bytes $kek
        clear_bytes -Bytes $salt
        $device.Dispose()
    }
}

function open_fido2_slot {
    param($Slot, [string]$Pin)

    $devices = get_fido2_devices
    if (-not $devices.success) { return $devices }
    $list = @($devices.data)
    if ($list.Count -eq 0) {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'FIDO2_NOT_PRESENT'
                message = "No security key detected. Plug in the key enrolled as '$($Slot.label)' and try again."
            }
        }
    }

    try {
        $credentialId = [Convert]::FromBase64String([string]$Slot.credential_id)
        $salt = [Convert]::FromBase64String([string]$Slot.hmac_salt)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'SLOT_MALFORMED'; message = 'FIDO2 slot contains invalid base64' }
        }
    }

    # The credential is non-resident, so only the token that minted it can
    # answer. Trying each attached key lets several be plugged in at once.
    $lastError = $null
    foreach ($deviceInfo in $list) {
        $opened = open_fido2_device -Path $deviceInfo.Path
        if (-not $opened.success) { $lastError = $opened.error; continue }
        $device = $opened.data

        $secret = $null
        $kek = $null
        try {
            Write-Host "Touch your security key to unlock the vault..."
            $secret = $device.GetHmacSecret([string]$Slot.rp_id, $credentialId, $salt, $Pin, $script:touchTimeoutMs)
            $kek = derive_fido2_kek -Secret $secret
            return (unwrap_master_key -WrappedKey ([string]$Slot.wrapped_key) -Kek $kek)
        } catch {
            $lastError = @{ code = 'FIDO2_ASSERT_FAILED'; message = $_.Exception.Message }
        } finally {
            clear_bytes -Bytes $secret
            clear_bytes -Bytes $kek
            $device.Dispose()
        }
    }

    return @{
        success = $false
        data = $null
        error = $(if ($lastError) { $lastError } else {
            @{ code = 'FIDO2_ASSERT_FAILED'; message = 'No attached security key could open this slot' }
        })
    }
}

Export-ModuleMember -Function @(
    'get_fido2_relying_party_id',
    'test_fido2_available',
    'test_fido2_pin_required',
    'derive_fido2_kek',
    'select_fido2_device',
    'build_fido2_slot',
    'open_fido2_slot'
)
