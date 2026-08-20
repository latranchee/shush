# factor_hello.psm1
# Windows Hello unlock factor.
#
# Hello gives us a TPM-backed key that only releases a signature after a
# gesture (PIN, fingerprint, face). RSA PKCS#1 v1.5 signing is deterministic,
# so signing one fixed random challenge yields the same bytes every time -
# which is what lets a signature act as a key-encryption key. The private key
# never leaves the TPM, so a vault file copied to another machine is inert.
#
# Enrollment verifies that determinism by signing twice and comparing, rather
# than trusting it: an authenticator that ever signs with RSA-PSS (or any
# randomized scheme) would produce a slot that can never be opened again.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Nested imports deliberately omit -Force: it unloads the module first, which
# strips those functions from the scope of anything that already imported it.
Import-Module (Join-Path $PSScriptRoot 'vault_crypto.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'vault_keyslots.psm1') -DisableNameChecking

$script:helperPath = Join-Path $PSScriptRoot 'hello_helper.ps1'
$script:helloKekLabel = 'shush-hello-kek-v1'
$script:credentialNamePrefix = 'shush_vault_'
$script:winrtAvailable = $null

function test_winrt_in_process {
    if ($null -ne $script:winrtAvailable) { return $script:winrtAvailable }
    try {
        [void][Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType=WindowsRuntime]
        $script:winrtAvailable = $true
    } catch {
        $script:winrtAvailable = $false
    }
    return $script:winrtAvailable
}

function get_windows_powershell_path {
    return (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
}

# Runs the WinRT helper and parses its single JSON line. In-process when the
# host projects WinRT (5.1), otherwise under powershell.exe 5.1 so PowerShell 7
# is supported too. The out-of-process path carries the signature back over the
# child's stdout pipe - same user, same process tree, and the parent is holding
# the master key in memory anyway, so this adds no new reader.
function invoke_hello_helper {
    param(
        [string]$Operation,
        [string]$CredentialName,
        [string]$ChallengeBase64
    )

    $output = $null
    try {
        if (test_winrt_in_process) {
            $output = & $script:helperPath -Operation $Operation -CredentialName $CredentialName -ChallengeBase64 $ChallengeBase64
        } else {
            $shell = get_windows_powershell_path
            if (-not (Test-Path $shell)) {
                return @{
                    success = $false
                    data = $null
                    error = @{
                        code = 'HELLO_HOST_MISSING'
                        message = "Windows Hello needs Windows PowerShell 5.1 for Windows Runtime access, and it was not found at $shell"
                    }
                }
            }
            $arguments = @(
                '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                '-File', $script:helperPath,
                '-Operation', $Operation
            )
            if ($CredentialName) { $arguments += @('-CredentialName', $CredentialName) }
            if ($ChallengeBase64) { $arguments += @('-ChallengeBase64', $ChallengeBase64) }
            $output = & $shell @arguments
        }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'HELLO_HELPER_FAILED'; message = "Windows Hello helper failed: $($_.Exception.Message)" }
        }
    }

    $line = @($output | Where-Object { $_ -and ([string]$_).Trim().StartsWith('{') } | Select-Object -Last 1)
    if ($line.Count -eq 0) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'HELLO_HELPER_SILENT'; message = 'Windows Hello helper returned no result' }
        }
    }

    try {
        $parsed = [string]$line[0] | ConvertFrom-Json
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'HELLO_HELPER_BAD_OUTPUT'; message = 'Windows Hello helper returned unparseable output' }
        }
    }

    if (-not $parsed.ok) {
        return @{
            success = $false
            data = $null
            error = @{ code = [string]$parsed.code; message = [string]$parsed.message }
        }
    }
    return @{ success = $true; data = $parsed.data; error = $null }
}

function test_hello_available {
    $result = invoke_hello_helper -Operation 'probe'
    if (-not $result.success) {
        return @{ success = $true; data = @{ available = $false; reason = $result.error.message }; error = $null }
    }
    if (-not [bool]$result.data) {
        return @{
            success = $true
            data = @{
                available = $false
                reason = 'Windows Hello reports no usable credential provider on this machine. It needs a TPM and an enrolled Hello PIN (Settings > Accounts > Sign-in options).'
            }
            error = $null
        }
    }
    return @{ success = $true; data = @{ available = $true; reason = 'ready' }; error = $null }
}

# KEK = SHA-256(signature || label). The signature is a full RSA signature of
# a 32-byte random challenge, so it already carries far more entropy than a
# passphrase; no password-stretching KDF is needed or useful here.
function derive_hello_kek {
    param([byte[]]$Signature)

    $label = [System.Text.Encoding]::ASCII.GetBytes($script:helloKekLabel)
    $input = New-Object byte[] ($Signature.Length + $label.Length)
    [Array]::Copy($Signature, 0, $input, 0, $Signature.Length)
    [Array]::Copy($label, 0, $input, $Signature.Length, $label.Length)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ,$sha.ComputeHash($input)
    } finally {
        $sha.Dispose()
        clear_bytes -Bytes $input
    }
}

function get_hello_signature {
    param([string]$CredentialName, [string]$ChallengeBase64)

    $result = invoke_hello_helper -Operation 'sign' -CredentialName $CredentialName -ChallengeBase64 $ChallengeBase64
    if (-not $result.success) { return $result }

    try {
        return @{ success = $true; data = [Convert]::FromBase64String([string]$result.data); error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'HELLO_BAD_SIGNATURE'; message = 'Windows Hello returned an unreadable signature' }
        }
    }
}

function build_hello_slot {
    param([byte[]]$MasterKey, [string]$Label)

    $availability = test_hello_available
    if (-not $availability.data.available) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'HELLO_UNAVAILABLE'; message = $availability.data.reason }
        }
    }

    $credentialName = $script:credentialNamePrefix + (new_slot_id)
    $created = invoke_hello_helper -Operation 'create' -CredentialName $credentialName
    if (-not $created.success) { return $created }

    $challenge = new_random_bytes -Count 32
    $challengeBase64 = [Convert]::ToBase64String($challenge)

    $first = $null
    $second = $null
    $kek = $null
    try {
        Write-Host 'Windows Hello: approve the prompt (1 of 2, verifying repeatability)...'
        $firstResult = get_hello_signature -CredentialName $credentialName -ChallengeBase64 $challengeBase64
        if (-not $firstResult.success) { return $firstResult }
        $first = $firstResult.data

        Write-Host 'Windows Hello: approve the prompt (2 of 2)...'
        $secondResult = get_hello_signature -CredentialName $credentialName -ChallengeBase64 $challengeBase64
        if (-not $secondResult.success) { return $secondResult }
        $second = $secondResult.data

        # A randomized signature scheme would make this slot unopenable, so
        # refuse to enroll rather than hand back a slot that looks fine today
        # and locks the secret forever tomorrow.
        if (-not (compare_bytes_constant_time -Left $first -Right $second)) {
            [void](invoke_hello_helper -Operation 'delete' -CredentialName $credentialName)
            return @{
                success = $false
                data = $null
                error = @{
                    code = 'HELLO_NONDETERMINISTIC'
                    message = 'Windows Hello produced two different signatures for the same challenge, so it cannot be used as an unlock factor on this machine. Use a passphrase or FIDO2 slot instead.'
                }
            }
        }

        $kek = derive_hello_kek -Signature $first
        $wrapped = wrap_master_key -MasterKey $MasterKey -Kek $kek
        if (-not $wrapped.success) { return $wrapped }

        return @{
            success = $true
            data = @{
                id = new_slot_id
                type = 'hello'
                label = $(if ($Label) { $Label } else { 'windows hello' })
                created_utc = (Get-Date).ToUniversalTime().ToString('o')
                credential_name = $credentialName
                challenge = $challengeBase64
                wrapped_key = $wrapped.data
            }
            error = $null
        }
    } finally {
        clear_bytes -Bytes $first
        clear_bytes -Bytes $second
        clear_bytes -Bytes $kek
        clear_bytes -Bytes $challenge
    }
}

function open_hello_slot {
    param($Slot)

    $signature = $null
    $kek = $null
    try {
        Write-Host 'Windows Hello: approve the prompt to unlock the vault...'
        $signatureResult = get_hello_signature -CredentialName ([string]$Slot.credential_name) -ChallengeBase64 ([string]$Slot.challenge)
        if (-not $signatureResult.success) { return $signatureResult }
        $signature = $signatureResult.data

        $kek = derive_hello_kek -Signature $signature
        return (unwrap_master_key -WrappedKey ([string]$Slot.wrapped_key) -Kek $kek)
    } finally {
        clear_bytes -Bytes $signature
        clear_bytes -Bytes $kek
    }
}

function remove_hello_credential {
    param($Slot)

    return (invoke_hello_helper -Operation 'delete' -CredentialName ([string]$Slot.credential_name))
}

Export-ModuleMember -Function @(
    'test_hello_available',
    'test_winrt_in_process',
    'derive_hello_kek',
    'build_hello_slot',
    'open_hello_slot',
    'remove_hello_credential'
)
