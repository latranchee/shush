# vault_crypto.psm1
# Authenticated encryption for protected secrets.
#
# AES-256-CBC + HMAC-SHA256 in encrypt-then-MAC order. Not AES-GCM: that
# lives in System.Security.Cryptography.AesGcm, which is .NET Core 3.0+
# only, and this repo supports Windows PowerShell 5.1 (.NET Framework).
# CBC+HMAC is the strongest construction available on both hosts.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Envelope marker on stored credential blobs. A value that does not start
# with this is a legacy plaintext secret and is returned as-is, so
# protected and unprotected secrets coexist in one vault.
$script:envelopePrefix = 'shush.v1:'
$script:envelopeVersion = 1
$script:aesKeyBytes = 32
$script:ivBytes = 16
$script:macBytes = 32
# Envelope layout: [version 1][iv 16][ciphertext n][mac 32]
$script:envelopeOverhead = 1 + $script:ivBytes + $script:macBytes

# Derived from the Windows credential blob ceiling (2560 bytes), which the
# store writes as UTF-16, so 1280 chars. Minus the 9-char prefix leaves 1271
# base64 chars, rounded down to a 4-char boundary = 1268 chars = 951 bytes of
# envelope. Minus 49 bytes of overhead leaves 902 bytes for ciphertext; PKCS7
# rounds up to a 16-byte boundary and always adds at least one byte, so the
# largest plaintext that still fits is 895 bytes of UTF-8.
$script:maxProtectedPlaintextBytes = 895

# Subkey labels. One master key per vault, split into independent encryption
# and authentication keys so the same bytes never serve both roles.
$script:encryptionSubkeyLabel = 'shush-enc-v1'
$script:macSubkeyLabel = 'shush-mac-v1'

function new_random_bytes {
    param([int]$Count)

    $bytes = New-Object byte[] $Count
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ,$bytes
}

function clear_bytes {
    param([byte[]]$Bytes)

    if ($null -ne $Bytes -and $Bytes.Length -gt 0) {
        [Array]::Clear($Bytes, 0, $Bytes.Length)
    }
}

# Length-independent comparison. Compares every byte of the longer input so
# the running time does not reveal the position of the first difference.
function compare_bytes_constant_time {
    param([byte[]]$Left, [byte[]]$Right)

    if ($null -eq $Left -or $null -eq $Right) { return $false }
    $diff = $Left.Length -bxor $Right.Length
    $max = [Math]::Max($Left.Length, $Right.Length)
    for ($i = 0; $i -lt $max; $i++) {
        $l = if ($i -lt $Left.Length) { $Left[$i] } else { 0 }
        $r = if ($i -lt $Right.Length) { $Right[$i] } else { 0 }
        $diff = $diff -bor ($l -bxor $r)
    }
    return ($diff -eq 0)
}

function derive_subkey {
    param([byte[]]$MasterKey, [string]$Label)

    $hmac = [System.Security.Cryptography.HMACSHA256]::new($MasterKey)
    try {
        return ,$hmac.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($Label))
    } finally {
        $hmac.Dispose()
    }
}

# PBKDF2-SHA256. Windows PowerShell 5.1 on .NET Framework 4.7.2+ has the
# HashAlgorithmName overload; older frameworks only offer PBKDF1/SHA-1, which
# we refuse rather than silently downgrading the KDF.
function derive_key_from_passphrase {
    param(
        [string]$Passphrase,
        [byte[]]$Salt,
        [int]$Iterations
    )

    try {
        $kdf = [System.Security.Cryptography.Rfc2898DeriveBytes]::new(
            $Passphrase, $Salt, $Iterations,
            [System.Security.Cryptography.HashAlgorithmName]::SHA256)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'KDF_UNAVAILABLE'
                message = "PBKDF2-SHA256 is unavailable on this runtime (.NET Framework 4.7.2+ required): $($_.Exception.Message)"
            }
        }
    }

    try {
        return @{ success = $true; data = $kdf.GetBytes($script:aesKeyBytes); error = $null }
    } finally {
        if ($kdf -is [System.IDisposable]) { $kdf.Dispose() }
    }
}

function get_max_protected_plaintext_bytes {
    return $script:maxProtectedPlaintextBytes
}

function test_protected_value {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) { return $false }
    return $Value.StartsWith($script:envelopePrefix, [System.StringComparison]::Ordinal)
}

function protect_bytes {
    param([byte[]]$Plaintext, [byte[]]$MasterKey)

    if ($null -eq $MasterKey -or $MasterKey.Length -ne $script:aesKeyBytes) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'BAD_KEY'; message = "Master key must be $script:aesKeyBytes bytes" }
        }
    }

    $encKey = $null
    $macKey = $null
    $aes = $null
    try {
        $encKey = derive_subkey -MasterKey $MasterKey -Label $script:encryptionSubkeyLabel
        $macKey = derive_subkey -MasterKey $MasterKey -Label $script:macSubkeyLabel

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey
        $aes.GenerateIV()
        $iv = $aes.IV

        $encryptor = $aes.CreateEncryptor()
        try {
            $ciphertext = $encryptor.TransformFinalBlock($Plaintext, 0, $Plaintext.Length)
        } finally {
            $encryptor.Dispose()
        }

        # MAC covers version and IV as well as ciphertext, so neither can be
        # swapped without detection.
        $signed = New-Object byte[] (1 + $iv.Length + $ciphertext.Length)
        $signed[0] = [byte]$script:envelopeVersion
        [Array]::Copy($iv, 0, $signed, 1, $iv.Length)
        [Array]::Copy($ciphertext, 0, $signed, 1 + $iv.Length, $ciphertext.Length)

        $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
        try {
            $mac = $hmac.ComputeHash($signed)
        } finally {
            $hmac.Dispose()
        }

        $envelope = New-Object byte[] ($signed.Length + $mac.Length)
        [Array]::Copy($signed, 0, $envelope, 0, $signed.Length)
        [Array]::Copy($mac, 0, $envelope, $signed.Length, $mac.Length)

        return @{ success = $true; data = $envelope; error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'ENCRYPT_FAILED'; message = "Encryption failed: $($_.Exception.Message)" }
        }
    } finally {
        clear_bytes -Bytes $encKey
        clear_bytes -Bytes $macKey
        if ($null -ne $aes) { $aes.Dispose() }
    }
}

function unprotect_bytes {
    param([byte[]]$Envelope, [byte[]]$MasterKey)

    if ($null -eq $MasterKey -or $MasterKey.Length -ne $script:aesKeyBytes) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'BAD_KEY'; message = "Master key must be $script:aesKeyBytes bytes" }
        }
    }
    if ($null -eq $Envelope -or $Envelope.Length -le $script:envelopeOverhead) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'MALFORMED_ENVELOPE'; message = 'Protected value is truncated' }
        }
    }
    if ($Envelope[0] -ne $script:envelopeVersion) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'UNSUPPORTED_VERSION'; message = "Protected value uses envelope version $($Envelope[0]); this build understands $script:envelopeVersion" }
        }
    }

    $encKey = $null
    $macKey = $null
    $aes = $null
    try {
        $macKey = derive_subkey -MasterKey $MasterKey -Label $script:macSubkeyLabel

        $signedLength = $Envelope.Length - $script:macBytes
        $signed = New-Object byte[] $signedLength
        [Array]::Copy($Envelope, 0, $signed, 0, $signedLength)
        $mac = New-Object byte[] $script:macBytes
        [Array]::Copy($Envelope, $signedLength, $mac, 0, $script:macBytes)

        $hmac = [System.Security.Cryptography.HMACSHA256]::new($macKey)
        try {
            $expected = $hmac.ComputeHash($signed)
        } finally {
            $hmac.Dispose()
        }

        # Verify before decrypting. This is what makes the construction
        # encrypt-then-MAC and keeps a wrong key or tampered blob from ever
        # reaching the CBC padding check (a padding oracle).
        if (-not (compare_bytes_constant_time -Left $expected -Right $mac)) {
            return @{
                success = $false
                data = $null
                error = @{ code = 'AUTH_FAILED'; message = 'Wrong key or tampered value: authentication check failed' }
            }
        }

        $encKey = derive_subkey -MasterKey $MasterKey -Label $script:encryptionSubkeyLabel
        $iv = New-Object byte[] $script:ivBytes
        [Array]::Copy($Envelope, 1, $iv, 0, $script:ivBytes)
        $ciphertextLength = $signedLength - 1 - $script:ivBytes
        $ciphertext = New-Object byte[] $ciphertextLength
        [Array]::Copy($Envelope, 1 + $script:ivBytes, $ciphertext, 0, $ciphertextLength)

        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.KeySize = 256
        $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $aes.Key = $encKey
        $aes.IV = $iv

        $decryptor = $aes.CreateDecryptor()
        try {
            $plaintext = $decryptor.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
        } finally {
            $decryptor.Dispose()
        }

        return @{ success = $true; data = $plaintext; error = $null }
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'DECRYPT_FAILED'; message = "Decryption failed: $($_.Exception.Message)" }
        }
    } finally {
        clear_bytes -Bytes $encKey
        clear_bytes -Bytes $macKey
        if ($null -ne $aes) { $aes.Dispose() }
    }
}

# Wraps a secret value into the string form stored in Credential Manager.
function protect_secret_string {
    param([string]$Value, [byte[]]$MasterKey)

    $plaintext = [System.Text.Encoding]::UTF8.GetBytes($Value)
    if ($plaintext.Length -gt $script:maxProtectedPlaintextBytes) {
        clear_bytes -Bytes $plaintext
        return @{
            success = $false
            data = $null
            error = @{
                code = 'VALUE_TOO_LARGE_PROTECTED'
                message = "Secret is $($plaintext.Length) bytes; protected secrets are limited to $script:maxProtectedPlaintextBytes bytes because encryption overhead must fit the Windows credential blob ceiling"
            }
        }
    }

    try {
        $result = protect_bytes -Plaintext $plaintext -MasterKey $MasterKey
        if (-not $result.success) { return $result }
        return @{
            success = $true
            data = $script:envelopePrefix + [Convert]::ToBase64String($result.data)
            error = $null
        }
    } finally {
        clear_bytes -Bytes $plaintext
    }
}

# Inverse of protect_secret_string. A value with no envelope prefix is a
# legacy plaintext secret and passes through untouched.
function unprotect_secret_string {
    param([string]$Value, [byte[]]$MasterKey)

    if (-not (test_protected_value -Value $Value)) {
        return @{ success = $true; data = $Value; error = $null }
    }

    $encoded = $Value.Substring($script:envelopePrefix.Length)
    try {
        $envelope = [Convert]::FromBase64String($encoded)
    } catch {
        return @{
            success = $false
            data = $null
            error = @{ code = 'MALFORMED_ENVELOPE'; message = 'Protected value is not valid base64' }
        }
    }

    $plaintext = $null
    try {
        $result = unprotect_bytes -Envelope $envelope -MasterKey $MasterKey
        if (-not $result.success) { return $result }
        $plaintext = $result.data
        return @{ success = $true; data = [System.Text.Encoding]::UTF8.GetString($plaintext); error = $null }
    } finally {
        clear_bytes -Bytes $plaintext
        clear_bytes -Bytes $envelope
    }
}

Export-ModuleMember -Function @(
    'new_random_bytes',
    'clear_bytes',
    'compare_bytes_constant_time',
    'derive_subkey',
    'derive_key_from_passphrase',
    'get_max_protected_plaintext_bytes',
    'test_protected_value',
    'protect_bytes',
    'unprotect_bytes',
    'protect_secret_string',
    'unprotect_secret_string'
)
