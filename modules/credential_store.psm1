# credential_store.psm1
# Windows Credential Manager storage for secret_manager.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$script:credentialTargetPrefix = 'windows-helper-scripts/secret_manager/'
# CRED_PERSIST_LOCAL_MACHINE: per-user-on-this-machine, persisted across sessions.
$script:credentialPersistLocalMachine = 2
# CRED_TYPE_GENERIC: untyped credential blob.
$script:credentialTypeGeneric = 1
# CRED_MAX_CREDENTIAL_BLOB_SIZE = 5*512 (Windows 7+).
$script:credentialMaxBlobSize = 2560
# Win32 error codes.
$script:errNotFound = 1168

function initialize_credential_native {
    if ('Whs.SecretManager.CredentialNative' -as [type]) {
        return
    }

    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace Whs.SecretManager {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CREDENTIAL {
        public UInt32 Flags;
        public UInt32 Type;
        public string TargetName;
        public string Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias;
        public string UserName;
    }

    public static class CredentialNative {
        [DllImport("advapi32.dll", EntryPoint="CredWriteW", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern bool CredWrite(ref CREDENTIAL credential, UInt32 flags);

        [DllImport("advapi32.dll", EntryPoint="CredReadW", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern bool CredRead(string target, UInt32 type, UInt32 reservedFlag, out IntPtr credentialPtr);

        [DllImport("advapi32.dll", EntryPoint="CredDeleteW", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern bool CredDelete(string target, UInt32 type, UInt32 flags);

        [DllImport("advapi32.dll", EntryPoint="CredEnumerateW", CharSet=CharSet.Unicode, SetLastError=true)]
        public static extern bool CredEnumerate(string filter, UInt32 flags, out UInt32 count, out IntPtr credentialPtrs);

        [DllImport("advapi32.dll", EntryPoint="CredFree", SetLastError=true)]
        public static extern void CredFree(IntPtr buffer);
    }
}
'@
}

function test_secret_name {
    param([string]$Name)

    return [bool]($Name -cmatch '^[a-z][a-z0-9_]*$')
}

function assert_secret_name {
    param([string]$Name)

    if (-not (test_secret_name -Name $Name)) {
        throw "Invalid secret name '$Name'. Use lowercase letters, numbers, and underscores; start with a lowercase letter."
    }
}

function get_secret_target {
    param([string]$Name)

    assert_secret_name -Name $Name
    return "$script:credentialTargetPrefix$Name"
}

function get_secret_name_from_target {
    param([string]$Target)

    if ($Target.StartsWith($script:credentialTargetPrefix, [System.StringComparison]::Ordinal)) {
        return $Target.Substring($script:credentialTargetPrefix.Length)
    }
    return $null
}

function format_win32_error {
    param([int]$Code)
    try {
        $msg = (New-Object System.ComponentModel.Win32Exception($Code)).Message
        return "$msg (Win32 $Code)"
    } catch {
        return "Win32 error $Code"
    }
}

function new_invalid_name_error {
    param([string]$Name, [string]$Reason)
    return @{
        success = $false
        data = $null
        error = @{
            code = 'INVALID_NAME'
            message = "Invalid secret name '$Name'. Use lowercase letters, numbers, and underscores; start with a lowercase letter."
        }
    }
}

function try_get_secret_target {
    param([string]$Name)

    if (-not (test_secret_name -Name $Name)) {
        return @{ ok = $false; target = $null; error = (new_invalid_name_error -Name $Name) }
    }
    return @{ ok = $true; target = "$script:credentialTargetPrefix$Name"; error = $null }
}

# Lightweight existence probe that frees the credential immediately without
# decoding the plaintext blob into managed memory. Returns:
#   @{ success=$true; data=@{ exists=bool; win32=int|null }; error=$null }
# or
#   @{ success=$false; data=$null; error=@{code; message; win32} }  on read failure
# (NOT_FOUND is normal and reported as success with exists=$false).
function query_secret_exists {
    param([string]$Name)

    $targetResult = try_get_secret_target -Name $Name
    if (-not $targetResult.ok) { return $targetResult.error }

    initialize_credential_native
    $credentialPtr = [IntPtr]::Zero
    $ok = [Whs.SecretManager.CredentialNative]::CredRead($targetResult.target, $script:credentialTypeGeneric, 0, [ref]$credentialPtr)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $script:errNotFound) {
            return @{ success = $true; data = @{ exists = $false; win32 = $err }; error = $null }
        }
        return @{
            success = $false
            data = $null
            error = @{
                code = 'CRED_READ_FAILED'
                message = "CredRead failed: $(format_win32_error -Code $err)"
                win32 = $err
            }
        }
    }

    if ($credentialPtr -ne [IntPtr]::Zero) {
        [Whs.SecretManager.CredentialNative]::CredFree($credentialPtr)
    }
    return @{ success = $true; data = @{ exists = $true; win32 = 0 }; error = $null }
}

function set_secret_value {
    param(
        [string]$Name,
        [string]$Value,
        [switch]$Force
    )

    $targetResult = try_get_secret_target -Name $Name
    if (-not $targetResult.ok) { return $targetResult.error }
    $target = $targetResult.target

    if ($null -eq $Value -or $Value.Length -eq 0) {
        return @{
            success = $false
            data = $null
            error = @{ code = 'EMPTY_VALUE'; message = "Secret value is empty for '$Name'" }
        }
    }

    $bytes = [System.Text.Encoding]::Unicode.GetBytes($Value)
    if ($bytes.Length -gt $script:credentialMaxBlobSize) {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'VALUE_TOO_LARGE'
                message = "Secret value is $($bytes.Length) bytes; Windows Credential Manager limit is $script:credentialMaxBlobSize bytes"
            }
        }
    }

    initialize_credential_native

    # Cross-process named mutex serializes the no-Force existence check + write
    # against concurrent setters of the same name (TOCTOU mitigation).
    $mutex = [System.Threading.Mutex]::new($false, "Global\whs_secret_$Name")
    $mutexHeld = $false
    $wasOverwritten = $false
    $blob = [IntPtr]::Zero

    try {
        try { [void]$mutex.WaitOne(); $mutexHeld = $true } catch [System.Threading.AbandonedMutexException] { $mutexHeld = $true }

        $existsResult = query_secret_exists -Name $Name
        if (-not $existsResult.success) {
            # Read failure — refuse without --force, since we cannot tell
            # whether we'd be overwriting an existing protected secret.
            if (-not $Force) {
                return @{
                    success = $false
                    data = $null
                    error = @{
                        code = 'EXISTENCE_CHECK_FAILED'
                        message = "Cannot determine whether '$Name' already exists ($($existsResult.error.message)). Use --force to overwrite anyway."
                    }
                }
            }
        } elseif ($existsResult.data.exists) {
            if (-not $Force) {
                return @{
                    success = $false
                    data = $null
                    error = @{
                        code = 'ALREADY_EXISTS'
                        message = "Secret already exists: $Name. Use --force to overwrite."
                    }
                }
            }
            $wasOverwritten = $true
        }

        $blob = [System.Runtime.InteropServices.Marshal]::AllocCoTaskMem($bytes.Length)
        [System.Runtime.InteropServices.Marshal]::Copy($bytes, 0, $blob, $bytes.Length)

        $credential = [Whs.SecretManager.CREDENTIAL]::new()
        $credential.Flags = 0
        $credential.Type = $script:credentialTypeGeneric
        $credential.TargetName = $target
        $credential.Comment = 'windows-helper-scripts secret_manager'
        $credential.CredentialBlobSize = $bytes.Length
        $credential.CredentialBlob = $blob
        $credential.Persist = $script:credentialPersistLocalMachine
        $credential.AttributeCount = 0
        $credential.Attributes = [IntPtr]::Zero
        $credential.TargetAlias = $null
        # Stable audit identity, independent of the writer's logon name.
        $credential.UserName = 'secret_manager'

        $ok = [Whs.SecretManager.CredentialNative]::CredWrite([ref]$credential, 0)
        if (-not $ok) {
            $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
            return @{
                success = $false
                data = $null
                error = @{
                    code = 'CRED_WRITE_FAILED'
                    message = "CredWrite failed: $(format_win32_error -Code $err)"
                    win32 = $err
                }
            }
        }

        return @{
            success = $true
            data = @{ name = $Name; was_overwritten = $wasOverwritten }
            error = $null
        }
    }
    finally {
        # Zero the unmanaged blob and managed byte array before releasing.
        if ($blob -ne [IntPtr]::Zero) {
            for ($i = 0; $i -lt $bytes.Length; $i++) {
                [System.Runtime.InteropServices.Marshal]::WriteByte($blob, $i, 0)
            }
            [System.Runtime.InteropServices.Marshal]::FreeCoTaskMem($blob)
        }
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        if ($mutexHeld) {
            try { $mutex.ReleaseMutex() } catch { }
        }
        $mutex.Dispose()
    }
}

function get_secret_value {
    param([string]$Name)

    $targetResult = try_get_secret_target -Name $Name
    if (-not $targetResult.ok) { return $targetResult.error }
    $target = $targetResult.target

    initialize_credential_native
    $credentialPtr = [IntPtr]::Zero

    $ok = [Whs.SecretManager.CredentialNative]::CredRead($target, $script:credentialTypeGeneric, 0, [ref]$credentialPtr)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $script:errNotFound) {
            return @{
                success = $false
                data = $null
                error = @{ code = 'NOT_FOUND'; message = "Secret not found: $Name"; win32 = $err }
            }
        }
        return @{
            success = $false
            data = $null
            error = @{
                code = 'CRED_READ_FAILED'
                message = "CredRead failed for '$Name': $(format_win32_error -Code $err)"
                win32 = $err
            }
        }
    }

    $bytes = $null
    try {
        $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($credentialPtr, [type][Whs.SecretManager.CREDENTIAL])
        $blobSize = [int]$credential.CredentialBlobSize
        if (($blobSize % 2) -ne 0) {
            return @{
                success = $false
                data = $null
                error = @{ code = 'MALFORMED_BLOB'; message = "Credential blob for '$Name' has odd byte count ($blobSize); refusing UTF-16 decode" }
            }
        }
        $bytes = New-Object byte[] $blobSize
        [System.Runtime.InteropServices.Marshal]::Copy($credential.CredentialBlob, $bytes, 0, $bytes.Length)
        $value = [System.Text.Encoding]::Unicode.GetString($bytes)
        return @{ success = $true; data = $value; error = $null }
    }
    finally {
        if ($null -ne $bytes) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
        if ($credentialPtr -ne [IntPtr]::Zero) {
            [Whs.SecretManager.CredentialNative]::CredFree($credentialPtr)
        }
    }
}

# Boolean wrapper preserved for backward-compat. Uses query_secret_exists so
# no plaintext is materialized; returns $false on any read failure.
function test_secret_exists {
    param([string]$Name)

    $result = query_secret_exists -Name $Name
    if (-not $result.success) { return $false }
    return [bool]$result.data.exists
}

function remove_secret_value {
    param([string]$Name)

    $targetResult = try_get_secret_target -Name $Name
    if (-not $targetResult.ok) { return $targetResult.error }
    $target = $targetResult.target

    initialize_credential_native

    $ok = [Whs.SecretManager.CredentialNative]::CredDelete($target, $script:credentialTypeGeneric, 0)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $script:errNotFound) {
            return @{
                success = $false
                data = $null
                error = @{ code = 'NOT_FOUND'; message = "Secret not found: $Name"; win32 = $err }
            }
        }
        return @{
            success = $false
            data = $null
            error = @{
                code = 'CRED_DELETE_FAILED'
                message = "CredDelete failed for '$Name': $(format_win32_error -Code $err)"
                win32 = $err
            }
        }
    }

    return @{ success = $true; data = @{ name = $Name }; error = $null }
}

function get_secret_names {
    initialize_credential_native

    $count = [UInt32]0
    $credentialPtrs = [IntPtr]::Zero
    $ok = [Whs.SecretManager.CredentialNative]::CredEnumerate("$script:credentialTargetPrefix*", 0, [ref]$count, [ref]$credentialPtrs)

    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        if ($err -eq $script:errNotFound) {
            return @{ success = $true; data = @(); error = $null }
        }
        return @{
            success = $false
            data = $null
            error = @{
                code = 'CRED_ENUM_FAILED'
                message = "CredEnumerate failed: $(format_win32_error -Code $err)"
                win32 = $err
            }
        }
    }

    try {
        $names = [System.Collections.Generic.List[string]]::new()
        for ($i = 0; $i -lt $count; $i++) {
            $itemPtr = [System.Runtime.InteropServices.Marshal]::ReadIntPtr($credentialPtrs, $i * [IntPtr]::Size)
            if ($itemPtr -eq [IntPtr]::Zero) { continue }
            $credential = [System.Runtime.InteropServices.Marshal]::PtrToStructure($itemPtr, [type][Whs.SecretManager.CREDENTIAL])
            $name = get_secret_name_from_target -Target $credential.TargetName
            # Only return names that round-trip through our validator; foreign
            # credentials sharing the prefix would be un-deletable via this tool.
            if ($name -and (test_secret_name -Name $name)) {
                $names.Add($name)
            }
        }
        $sorted = @($names | Sort-Object)
        return @{ success = $true; data = $sorted; error = $null }
    }
    finally {
        if ($credentialPtrs -ne [IntPtr]::Zero) {
            [Whs.SecretManager.CredentialNative]::CredFree($credentialPtrs)
        }
    }
}

Export-ModuleMember -Function @(
    'test_secret_name',
    'assert_secret_name',
    'get_secret_target',
    'set_secret_value',
    'get_secret_value',
    'test_secret_exists',
    'query_secret_exists',
    'remove_secret_value',
    'get_secret_names',
    'format_win32_error'
)
