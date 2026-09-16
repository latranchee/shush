# Interactive portable backup/restore. Service export runs as the vault owner;
# the daemon's write-only pipe deliberately has no export operation.
param(
    [Parameter(Mandatory=$true)][ValidateSet('Backup', 'Restore')][string]$Action,
    [Parameter(Mandatory=$true)][string]$Path,
    [Parameter(Mandatory=$true)][ValidateSet('Local', 'Service')][string]$Vault,
    [string[]]$Names,
    [switch]$SkipExisting
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot 'modules\credential_store.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'modules\vault_backup.psm1') -DisableNameChecking
Import-Module (Join-Path $PSScriptRoot 'modules\admin_pipe.psm1') -DisableNameChecking

function read_backup_passphrase {
    param([string]$Prompt)
    $secure = Read-Host $Prompt -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr); $secure.Dispose() }
}

$passphrase = $null
$confirmation = $null
$records = $null
$restored = [Collections.Generic.List[string]]::new()
try {
    if ($Action -eq 'Backup' -and $SkipExisting) { throw 'SkipExisting applies only to Restore.' }
    if ($Action -eq 'Restore' -and $Names) { throw 'Names applies only to Backup.' }
    $full_path = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    $service = $null
    if ($Vault -eq 'Service') {
        $config_path = if ($env:SHUSH_SERVICE_CONFIG) { $env:SHUSH_SERVICE_CONFIG } else { Join-Path $PSScriptRoot 'service_config.json' }
        if (-not (Test-Path -LiteralPath $config_path)) { throw 'Service mode is not configured in this checkout.' }
        $service = Get-Content -LiteralPath $config_path -Raw | ConvertFrom-Json
        if ($Action -eq 'Backup') {
            $expected = [Security.Principal.NTAccount]::new($env:COMPUTERNAME, $service.account).Translate([Security.Principal.SecurityIdentifier]).Value
            if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $expected) {
                throw 'Service backup must run interactively as the configured service account. See docs/backup.md for runas instructions. The admin pipe cannot export secrets.'
            }
        }
    }
    Write-Host ("{0} vault: {1}; Windows identity: {2}" -f $Action, $Vault, [Security.Principal.WindowsIdentity]::GetCurrent().Name)
    if ($Action -eq 'Backup') {
        if (Test-Path -LiteralPath $full_path) { throw 'Destination already exists. Choose a new archive filename.' }
        $passphrase = read_backup_passphrase 'New backup passphrase (at least 12 characters)'
        $confirmation = read_backup_passphrase 'Repeat backup passphrase'
        if ($passphrase -cne $confirmation) { throw 'Passphrases do not match.' }
        if ($passphrase.Length -lt 12) { throw 'Use a backup passphrase of at least 12 characters.' }
        $listed = get_secret_names
        if (-not $listed.success) { throw 'Could not list the source vault.' }
        $selected = @($listed.data)
        if ($Names) {
            foreach ($name in $Names) {
                if ($name -cnotin $selected) { throw 'A requested name is absent from the source vault.' }
            }
            $selected = @($Names | Select-Object -Unique)
        }
        if ($selected.Count -eq 0) { throw 'Source vault is empty. No archive was created.' }
        $records = @(
            foreach ($name in $selected) {
                $read = get_secret_value -Name $name
                if (-not $read.success) { throw 'Could not read a source credential. No archive was created.' }
                @{ name = $name; value = $read.data }
            }
        )
        $sealed = protect_backup_archive -Records $records -Passphrase $passphrase
        if (-not $sealed.success) { throw $sealed.error.message }
        # CreateNew prevents races and accidental replacement. Only ciphertext
        # reaches disk; a failed write may leave a partial, invalid encrypted file.
        $stream = [IO.File]::Open($full_path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $stream.Write($sealed.data, 0, $sealed.data.Length); $stream.Flush() }
        finally { $stream.Dispose() }
        Write-Host ("Backed up {0} secrets to {1}" -f $records.Count, $full_path)
    } else {
        $stream = [IO.File]::OpenRead($full_path)
        try {
            if ($stream.Length -gt 8MB) { throw 'Archive exceeds the 8 MiB limit.' }
            $archive = New-Object byte[] ([int]$stream.Length)
            $offset = 0
            while ($offset -lt $archive.Length) {
                $count = $stream.Read($archive, $offset, $archive.Length - $offset)
                if ($count -eq 0) { throw 'Archive is truncated.' }
                $offset += $count
            }
        } finally { $stream.Dispose() }
        $passphrase = read_backup_passphrase 'Backup passphrase'
        $opened = unprotect_backup_archive -Archive $archive -Passphrase $passphrase
        if (-not $opened.success) { throw $opened.error.message }
        $records = @($opened.data)
        $pending = @(
            foreach ($record in $records) {
                if ($Vault -eq 'Service') {
                    $exists = send_admin_request -PipeName $service.pipe_name -Request @{ op = 'exists'; name = $record.name }
                } else { $exists = query_secret_exists -Name $record.name }
                if (-not $exists.success) { throw 'Could not check the destination vault. Nothing was restored.' }
                if ($exists.data.exists) {
                    if (-not $SkipExisting) { throw 'A destination name already exists. Nothing was restored. Use -SkipExisting to keep existing values.' }
                    Write-Host ("Skipped existing: {0}" -f $record.name)
                } else { $record }
            }
        )
        foreach ($record in $pending) {
            if ($Vault -eq 'Service') {
                $written = send_admin_request -PipeName $service.pipe_name -Request @{ op = 'create'; name = $record.name; value = $record.value; force = $false }
            } else { $written = set_secret_value -Name $record.name -Value $record.value }
            if (-not $written.success) { throw 'A credential write failed. Restore stopped; already restored names are listed below. Retry with -SkipExisting after resolving the failure.' }
            $restored.Add($record.name)
        }
        Write-Host ("Restored {0} secrets; kept {1} existing secrets." -f $restored.Count, ($records.Count - $pending.Count))
    }
} catch {
    # Only intentional errors get details; external errors might contain values.
    if ($_.Exception -is [System.Management.Automation.RuntimeException] -and $_.CategoryInfo.Category -eq 'OperationStopped') {
        Write-Host ("ERROR: {0}" -f $_.Exception.Message) -ForegroundColor Red
    } else { Write-Host 'ERROR: Backup/restore failed. Check the file path, permissions, and vault configuration.' -ForegroundColor Red }
    if ($restored.Count -gt 0) { Write-Host ("Already restored: {0}" -f ($restored -join ', ')) }
    exit 1
} finally {
    # Managed strings cannot be reliably zeroized; keep them process-local and
    # short-lived. No passphrase parameter, stdin mode, transcripts or logging.
    $passphrase = $null
    $confirmation = $null
    $records = $null
}
