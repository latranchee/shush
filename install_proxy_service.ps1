#Requires -RunAsAdministrator
# install_proxy_service.ps1
# One-shot setup for shush service mode:
#   1. Creates a dedicated local account (hidden from the login screen)
#      whose vault will hold the secrets.
#   2. Registers a scheduled task that runs the proxy daemon as that
#      account at startup (Task Scheduler grants the batch-logon right).
#   3. Writes service_config.json so the CLI routes management commands
#      through the daemon's write-only admin pipe.
#   4. Migrates every secret from YOUR vault into the service vault.
#
# After install, agents and CLI tools running as you can MANAGE secrets
# (create/list/delete) but can never read a value back: values leave the
# service vault only as auth headers injected into outbound provider
# requests by the proxy.
#
# Local copies of migrated secrets are KEPT by default; pass -PurgeLocal
# to delete them after successful migration (that is what actually
# removes same-user read access).
#
# Run under Windows PowerShell 5.1 (powershell.exe), elevated.

param(
    [string]$AccountName = 'shush_svc',
    [int]$Port = 8765,
    [string]$PipeName = 'shush_admin',
    [securestring]$ExistingPassword,
    [switch]$SkipMigration,
    [switch]$PurgeLocal,
    [switch]$Uninstall,
    [switch]$RemoveAccount,
    [switch]$NoPause
)

$ErrorActionPreference = 'Stop'

$toolRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$entryScript = Join-Path $toolRoot 'secret_manager.ps1'
$moduleDir = Join-Path $toolRoot 'modules'
$serviceConfigPath = Join-Path $toolRoot 'service_config.json'
$taskName = 'shush_proxy'

Import-Module (Join-Path $moduleDir 'credential_store.psm1') -Force
Import-Module (Join-Path $moduleDir 'admin_pipe.psm1') -Force

function pause_before_exit {
    param([int]$Code)
    if (-not $NoPause) {
        Write-Host ""
        Read-Host "Press Enter to close" | Out-Null
    }
    exit $Code
}

function fail {
    param([string]$Message)
    Write-Host "ERROR: $Message" -ForegroundColor Red
    pause_before_exit 1
}

# Scheduled tasks with a stored password use BATCH logon; plain local
# accounts do not have that right by default (Task Scheduler's auto-grant
# is not reliable when registering via the cmdlet). Grant it via secedit,
# which works on all editions including Home.
function grant_batch_logon_right {
    param([string]$Sid)

    $workDir = Join-Path $env:TEMP "shush_secedit_$([guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $workDir | Out-Null
    try {
        $exportCfg = Join-Path $workDir 'export.inf'
        $applyDb = Join-Path $workDir 'apply.sdb'
        & secedit /export /cfg $exportCfg /quiet | Out-Null
        if (-not (Test-Path $exportCfg)) {
            Write-Host "WARNING: secedit export failed; cannot verify batch-logon right." -ForegroundColor Yellow
            return
        }

        $lines = Get-Content $exportCfg
        $rightLine = $lines | Where-Object { $_ -match '^SeBatchLogonRight' } | Select-Object -First 1

        if ($rightLine -and $rightLine -match [regex]::Escape($Sid)) {
            Write-Host "Batch-logon right already granted."
            return
        }

        if ($rightLine) {
            $updated = "$rightLine,*$Sid"
            $lines = $lines | ForEach-Object { if ($_ -eq $rightLine) { $updated } else { $_ } }
        } else {
            $lines = $lines | ForEach-Object {
                if ($_ -match '^\[Privilege Rights\]') { @($_, "SeBatchLogonRight = *$Sid") } else { $_ }
            }
        }

        $applyCfg = Join-Path $workDir 'apply.inf'
        Set-Content $applyCfg $lines -Encoding unicode
        & secedit /configure /db $applyDb /cfg $applyCfg /areas USER_RIGHTS /quiet | Out-Null
        Write-Host "Granted 'Log on as a batch job' right."
    }
    finally {
        Remove-Item -Recurse -Force $workDir -Confirm:$false -ErrorAction SilentlyContinue
    }
}

# ---------------------------------------------------------------- uninstall
if ($Uninstall) {
    Write-Host "=== shush service mode uninstall ===" -ForegroundColor Cyan

    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        Write-Host "Removed scheduled task: $taskName"
    } else {
        Write-Host "Scheduled task not found (already removed): $taskName"
    }

    if (Test-Path $serviceConfigPath) {
        Remove-Item $serviceConfigPath -Force -Confirm:$false
        Write-Host "Removed service_config.json (CLI back to local vault)"
    }

    if ($RemoveAccount) {
        $account = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
        if ($account) {
            Write-Host ""
            Write-Host "WARNING: deleting '$AccountName' PERMANENTLY DESTROYS every secret" -ForegroundColor Yellow
            Write-Host "in its vault (DPAPI keys die with the account)." -ForegroundColor Yellow
            $answer = Read-Host "Type the account name to confirm deletion"
            if ($answer -ceq $AccountName) {
                Remove-LocalUser -Name $AccountName
                $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
                Remove-ItemProperty -Path $regPath -Name $AccountName -ErrorAction SilentlyContinue
                Write-Host "Removed account: $AccountName"
            } else {
                Write-Host "Account NOT removed (confirmation mismatch)."
            }
        }
    } else {
        Write-Host "Account '$AccountName' kept (its vault survives; use -RemoveAccount to delete)."
    }

    Write-Host "Uninstall complete." -ForegroundColor Green
    pause_before_exit 0
}

# ------------------------------------------------------------------ install
Write-Host "=== shush service mode install ===" -ForegroundColor Cyan
Write-Host "  account: $AccountName   port: $Port   pipe: $PipeName"
Write-Host ""

if (-not (Test-Path $entryScript)) { fail "secret_manager.ps1 not found next to this installer" }
if (Test-Path $serviceConfigPath) {
    Write-Host "service_config.json already exists; it will be rewritten (re-run/repair)." -ForegroundColor Yellow
}

# The daemon must be able to bind the port; a stale user-session proxy on
# the same port makes the task exit immediately with BIND_FAILED.
$portBusy = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($portBusy) {
    fail "Port $Port is already in use. Stop the process listening on it (a previously started 'proxy start'?) and re-run. Finder: Get-CimInstance Win32_Process -Filter `"Name='powershell.exe'`" | Where-Object { `$_.CommandLine -like '*secret_manager.ps1*proxy*start*' }"
}

# The SID allowed to use the admin pipe: the user running this installer.
# (UAC elevation keeps your identity, so this is you.)
$allowedSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$allowedName = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
Write-Host "Pipe access will be granted to: $allowedName ($allowedSid)"

# --- 1. service account ---------------------------------------------------
$existingAccount = Get-LocalUser -Name $AccountName -ErrorAction SilentlyContinue
$plainPassword = $null

if ($existingAccount) {
    if (-not $ExistingPassword) {
        # Prompt here rather than requiring a parameter: SecureString cannot
        # survive `powershell -File` argument passing (stringified).
        Write-Host "Account '$AccountName' already exists (re-run/repair)."
        $ExistingPassword = Read-Host "Enter the $AccountName password you saved at first install" -AsSecureString
    }
    $plainPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ExistingPassword))
    if ([string]::IsNullOrEmpty($plainPassword)) {
        fail "Empty password. Re-run and enter the saved $AccountName password."
    }
    Write-Host "Using existing account: $AccountName"
} else {
    # Random 24-byte password. Shown ONCE below; it is intentionally not
    # stored anywhere machine-readable (a recoverable password would let
    # same-user code log on as the service account and read the vault).
    $randomBytes = New-Object byte[] 24
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($randomBytes)
    $plainPassword = [Convert]::ToBase64String($randomBytes)
    $securePassword = ConvertTo-SecureString $plainPassword -AsPlainText -Force

    New-LocalUser -Name $AccountName -Password $securePassword `
        -Description 'shush secret vault service account' `
        -PasswordNeverExpires -AccountNeverExpires | Out-Null
    Write-Host "Created account: $AccountName"

    # Keep the login screen clean.
    $regPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList'
    if (-not (Test-Path $regPath)) { New-Item -Path $regPath -Force | Out-Null }
    New-ItemProperty -Path $regPath -Name $AccountName -Value 0 -PropertyType DWord -Force | Out-Null

    Write-Host ""
    Write-Host "  +----------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  |  SAVE THIS PASSWORD in your password manager. It is shown once  |" -ForegroundColor Yellow
    Write-Host "  |  and needed only to re-register the task on this machine.      |" -ForegroundColor Yellow
    Write-Host "  |  (An admin password RESET would destroy the service vault.)    |" -ForegroundColor Yellow
    Write-Host "  +----------------------------------------------------------------+" -ForegroundColor Yellow
    Write-Host "  $AccountName password: $plainPassword" -ForegroundColor Yellow
    Write-Host ""
}

$accountSid = (Get-LocalUser -Name $AccountName).SID.Value
grant_batch_logon_right -Sid $accountSid

# --- 2. filesystem access for the service account -------------------------
& icacls $toolRoot /grant "${AccountName}:(OI)(CI)RX" | Out-Null
Write-Host "Granted read access on $toolRoot to $AccountName"

# Daemon log location: the account needs write access here, and the log is
# the only way to see why a task-hosted daemon failed to start.
$logsDir = Join-Path $toolRoot 'logs'
if (-not (Test-Path $logsDir)) { New-Item -ItemType Directory -Path $logsDir | Out-Null }
& icacls $logsDir /grant "${AccountName}:(OI)(CI)M" | Out-Null
$daemonLog = Join-Path $logsDir 'daemon.log'
Write-Host "Daemon log: $daemonLog"

# --- 3. service_config.json (read by daemon AND client CLI) ---------------
@{
    mode = 'service'
    account = $AccountName
    allowed_sid = $allowedSid
    port = $Port
    pipe_name = $PipeName
} | ConvertTo-Json | Set-Content $serviceConfigPath -Encoding ascii
Write-Host "Wrote service_config.json"

# --- 4. scheduled task running the daemon as the service account ----------
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# cmd.exe wrapper so daemon stdout/stderr land in the log file - without it
# a failing daemon is invisible (task output goes nowhere).
$action = New-ScheduledTaskAction -Execute 'cmd.exe' `
    -Argument "/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$entryScript`" proxy start --port $Port >> `"$daemonLog`" 2>&1" `
    -WorkingDirectory $toolRoot
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -MultipleInstances IgnoreNew

# NOTE: must be machine-qualified; Register-ScheduledTask does not resolve
# the ".\" prefix (fails with 0x80070534 "no mapping ... was done").
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Settings $settings -User "$env:COMPUTERNAME\$AccountName" -Password $plainPassword `
    -RunLevel Limited | Out-Null
$plainPassword = $null
Write-Host "Registered scheduled task: $taskName (runs as $AccountName at startup)"

Start-ScheduledTask -TaskName $taskName
Write-Host "Started daemon; waiting for the admin pipe..."
Start-Sleep -Seconds 2

$taskInfo = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue
if ($taskInfo -and $taskInfo.LastTaskResult -notin @(0, 0x41301, 0x41303)) {
    $code = $taskInfo.LastTaskResult
    $hint = switch ($code) {
        2147943785 { "the account lacks 'Log on as a batch job' (0x80070569) - the right grant above may need a reboot to take effect" }
        2147943726 { "wrong password for $AccountName (0x8007052E) - re-run and enter the saved password exactly" }
        default { "LastTaskResult 0x{0:X}" -f $code }
    }
    Write-Host "Task launch problem: $hint" -ForegroundColor Yellow
}

$pipeUp = $false
$deadline = (Get-Date).AddSeconds(30)
while ((Get-Date) -lt $deadline) {
    $ping = send_admin_request -PipeName $PipeName -TimeoutMs 1500 -Request @{ op = 'ping' }
    if ($ping.success) { $pipeUp = $true; break }
    Start-Sleep -Milliseconds 500
}
if (-not $pipeUp) {
    Write-Host "Daemon did not come up." -ForegroundColor Red
    if (Test-Path $daemonLog) {
        Write-Host "--- last 25 lines of $daemonLog ---" -ForegroundColor Yellow
        Get-Content $daemonLog -Tail 25 | ForEach-Object { Write-Host "  $_" }
    } else {
        Write-Host "No daemon.log was written - the task itself failed to launch." -ForegroundColor Yellow
        Write-Host "Check: Get-ScheduledTaskInfo $taskName (LastTaskResult)" -ForegroundColor Yellow
    }
    fail "Admin pipe unreachable after 30s. service_config.json left in place for debugging."
}
Write-Host "Admin pipe is up." -ForegroundColor Green

# --- 5. vault migration ---------------------------------------------------
if (-not $SkipMigration) {
    Write-Host ""
    Write-Host "Migrating your local vault into the service vault..."
    $migration = invoke_vault_migration -PipeName $PipeName

    foreach ($name in @($migration.data.migrated)) {
        Write-Host "  migrated: $name" -ForegroundColor Green
    }
    foreach ($failure in @($migration.data.failed)) {
        Write-Host "  FAILED:   $($failure.name) ($($failure.error))" -ForegroundColor Red
    }
    Write-Host "Migration: $(@($migration.data.migrated).Count)/$($migration.data.total) migrated."

    if ($PurgeLocal) {
        if (-not $migration.success) {
            Write-Host "Skipping purge: migration was not fully successful." -ForegroundColor Yellow
        } else {
            Write-Host ""
            Write-Host "Purging local copies (verifying each in the service vault first)..."
            foreach ($name in @($migration.data.migrated)) {
                $check = send_admin_request -PipeName $PipeName -Request @{ op = 'exists'; name = $name }
                if ($check.success -and $check.data.exists) {
                    $removal = remove_secret_value -Name $name
                    if ($removal.success) {
                        Write-Host "  purged local: $name"
                    } else {
                        Write-Host "  purge FAILED: $name ($($removal.error.message))" -ForegroundColor Red
                    }
                } else {
                    Write-Host "  NOT purged (service copy unverified): $name" -ForegroundColor Yellow
                }
            }
        }
    } else {
        Write-Host ""
        Write-Host "Local copies were KEPT. Agents running as you can still read those." -ForegroundColor Yellow
        Write-Host "When you are confident everything works, purge them with:" -ForegroundColor Yellow
        Write-Host "  .\secret_manager.ps1 list --local" -ForegroundColor Yellow
        Write-Host "  .\secret_manager.ps1 delete <name> --local" -ForegroundColor Yellow
        Write-Host "or re-run this installer with -PurgeLocal." -ForegroundColor Yellow
    }
}

# --- summary --------------------------------------------------------------
Write-Host ""
Write-Host "=== Service mode is active ===" -ForegroundColor Green
Write-Host "  Proxy:   http://127.0.0.1:$Port/<provider>/<path>"
Write-Host "  Manage:  .\secret_manager.ps1 create|set|list|exists|delete  (via admin pipe)"
Write-Host "  Local:   add --local to any command to touch YOUR vault instead"
Write-Host "  Undo:    .\install_proxy_service.ps1 -Uninstall"
pause_before_exit 0
