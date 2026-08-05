# Admin-pipe e2e: runs the daemon same-user with the pipe enabled, then
# verifies CLI service-mode routing, the write-only guarantee (no op returns
# a value), HTTP+pipe concurrency in one process, and the migration helper.
# Self-contained; cleans up all secrets and processes it creates.
param(
    [int]$TimeoutSec = 20
)

$ErrorActionPreference = 'Stop'
$script:exitCode = 0
$script:checks = @()

function _check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $tag = if ($Ok) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Ok) { 'Green' } else { 'Red' }
    $suffix = if ($Detail) { " - $Detail" } else { '' }
    Write-Host "$tag $Name$suffix" -ForegroundColor $color
    $script:checks += [pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail }
    if (-not $Ok) { $script:exitCode = 1 }
}

$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $testsDir
$entryScript = Join-Path $toolDir 'secret_manager.ps1'
$adminModule = Join-Path $toolDir 'modules\admin_pipe.psm1'
$credentialModule = Join-Path $toolDir 'modules\credential_store.psm1'

$proxyPort = 18874
$pipeName = "shush_admin_e2e_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
$currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$secretName = "e2e_pipe_$([guid]::NewGuid().ToString('N').Substring(0, 16))"
$migrateName = "e2e_pipemig_$([guid]::NewGuid().ToString('N').Substring(0, 14))"
$sentinel = "pipe-e2e-value:$([guid]::NewGuid().ToString('N'))"
$updatedSentinel = "pipe-e2e-updated:$([guid]::NewGuid().ToString('N'))"

$scratch = Join-Path $env:TEMP "shush_pipe_e2e_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
New-Item -ItemType Directory -Path $scratch | Out-Null
$serviceConfigPath = Join-Path $scratch 'service_config.json'
$daemonStdout = Join-Path $scratch 'daemon_out.log'
$daemonStderr = Join-Path $scratch 'daemon_err.log'

$daemonProcess = $null

Write-Host "=== shush admin pipe E2E ===" -ForegroundColor Cyan
Write-Host "  pipe: $pipeName  port: $proxyPort  secret: $secretName"

$importsOk = $false
try {
    Import-Module $adminModule -Force
    Import-Module $credentialModule -Force
    $importsOk = $true

    # Pin to the synthetic config path from the start so neither the daemon
    # nor CLI children pick up a real machine service_config.json. The file
    # does not exist yet, so the daemon starts config-less (test flags below
    # provide the pipe); CLI calls run after the file is written.
    $env:SHUSH_SERVICE_CONFIG = $serviceConfigPath

    # Daemon runs as the current user with the pipe enabled via test flags.
    $daemonProcess = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entryScript,
        'proxy', 'start', '--port', $proxyPort,
        '--admin-pipe', $pipeName, '--allow-sid', $currentSid
    ) -WindowStyle Hidden -PassThru -RedirectStandardOutput $daemonStdout -RedirectStandardError $daemonStderr

    $pipeUp = $false
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    while ((Get-Date) -lt $deadline) {
        $ping = send_admin_request -PipeName $pipeName -TimeoutMs 1500 -Request @{ op = 'ping' }
        if ($ping.success) { $pipeUp = $true; break }
        Start-Sleep -Milliseconds 300
    }
    _check "daemon admin pipe answers ping" $pipeUp ''
    if (-not $pipeUp) { exit 1 }

    # CLI service-mode routing: point the CLI at a synthetic service config.
    @{
        mode = 'service'
        account = $env:USERNAME
        allowed_sid = $currentSid
        port = $proxyPort
        pipe_name = $pipeName
    } | ConvertTo-Json | Set-Content $serviceConfigPath -Encoding ascii
    $env:SHUSH_SERVICE_CONFIG = $serviceConfigPath

    $createOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $secretName $sentinel 2>&1
    _check "CLI create routes via pipe" ($LASTEXITCODE -eq 0 -and (($createOutput -join "`n") -like "*Stored new secret*")) ($createOutput -join "`n")

    $listOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript list 2>&1
    _check "CLI list via pipe shows secret" (($listOutput -join "`n") -like "*$secretName*") ''
    _check "CLI list does not include value" (-not (($listOutput -join "`n") -like "*$sentinel*")) ''

    $existsOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript exists $secretName 2>&1
    _check "CLI exists via pipe" ($LASTEXITCODE -eq 0) ($existsOutput -join "`n")

    $duplicateOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $secretName $sentinel 2>&1
    _check "duplicate create via pipe fails without --force" ($LASTEXITCODE -ne 0) ($duplicateOutput -join "`n")

    $forceOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $secretName $updatedSentinel --force 2>&1
    _check "create --force via pipe reports update" (($forceOutput -join "`n") -like "*Updated existing secret*") ($forceOutput -join "`n")

    # Write-only guarantee: every read-flavored op is rejected at parse.
    foreach ($op in @('get', 'read', 'export')) {
        $probe = send_admin_request -PipeName $pipeName -Request @{ op = $op; name = $secretName }
        _check "op '$op' rejected (UNSUPPORTED_OP)" ((-not $probe.success) -and $probe.error.code -eq 'UNSUPPORTED_OP') ''
    }

    # HTTP proxy still serves while the pipe is active (single process).
    try { Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/nope/x" -UseBasicParsing -TimeoutSec 10 | Out-Null; $status = 200 }
    catch { $status = [int]$_.Exception.Response.StatusCode }
    _check "HTTP proxy responds (404) while pipe active" ($status -eq 404) "status=$status"

    $pingAfterHttp = send_admin_request -PipeName $pipeName -Request @{ op = 'ping' }
    _check "pipe still answers after HTTP traffic" ([bool]$pingAfterHttp.success) ''

    # Migration helper: local secret lands in the (here: same) target vault.
    $localStore = set_secret_value -Name $migrateName -Value $sentinel
    _check "fixture local secret stored" ([bool]$localStore.success) ''
    $migration = invoke_vault_migration -PipeName $pipeName
    _check "migration succeeds" ([bool]$migration.success) "failed=$(@($migration.data.failed).Count)"
    _check "migration covered fixture secret" (@($migration.data.migrated) -contains $migrateName) ''

    # Cleanup path via pipe.
    $deleteOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript delete $secretName 2>&1
    _check "CLI delete via pipe" ($LASTEXITCODE -eq 0) ($deleteOutput -join "`n")

    $goneOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript exists $secretName 2>&1
    _check "exists fails after pipe delete" ($LASTEXITCODE -ne 0) ($goneOutput -join "`n")

    # --local bypasses the pipe even in service mode.
    $localList = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript list --local 2>&1
    _check "list --local works in service mode" ($LASTEXITCODE -eq 0) ''

    # Daemon output never contains a secret value.
    $daemonText = (Get-Content $daemonStdout -Raw -ErrorAction SilentlyContinue) + (Get-Content $daemonStderr -Raw -ErrorAction SilentlyContinue)
    _check "daemon output does not leak values" (-not (($daemonText -like "*$sentinel*") -or ($daemonText -like "*$updatedSentinel*"))) ''
    _check "daemon logged admin ops" ($daemonText -like "*admin create*") ''
}
finally {
    Remove-Item Env:\SHUSH_SERVICE_CONFIG -ErrorAction SilentlyContinue
    if ($daemonProcess -and -not $daemonProcess.HasExited) {
        try { Stop-Process -Id $daemonProcess.Id -Force -Confirm:$false } catch { }
    }
    if ($importsOk) {
        foreach ($leftover in @($secretName, $migrateName)) {
            try {
                $cleanup = remove_secret_value -Name $leftover
                if (-not $cleanup.success -and $cleanup.error.code -ne 'NOT_FOUND') {
                    Write-Host "WARNING: cleanup of $leftover failed: $($cleanup.error.message)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "WARNING: cleanup threw: $_" -ForegroundColor Yellow
            }
        }
    }
    try { Remove-Item -Recurse -Force $scratch -Confirm:$false -ErrorAction SilentlyContinue } catch { }
}

$total = $script:checks.Count
$passed = ($script:checks | Where-Object { $_.Ok }).Count
$failed = $total - $passed
$summaryColor = if ($failed -eq 0) { 'Green' } else { 'Red' }
Write-Host ""
Write-Host "=== Summary: $passed/$total passed, $failed failed ===" -ForegroundColor $summaryColor
exit $script:exitCode
