param(
    [int]$TimeoutSec = 30
)

$ErrorActionPreference = 'Stop'
$script:exitCode = 0
$script:checks = @()

# This suite tests LOCAL vault behavior. Pin the CLI (and every child it
# spawns) to local mode even when the machine is in service mode.
$env:SHUSH_SERVICE_CONFIG = Join-Path $env:TEMP "shush_e2e_no_service_$([guid]::NewGuid().ToString('N').Substring(0,8)).json"

function _check {
    param([string]$Name, [bool]$Ok, [string]$Detail = '')
    $tag = if ($Ok) { '[PASS]' } else { '[FAIL]' }
    $color = if ($Ok) { 'Green' } else { 'Red' }
    $suffix = if ($Detail) { " - $Detail" } else { '' }
    Write-Host "$tag $Name$suffix" -ForegroundColor $color
    $script:checks += [pscustomobject]@{ Name = $Name; Ok = $Ok; Detail = $Detail }
    if (-not $Ok) { $script:exitCode = 1 }
}

# Best-effort Python discovery: py launcher first, then PATH. Python checks
# are skipped (not failed) when no interpreter is installed.
function resolve_python_executable {
    try {
        $pyPath = & py -c "import sys; print(sys.executable)" 2>$null
        if ($pyPath -and (Test-Path $pyPath)) { return $pyPath }
    } catch { }
    foreach ($candidate in @('python', 'python3')) {
        $cmd = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return $cmd.Source }
    }
    return $null
}

$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $testsDir
$entryScript = Join-Path $toolDir 'secret_manager.ps1'
$fixtureDir = Join-Path $testsDir 'fixtures'
$psFixture = Join-Path $fixtureDir 'read_secret.ps1'
$pyFixture = Join-Path $fixtureDir 'read_secret.py'
$credentialModule = Join-Path $toolDir 'modules\credential_store.psm1'

$secretName = "e2e_secret_$([guid]::NewGuid().ToString('N'))"
$createName = "e2e_create_$([guid]::NewGuid().ToString('N'))"
$sentinel = "secret-manager-e2e:$([guid]::NewGuid().ToString('N'))"
$encoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($sentinel))
$updatedSentinel = "secret-manager-e2e-updated:$([guid]::NewGuid().ToString('N'))"
$updatedEncoded = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($updatedSentinel))

Write-Host "=== secret_manager E2E ===" -ForegroundColor Cyan
Write-Host "  secret: $secretName"

$importsOk = $false
try {
    Import-Module $credentialModule -Force
    $importsOk = $true

    foreach ($path in @($entryScript, $psFixture, $pyFixture, $credentialModule)) {
        _check "preflight: $(Split-Path $path -Leaf) exists" (Test-Path $path) $path
    }
    if ($script:exitCode -ne 0) { exit $script:exitCode }

    $setOutput = $encoded | powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript set $secretName --from-stdin 2>&1
    _check "set stores fake encoded secret" ($LASTEXITCODE -eq 0) ($setOutput -join "`n")
    _check "set output does not include raw encoded secret" (-not (($setOutput -join "`n") -like "*$encoded*")) ''
    _check "set output does not include decoded sentinel" (-not (($setOutput -join "`n") -like "*$sentinel*")) ''

    $duplicateSetOutput = $encoded | powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript set $secretName --from-stdin 2>&1
    _check "set without --force on existing secret fails" ($LASTEXITCODE -ne 0) ($duplicateSetOutput -join "`n")
    _check "duplicate set error suggests --force" (($duplicateSetOutput -join "`n") -like "*--force*") ($duplicateSetOutput -join "`n")

    $overwriteOutput = $updatedEncoded | powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript set $secretName --from-stdin --force 2>&1
    _check "set --force overwrites existing secret" ($LASTEXITCODE -eq 0) ($overwriteOutput -join "`n")
    _check "overwrite output reports update (not new)" (($overwriteOutput -join "`n") -like "*Updated existing secret*") ($overwriteOutput -join "`n")

    $createOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $createName $encoded 2>&1
    _check "create stores one-liner secret" ($LASTEXITCODE -eq 0) ($createOutput -join "`n")
    _check "create output does not include raw encoded secret" (-not (($createOutput -join "`n") -like "*$encoded*")) ''

    # Without an inline value, create falls back to prompting; with piped
    # empty input that yields an empty value, which is refused.
    $createNoValue = '' | powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create "$($createName)_prompted" --from-stdin 2>&1
    _check "create with empty prompted value fails" ($LASTEXITCODE -ne 0) ($createNoValue -join "`n")

    $promptedName = "$($createName)_prompted"
    $promptedCreate = $encoded | powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $promptedName --from-stdin 2>&1
    _check "create without inline value reads stdin like set" ($LASTEXITCODE -eq 0) ($promptedCreate -join "`n")
    $promptedDelete = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript delete $promptedName --if-exists 2>&1
    _check "prompted-create secret cleaned up" ($LASTEXITCODE -eq 0) ($promptedDelete -join "`n")

    $duplicateCreate = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $createName $encoded 2>&1
    _check "create without --force on existing secret fails" ($LASTEXITCODE -ne 0) ($duplicateCreate -join "`n")

    $forceCreate = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $createName $updatedEncoded --force 2>&1
    _check "create --force overwrites existing secret" ($LASTEXITCODE -eq 0) ($forceCreate -join "`n")
    _check "create --force reports update" (($forceCreate -join "`n") -like "*Updated existing secret*") ($forceCreate -join "`n")

    $createRunOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript run powershell.exe -NoProfile -ExecutionPolicy Bypass -File $psFixture --env WHS_E2E_SECRET=$createName 2>&1
    _check "created secret round-trips through run" (($createRunOutput -join "`n") -like "*ps_decoded=$updatedSentinel*") ($createRunOutput -join "`n")

    $createDelete = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript delete $createName 2>&1
    _check "delete removes created secret" ($LASTEXITCODE -eq 0) ($createDelete -join "`n")

    $listOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript list 2>&1
    _check "list includes secret name" (($listOutput -join "`n") -like "*$secretName*") ''
    _check "list does not include raw encoded secret" (-not (($listOutput -join "`n") -like "*$encoded*")) ''
    _check "list does not include decoded sentinel" (-not (($listOutput -join "`n") -like "*$sentinel*")) ''

    $existsOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript exists $secretName 2>&1
    _check "exists confirms secret name" ($LASTEXITCODE -eq 0) ($existsOutput -join "`n")
    _check "exists does not include raw encoded secret" (-not (($existsOutput -join "`n") -like "*$encoded*")) ''
    _check "exists does not include decoded sentinel" (-not (($existsOutput -join "`n") -like "*$sentinel*")) ''

    $psOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript run powershell.exe -NoProfile -ExecutionPolicy Bypass -File $psFixture --env WHS_E2E_SECRET=$secretName 2>&1
    _check "PowerShell fixture run succeeds" ($LASTEXITCODE -eq 0) ($psOutput -join "`n")
    _check "PowerShell fixture decodes overwritten secret" (($psOutput -join "`n") -like "*ps_decoded=$updatedSentinel*") ($psOutput -join "`n")
    _check "PowerShell wrapper does not print raw encoded secret" (-not (($psOutput -join "`n") -like "*$updatedEncoded*")) ''

    $pythonExe = resolve_python_executable
    if ($pythonExe -and (Test-Path $pythonExe)) {
        $pyOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript run $pythonExe $pyFixture --env WHS_E2E_SECRET=$secretName 2>&1
        _check "Python fixture run succeeds" ($LASTEXITCODE -eq 0) ($pyOutput -join "`n")
        _check "Python fixture decodes overwritten secret" (($pyOutput -join "`n") -like "*py_decoded=$updatedSentinel*") ($pyOutput -join "`n")
        _check "Python wrapper does not print raw encoded secret" (-not (($pyOutput -join "`n") -like "*$updatedEncoded*")) ''
    } else {
        Write-Host "[SKIP] Python checks (no Python interpreter found)" -ForegroundColor Yellow
    }

    $deleteOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript delete $secretName 2>&1
    _check "delete removes secret" ($LASTEXITCODE -eq 0) ($deleteOutput -join "`n")

    $afterDeleteList = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript list 2>&1
    _check "list no longer includes secret name" (-not (($afterDeleteList -join "`n") -like "*$secretName*")) ''

    $afterDeleteExists = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript exists $secretName 2>&1
    _check "exists fails after delete" ($LASTEXITCODE -ne 0) ($afterDeleteExists -join "`n")

    $idempotentDelete = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript delete $secretName --if-exists 2>&1
    _check "delete --if-exists is idempotent on missing secret" ($LASTEXITCODE -eq 0) ($idempotentDelete -join "`n")
}
finally {
    if ($importsOk) {
        foreach ($leftover in @($secretName, $createName)) {
            try {
                $cleanupResult = remove_secret_value -Name $leftover
                if ($cleanupResult.success) {
                    # Cleanup removed a leftover; nothing else to do.
                } elseif ($cleanupResult.error.code -ne 'NOT_FOUND') {
                    Write-Host "WARNING: cleanup of $leftover failed: $($cleanupResult.error.message)" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "WARNING: cleanup threw: $_" -ForegroundColor Yellow
            }
        }
    }
}

$total = $script:checks.Count
$passed = ($script:checks | Where-Object { $_.Ok }).Count
$failed = $total - $passed
$summaryColor = if ($failed -eq 0) { 'Green' } else { 'Red' }
Write-Host ""
Write-Host "=== Summary: $passed/$total passed, $failed failed ===" -ForegroundColor $summaryColor
exit $script:exitCode
