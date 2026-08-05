param(
    [int]$TimeoutSec = 30
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
        try {
            $cleanupResult = remove_secret_value -Name $secretName
            if ($cleanupResult.success) {
                # Cleanup removed a leftover; nothing else to do.
            } elseif ($cleanupResult.error.code -ne 'NOT_FOUND') {
                Write-Host "WARNING: cleanup of $secretName failed: $($cleanupResult.error.message)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "WARNING: cleanup threw: $_" -ForegroundColor Yellow
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
