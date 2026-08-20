# e2e_protected_secrets.ps1
# End-to-end test for protected secrets against the real credential vault.
#
# Creates a uniquely named throwaway secret and its own key slot file, then
# exercises enroll / protect / run / unprotect. Never reads or modifies any
# real secret, and cleans up after itself even on failure.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_protected_secrets.ps1

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$secretManager = Join-Path $repoRoot 'secret_manager.ps1'
$suffix = ([guid]::NewGuid().ToString('n').Substring(0, 8))
$secretName = "e2e_protected_$suffix"
# Base64 so the child fixture can prove it decoded the real value without any
# step printing a bare secret, matching tests/fixtures/read_secret.ps1.
$secretPlaintext = "protected-$suffix"
$secretValue = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($secretPlaintext))
$vaultPassphrase = "e2e passphrase $suffix"

# Isolate the slot file so a developer's real vault keys are never touched.
$env:SHUSH_VAULT_KEYS = Join-Path ([System.IO.Path]::GetTempPath()) "shush_e2e_keys_$suffix.json"
# Force local-vault behavior even on a service-mode machine.
$env:SHUSH_SERVICE_CONFIG = Join-Path ([System.IO.Path]::GetTempPath()) "shush_e2e_no_service_$suffix.json"

$script:failures = 0
$script:checks = 0

function check {
    param([string]$Name, [bool]$Condition, [string]$Detail)

    $script:checks++
    if ($Condition) {
        Write-Host "  PASS  $Name" -ForegroundColor Green
    } else {
        $script:failures++
        Write-Host "  FAIL  $Name" -ForegroundColor Red
        if ($Detail) { Write-Host "        $Detail" -ForegroundColor Yellow }
    }
}

# ProcessStartInfo.ArgumentList is .NET Core only, and this suite has to run
# on Windows PowerShell 5.1, so arguments are quoted by hand.
function quote_argument {
    param([string]$Value)

    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + ($Value -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"'
}

function run_shush {
    param([string[]]$ShushArguments, [string]$StdinLine)

    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = (Get-Process -Id $PID).Path
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.RedirectStandardInput = $true
    $psi.UseShellExecute = $false
    $psi.WorkingDirectory = $repoRoot

    $allArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $secretManager) + $ShushArguments
    $psi.Arguments = (($allArguments | ForEach-Object { quote_argument -Value $_ }) -join ' ')

    $process = [System.Diagnostics.Process]::Start($psi)
    if ($null -ne $StdinLine) { $process.StandardInput.WriteLine($StdinLine) }
    $process.StandardInput.Close()
    $stdout = $process.StandardOutput.ReadToEnd()
    $stderr = $process.StandardError.ReadToEnd()
    $process.WaitForExit()

    return @{ stdout = $stdout; stderr = $stderr; exit_code = $process.ExitCode }
}

Write-Host "Protected secrets end-to-end test (secret: $secretName)"
Write-Host ''

try {
    Import-Module (Join-Path $repoRoot 'modules\credential_store.psm1') -Force
    Import-Module (Join-Path $repoRoot 'modules\vault_crypto.psm1') -Force -DisableNameChecking

    Write-Host 'Setup'
    $created = run_shush -ShushArguments @('create', $secretName, $secretValue)
    check -Name 'create throwaway secret' -Condition ($created.exit_code -eq 0) -Detail $created.stdout

    Write-Host 'Enrollment'
    $enrolled = run_shush -ShushArguments @('enroll', '--passphrase', '--passphrase-stdin', '--label', 'e2e') -StdinLine $vaultPassphrase
    check -Name 'enroll passphrase slot' -Condition ($enrolled.exit_code -eq 0) -Detail ($enrolled.stdout + $enrolled.stderr)
    check -Name 'slot file created' -Condition (Test-Path $env:SHUSH_VAULT_KEYS)

    $slotFileText = Get-Content $env:SHUSH_VAULT_KEYS -Raw
    check -Name 'slot file holds no passphrase' -Condition (-not $slotFileText.Contains($vaultPassphrase))
    check -Name 'slot file holds no secret value' -Condition (-not $slotFileText.Contains($secretValue))

    $slotsOutput = run_shush -ShushArguments @('slots')
    check -Name 'slots lists the enrolled factor' -Condition ($slotsOutput.stdout -match 'passphrase') -Detail $slotsOutput.stdout

    Write-Host 'Protect'
    $protected = run_shush -ShushArguments @('protect', $secretName, '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'protect succeeds' -Condition ($protected.exit_code -eq 0) -Detail ($protected.stdout + $protected.stderr)

    # The whole point: what sits in Credential Manager must be ciphertext.
    $rawStored = get_secret_value -Name $secretName
    check -Name 'stored blob is an envelope' -Condition (test_protected_value -Value $rawStored.data)
    check -Name 'stored blob does not contain the plaintext' -Condition (-not ([string]$rawStored.data).Contains($secretValue)) `
        -Detail 'Credential Manager still holds a readable secret'

    $listOutput = run_shush -ShushArguments @('list')
    check -Name 'list marks the secret protected' -Condition ($listOutput.stdout -match "$secretName\s+\[protected\]") -Detail $listOutput.stdout

    Write-Host 'Unlock'
    $childScript = Join-Path $repoRoot 'tests\fixtures\read_secret.ps1'
    $ran = run_shush -ShushArguments @('run', (Get-Process -Id $PID).Path, '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $childScript, '--env', "SHUSH_E2E_SECRET=$secretName", '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'run decrypts into the child environment' -Condition ($ran.stdout -match "ps_decoded=$([regex]::Escape($secretPlaintext))") `
        -Detail ($ran.stdout + $ran.stderr)

    Write-Host 'Overwrite stays protected'
    $newPlaintext = "rotated-$suffix"
    $newValue = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($newPlaintext))
    $rotated = run_shush -ShushArguments @('create', $secretName, $newValue, '--force', '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'overwrite of a protected secret succeeds' -Condition ($rotated.exit_code -eq 0) -Detail ($rotated.stdout + $rotated.stderr)

    $afterRotation = get_secret_value -Name $secretName
    check -Name 'overwritten value is still encrypted' -Condition (test_protected_value -Value $afterRotation.data) `
        -Detail 'set/create silently downgraded a protected secret to plaintext'
    check -Name 'overwritten blob does not contain the new plaintext' `
        -Condition (-not ([string]$afterRotation.data).Contains($newValue))

    $reread = run_shush -ShushArguments @('run', (Get-Process -Id $PID).Path, '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $childScript, '--env', "SHUSH_E2E_SECRET=$secretName", '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'rotated value decrypts to the new secret' -Condition ($reread.stdout -match "ps_decoded=$([regex]::Escape($newPlaintext))") `
        -Detail ($reread.stdout + $reread.stderr)

    # Restore the original value so the later round-trip check is meaningful.
    [void](run_shush -ShushArguments @('create', $secretName, $secretValue, '--force', '--passphrase-stdin') -StdinLine $vaultPassphrase)

    $wrongPassphrase = run_shush -ShushArguments @('unprotect', $secretName, '--passphrase-stdin') -StdinLine 'not the passphrase'
    check -Name 'wrong passphrase is refused' -Condition ($wrongPassphrase.exit_code -ne 0) -Detail $wrongPassphrase.stdout
    check -Name 'refusal names the cause' -Condition ($wrongPassphrase.stdout -match 'Unlock failed') -Detail $wrongPassphrase.stdout

    Write-Host 'Unprotect'
    $unprotected = run_shush -ShushArguments @('unprotect', $secretName, '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'unprotect succeeds' -Condition ($unprotected.exit_code -eq 0) -Detail ($unprotected.stdout + $unprotected.stderr)

    $restored = get_secret_value -Name $secretName
    check -Name 'value round-trips intact' -Condition ($restored.data -ceq $secretValue)
    check -Name 'value is plaintext again' -Condition (-not (test_protected_value -Value $restored.data))

    Write-Host 'Keyfile factor'
    # A temp file stands in for the thumbdrive; SHUSH_KEYFILE is the same
    # override a user would reach for when the drive is not removable.
    $keyfilePath = Join-Path ([System.IO.Path]::GetTempPath()) "shush_e2e_keyfile_$suffix.key"
    $enrolledKeyfile = run_shush -ShushArguments @('enroll', '--keyfile', $keyfilePath, '--label', 'e2e drive', '--passphrase-stdin') -StdinLine $vaultPassphrase
    check -Name 'enroll keyfile slot' -Condition ($enrolledKeyfile.exit_code -eq 0) -Detail ($enrolledKeyfile.stdout + $enrolledKeyfile.stderr)
    check -Name 'keyfile written to the drive' -Condition (Test-Path $keyfilePath)

    $keyfileText = Get-Content $keyfilePath -Raw
    check -Name 'keyfile holds no vault passphrase' -Condition (-not $keyfileText.Contains($vaultPassphrase))
    check -Name 'keyfile holds no secret value' -Condition (-not $keyfileText.Contains($secretValue))

    [void](run_shush -ShushArguments @('protect', $secretName, '--passphrase-stdin') -StdinLine $vaultPassphrase)

    # The point of the whole factor: plugged in, nothing is typed.
    $env:SHUSH_KEYFILE = $keyfilePath
    $viaKeyfile = run_shush -ShushArguments @('run', (Get-Process -Id $PID).Path, '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $childScript, '--env', "SHUSH_E2E_SECRET=$secretName")
    check -Name 'keyfile unlocks with no prompt' -Condition ($viaKeyfile.stdout -match "ps_decoded=$([regex]::Escape($secretPlaintext))") `
        -Detail ($viaKeyfile.stdout + $viaKeyfile.stderr)

    # Unplugged: the drive is gone, so the vault must be shut.
    Remove-Item env:SHUSH_KEYFILE -ErrorAction SilentlyContinue
    Rename-Item -Path $keyfilePath -NewName "$(Split-Path $keyfilePath -Leaf).unplugged"
    $unpluggedPath = "$keyfilePath.unplugged"
    $viaMissingKeyfile = run_shush -ShushArguments @('run', (Get-Process -Id $PID).Path, '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $childScript, '--env', "SHUSH_E2E_SECRET=$secretName", '--keyfile', $keyfilePath)
    check -Name 'unplugged keyfile does not unlock' -Condition ($viaMissingKeyfile.stdout -notmatch [regex]::Escape($secretPlaintext)) `
        -Detail 'the secret decrypted without its keyfile'

    # Plugged back in at a different path: matching is by id, not location.
    $movedPath = Join-Path ([System.IO.Path]::GetTempPath()) "shush_e2e_keyfile_moved_$suffix.key"
    Move-Item -Path $unpluggedPath -Destination $movedPath
    $viaMovedKeyfile = run_shush -ShushArguments @('run', (Get-Process -Id $PID).Path, '-NoProfile', '-ExecutionPolicy', 'Bypass',
        '-File', $childScript, '--env', "SHUSH_E2E_SECRET=$secretName", '--keyfile', $movedPath)
    check -Name 'keyfile still unlocks after moving to a new path' `
        -Condition ($viaMovedKeyfile.stdout -match "ps_decoded=$([regex]::Escape($secretPlaintext))") `
        -Detail ($viaMovedKeyfile.stdout + $viaMovedKeyfile.stderr)

    $slotsWithKeyfile = run_shush -ShushArguments @('slots')
    check -Name 'slots lists both factors' `
        -Condition (($slotsWithKeyfile.stdout -match 'keyfile') -and ($slotsWithKeyfile.stdout -match 'passphrase')) `
        -Detail $slotsWithKeyfile.stdout

    [void](run_shush -ShushArguments @('unprotect', $secretName, '--keyfile', $movedPath))
    foreach ($stale in @($keyfilePath, $unpluggedPath, $movedPath)) {
        if (Test-Path $stale) { Remove-Item $stale -Force }
    }

    Write-Host 'Delete clears the protected marker'
    [void](run_shush -ShushArguments @('protect', $secretName, '--passphrase-stdin') -StdinLine $vaultPassphrase)
    [void](run_shush -ShushArguments @('delete', $secretName))
    $keysAfterDelete = Get-Content $env:SHUSH_VAULT_KEYS -Raw | ConvertFrom-Json
    check -Name 'deleted secret is dropped from the protected list' `
        -Condition (-not (@($keysAfterDelete.protected) -contains $secretName)) `
        -Detail "protected list still holds: $(@($keysAfterDelete.protected) -join ', ')"
    # Both enrolled factors (passphrase and keyfile) must outlive the secret.
    check -Name 'key slots survive the delete' -Condition (@($keysAfterDelete.slots).Count -eq 2) `
        -Detail "slots remaining: $(@($keysAfterDelete.slots).Count)"
}
finally {
    Write-Host ''
    Write-Host 'Cleanup'
    $deleted = run_shush -ShushArguments @('delete', $secretName, '--if-exists')
    Write-Host "  removed secret: exit $($deleted.exit_code)"
    if (Test-Path $env:SHUSH_VAULT_KEYS) {
        Remove-Item $env:SHUSH_VAULT_KEYS -Force
        Write-Host '  removed throwaway slot file'
    }
}

Write-Host ''
if ($script:failures -eq 0) {
    Write-Host "All $script:checks checks passed." -ForegroundColor Green
    exit 0
}
Write-Host "$script:failures of $script:checks checks FAILED." -ForegroundColor Red
exit 1
