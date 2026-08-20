# e2e_hardware_factors.ps1
# Hardware round-trip test for the Windows Hello and FIDO2 unlock factors.
#
# INTERACTIVE. Unlike the other suites this one cannot run unattended: it will
# ask for a Hello gesture and for touches on a security key. It uses a
# throwaway slot file and a throwaway master key, and never touches a real
# secret or a real vault key file.
#
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1
#   powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\e2e_hardware_factors.ps1 -Only fido2
#
# Each factor is skipped, not failed, when its hardware is absent - the point
# is to prove the factor works where the hardware exists.

param(
    [ValidateSet('all', 'hello', 'fido2')]
    [string]$Only = 'all'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Split-Path $PSScriptRoot -Parent
$modulesPath = Join-Path $repoRoot 'modules'

Import-Module (Join-Path $modulesPath 'vault_crypto.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath 'vault_keyslots.psm1') -Force -DisableNameChecking

$script:failures = 0
$script:checks = 0
$script:skips = 0

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

function skip {
    param([string]$Name, [string]$Reason)

    $script:skips++
    Write-Host "  SKIP  $Name" -ForegroundColor Yellow
    Write-Host "        $Reason" -ForegroundColor DarkGray
}

function test_factor_round_trip {
    param([string]$FactorName, [scriptblock]$BuildSlot, [scriptblock]$OpenSlot)

    $masterKey = new_master_key
    $built = & $BuildSlot $masterKey
    if (-not $built.success) {
        check -Name "$FactorName enrollment" -Condition $false -Detail "$($built.error.code): $($built.error.message)"
        return
    }
    check -Name "$FactorName enrollment" -Condition $true

    $slot = $built.data
    check -Name "$FactorName slot stores no master key" `
        -Condition (-not ([string]$slot.wrapped_key).Contains([Convert]::ToBase64String($masterKey)))

    $opened = & $OpenSlot $slot
    if (-not $opened.success) {
        check -Name "$FactorName unlock" -Condition $false -Detail "$($opened.error.code): $($opened.error.message)"
        return
    }
    check -Name "$FactorName unlock" -Condition $true
    check -Name "$FactorName recovers the exact master key" `
        -Condition ([Convert]::ToBase64String($opened.data) -eq [Convert]::ToBase64String($masterKey))

    # A second unlock proves the factor is stable across sessions, which is
    # what a real vault depends on.
    $again = & $OpenSlot $slot
    check -Name "$FactorName unlocks repeatably" `
        -Condition ($again.success -and ([Convert]::ToBase64String($again.data) -eq [Convert]::ToBase64String($masterKey))) `
        -Detail $(if (-not $again.success) { $again.error.message } else { '' })

    # And that a secret encrypted under it actually round-trips.
    $wrapped = protect_secret_string -Value 'hardware-factor-test-value' -MasterKey $masterKey
    $unwrapped = unprotect_secret_string -Value $wrapped.data -MasterKey $opened.data
    check -Name "$FactorName decrypts a protected secret" `
        -Condition ($unwrapped.success -and $unwrapped.data -ceq 'hardware-factor-test-value')
}

Write-Host 'Hardware unlock factor test (interactive)'
Write-Host ''

if ($Only -in @('all', 'hello')) {
    Write-Host 'Windows Hello'
    Import-Module (Join-Path $modulesPath 'factor_hello.psm1') -Force -DisableNameChecking

    $availability = test_hello_available
    if (-not $availability.data.available) {
        skip -Name 'Windows Hello round trip' -Reason $availability.data.reason
    } else {
        Write-Host '  You will be asked for your Hello gesture several times.' -ForegroundColor Cyan
        test_factor_round_trip -FactorName 'hello' `
            -BuildSlot { param($key) build_hello_slot -MasterKey $key -Label 'hardware test' } `
            -OpenSlot { param($slot) open_hello_slot -Slot $slot }
    }
    Write-Host ''
}

if ($Only -in @('all', 'fido2')) {
    Write-Host 'FIDO2 security key'
    Import-Module (Join-Path $modulesPath 'factor_fido2.psm1') -Force -DisableNameChecking

    $availability = test_fido2_available
    if (-not $availability.data.available) {
        skip -Name 'FIDO2 round trip' -Reason $availability.data.reason
    } else {
        foreach ($device in @($availability.data.devices)) {
            Write-Host "  Detected: $($device.Product) (vid $('{0:x4}' -f $device.VendorId), pid $('{0:x4}' -f $device.ProductId))"
        }

        $selected = select_fido2_device
        $pin = ''
        if ($selected.success) {
            $pinState = test_fido2_pin_required -DevicePath $selected.data.Path
            check -Name 'fido2 getInfo answers' -Condition $pinState.success `
                -Detail $(if (-not $pinState.success) { $pinState.error.message } else { '' })

            if ($pinState.success -and $pinState.data.pin_required) {
                Write-Host '  This key has a PIN set; enter it when prompted.' -ForegroundColor Cyan
                $secure = Read-Host 'Security key PIN' -AsSecureString
                $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                try { $pin = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
                finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
            }
        }

        Write-Host '  You will be asked to touch the key several times.' -ForegroundColor Cyan
        test_factor_round_trip -FactorName 'fido2' `
            -BuildSlot { param($key) build_fido2_slot -MasterKey $key -Label 'hardware test' -Pin $pin } `
            -OpenSlot { param($slot) open_fido2_slot -Slot $slot -Pin $pin }
    }
    Write-Host ''
}

Write-Host ''
if ($script:checks -eq 0) {
    Write-Host "No hardware available; $script:skips factor(s) skipped." -ForegroundColor Yellow
    exit 0
}
if ($script:failures -eq 0) {
    Write-Host "All $script:checks checks passed ($script:skips skipped)." -ForegroundColor Green
    exit 0
}
Write-Host "$script:failures of $script:checks checks FAILED." -ForegroundColor Red
exit 1
