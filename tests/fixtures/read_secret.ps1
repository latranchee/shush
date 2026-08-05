$ErrorActionPreference = 'Stop'

$encoded = $env:WHS_E2E_SECRET
if (-not $encoded) {
    Write-Error 'WHS_E2E_SECRET is missing'
    exit 2
}

$decoded = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
Write-Host "ps_decoded=$decoded"

