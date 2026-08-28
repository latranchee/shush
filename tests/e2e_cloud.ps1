# Cloud e2e: runs the real worker (wrangler dev, fully local) against a
# loopback echo upstream and proves the cloud tier's promises end to end:
# fail-closed-until-configured is bypassed via a dev-vars admin hash, machine
# add, grant enforcement, credential injection (UTF-8 exact), client-auth
# stripping, ?key= scrubbing, immediate revocation, login-code handoff, and
# body round-trip. Offline: no Cloudflare account, no real keys.
#
# Skips (exit 0) with a message when Node.js is absent - same precedent as
# e2e_hardware_factors.ps1 for missing hardware.
param(
    [int]$TimeoutSec = 120
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
$workerDir = Join-Path $toolDir 'cloud\worker'
$entryScript = Join-Path $toolDir 'secret_manager.ps1'
$echoFixture = Join-Path $testsDir 'fixtures\echo_server.ps1'
$cloudModule = Join-Path $toolDir 'modules\cloud_client.psm1'

# Node is the one external dependency of the cloud tier.
$npx = Get-Command 'npx.cmd' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $npx) { $npx = Get-Command 'npx' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1 }
if (-not $npx) {
    Write-Host 'SKIP: Node.js (npx) not found; the cloud e2e needs it. Install Node and re-run.' -ForegroundColor Yellow
    exit 0
}

$echoPort = 18876
$devPort = 18877
$workerUrl = "http://127.0.0.1:$devPort"
$adminToken = "e2e-admin-$([guid]::NewGuid().ToString('N'))"

# The exact bytes that must reach the upstream: accents prove the UTF-8 path.
$echoSecret = 'cl' + [char]0xE9 + '-secr' + [char]0xE8 + 'te-' + [char]0xE9

$scratch = Join-Path $env:TEMP "shush_cloud_e2e_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
New-Item -ItemType Directory -Path $scratch | Out-Null
$devVarsPath = Join-Path $workerDir '.dev.vars'
$devOut = Join-Path $scratch 'wrangler_out.log'
$devErr = Join-Path $scratch 'wrangler_err.log'
$echoOut = Join-Path $scratch 'echo_out.log'
$echoErr = Join-Path $scratch 'echo_err.log'
$cloudConfigPath = Join-Path $scratch 'cloud_config.json'

$echoProcess = $null
$devProcess = $null
$devVarsWritten = $false

Write-Host '=== shush cloud E2E (wrangler dev, offline) ===' -ForegroundColor Cyan
Write-Host "  echo:$echoPort  worker:$devPort"

function wait_for_http {
    param([string]$Url, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return $true
        } catch {
            if ($_.Exception.PSObject.Properties.Match('Response').Count -gt 0 -and $_.Exception.Response) { return $true }
            Start-Sleep -Milliseconds 500
        }
    }
    return $false
}

function get_http_status {
    param([string]$Method, [string]$Url, [hashtable]$Headers = @{}, $Body = $null)
    try {
        $splat = @{ Method = $Method; Uri = $Url; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 15 }
        if ($null -ne $Body) {
            $splat['Body'] = ($Body | ConvertTo-Json -Depth 10)
            $splat['ContentType'] = 'application/json'
        }
        $resp = Invoke-WebRequest @splat
        return [int]$resp.StatusCode
    } catch {
        if ($_.Exception.PSObject.Properties.Match('Response').Count -gt 0 -and $_.Exception.Response) {
            return [int]$_.Exception.Response.StatusCode
        }
        return -1
    }
}

# PS 5.1 Invoke-RestMethod decodes charset-less JSON as Latin-1; fetch raw
# bytes and decode UTF-8 explicitly so accented content asserts faithfully.
function get_json_utf8 {
    param([string]$Method, [string]$Url, [hashtable]$Headers = @{}, [byte[]]$BodyBytes = $null, [string]$ContentType = '')
    $splat = @{ Method = $Method; Uri = $Url; Headers = $Headers; UseBasicParsing = $true; TimeoutSec = 15 }
    if ($null -ne $BodyBytes) {
        $splat['Body'] = $BodyBytes
        $splat['ContentType'] = $ContentType
    }
    $resp = Invoke-WebRequest @splat
    $bytes = $resp.RawContentStream.ToArray()
    return ([System.Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json)
}

try {
    Import-Module $cloudModule -Force

    foreach ($path in @($entryScript, $echoFixture, (Join-Path $workerDir 'wrangler.jsonc'))) {
        _check "preflight: $(Split-Path $path -Leaf) exists" (Test-Path $path) $path
    }
    if ($script:exitCode -ne 0) { exit $script:exitCode }

    # --- echo upstream ---
    $echoProcess = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $echoFixture, '-Port', $echoPort
    ) -PassThru -WindowStyle Hidden -RedirectStandardOutput $echoOut -RedirectStandardError $echoErr
    _check 'echo upstream started' (wait_for_http -Url "http://127.0.0.1:$echoPort/ping" -Seconds 20)

    # --- worker via wrangler dev (fully local) ---
    # .dev.vars supplies what `wrangler secret put` would in production:
    # the admin hash and the provider key. BOM-less UTF-8 or wrangler's
    # dotenv parser sees a mangled first key.
    $adminHash = get_admin_token_hash -Token $adminToken
    $devVars = "ADMIN_TOKEN_HASH=$adminHash`nSK_ECHO_KEY=$echoSecret`n"
    [System.IO.File]::WriteAllText($devVarsPath, $devVars, [System.Text.UTF8Encoding]::new($false))
    $devVarsWritten = $true

    $devProcess = Start-Process $npx.Source -ArgumentList @(
        # Fresh per-run state dir: without it, KV/DO state persists in
        # .wrangler/state and a second run starts at a non-zero config version.
        '--yes', 'wrangler@4.127.0', 'dev', '--port', "$devPort", '--persist-to', (Join-Path $scratch 'state')
    ) -WorkingDirectory $workerDir -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput $devOut -RedirectStandardError $devErr
    _check 'wrangler dev came up' (wait_for_http -Url "$workerUrl/" -Seconds $TimeoutSec)
    if ($script:exitCode -ne 0) { exit $script:exitCode }

    $adminHeaders = @{ Authorization = "Bearer $adminToken" }

    # --- admin auth ---
    _check 'admin API rejects a wrong token (401)' ((get_http_status -Method GET -Url "$workerUrl/api/status" -Headers @{ Authorization = 'Bearer nope' }) -eq 401)
    $status = Invoke-RestMethod -Uri "$workerUrl/api/status" -Headers $adminHeaders -TimeoutSec 15
    _check 'admin status responds with built-in providers' (@($status.providers).Count -ge 3)

    # --- provider overlay pointing at the echo upstream ---
    $putBody = @{
        version = 0
        providers = @{
            echo = @{ secret = 'echo_key'; auth = 'bearer'; base_url = "http://127.0.0.1:$echoPort" }
            other = @{ secret = 'echo_key'; auth = 'x-api-key'; base_url = "http://127.0.0.1:$echoPort" }
        }
    }
    $putResult = Invoke-RestMethod -Method Put -Uri "$workerUrl/api/providers" -Headers $adminHeaders -Body ($putBody | ConvertTo-Json -Depth 10) -ContentType 'application/json' -TimeoutSec 15
    _check 'provider overlay PUT accepted (v1)' ($putResult.version -eq 1)
    _check 'stale-version PUT is rejected (409)' ((get_http_status -Method PUT -Url "$workerUrl/api/providers" -Headers $adminHeaders -Body $putBody) -eq 409)

    # --- machine lifecycle ---
    $created = Invoke-RestMethod -Method Post -Uri "$workerUrl/api/machines" -Headers $adminHeaders -Body (@{ label = 'e2e-machine'; grants = @('echo') } | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 15
    $machineToken = [string]$created.token
    $machineId = [string]$created.machine.id
    _check 'machine add returns a shm. token once' ($machineToken -match '^shm\.[a-z0-9]{12}\.[A-Za-z0-9_-]{40,}$')

    # --- proxying: injection, stripping, UTF-8 ---
    $proxied = get_json_utf8 -Method GET -Url "$workerUrl/echo/v1/models?keep=me" -Headers @{
        Authorization = "Bearer $machineToken"
        'x-api-key' = 'client-cred-should-vanish'
        Cookie = 'session=should-vanish'
    }
    # The worker puts the secret's UTF-8 bytes on the wire; HttpListener
    # exposes header bytes as a Latin-1 string, so byte fidelity is proven by
    # comparing against the Latin-1 rendering of those UTF-8 bytes.
    $expectedHeader = [System.Text.Encoding]::GetEncoding(28591).GetString([System.Text.Encoding]::UTF8.GetBytes("Bearer $echoSecret"))
    _check 'upstream saw the injected key, byte-exact UTF-8' ($proxied.headers.Authorization -ceq $expectedHeader) "got: $($proxied.headers.Authorization)"
    $headerNames = @($proxied.headers.PSObject.Properties | ForEach-Object { $_.Name.ToLowerInvariant() })
    _check 'client x-api-key was stripped' ($headerNames -notcontains 'x-api-key')
    _check 'client cookie was stripped' ($headerNames -notcontains 'cookie')
    _check 'query string passed through' ($proxied.query -eq '?keep=me')
    _check 'upstream path is rewritten' ($proxied.path -eq '/v1/models')

    # --- token via ?key= and scrubbing ---
    $viaKey = Invoke-RestMethod -Uri "$workerUrl/echo/v1beta/x?key=$machineToken&alt=json" -TimeoutSec 15
    _check '?key= accepted as the machine token' ($viaKey.method -eq 'GET')
    _check '?key= scrubbed from the upstream query' ($viaKey.query -notmatch 'key=')

    # --- body round-trip ---
    $bodyText = '{"prompt": "caf' + [char]0xE9 + ' streaming test"}'
    $posted = get_json_utf8 -Method POST -Url "$workerUrl/echo/v1/complete" -Headers @{ Authorization = "Bearer $machineToken" } -BodyBytes ([System.Text.Encoding]::UTF8.GetBytes($bodyText)) -ContentType 'application/json; charset=utf-8'
    _check 'POST body round-trips through the worker (UTF-8)' ($posted.body -ceq $bodyText) "got: $($posted.body)"

    # --- grant enforcement ---
    _check 'ungranted provider is refused (403)' ((get_http_status -Method GET -Url "$workerUrl/other/v1/x" -Headers @{ Authorization = "Bearer $machineToken" }) -eq 403)
    _check 'garbage token is refused (401)' ((get_http_status -Method GET -Url "$workerUrl/echo/v1/x" -Headers @{ Authorization = 'Bearer shm.aaaabbbbcccc.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' }) -eq 401)
    _check 'no token at all is refused (401)' ((get_http_status -Method GET -Url "$workerUrl/echo/v1/x") -eq 401)

    # --- status counters ---
    $statusAfter = Invoke-RestMethod -Uri "$workerUrl/api/status" -Headers $adminHeaders -TimeoutSec 15
    $machineRow = @($statusAfter.machines) | Where-Object { $_.id -eq $machineId }
    _check 'status shows per-machine hits' ($machineRow.total_count -ge 3) "total=$($machineRow.total_count)"

    # --- login-code handoff ---
    $code = (Invoke-RestMethod -Method Post -Uri "$workerUrl/api/login-code" -Headers $adminHeaders -TimeoutSec 15).code
    $session = (Invoke-RestMethod -Method Post -Uri "$workerUrl/api/session" -Body (@{ code = $code } | ConvertTo-Json) -ContentType 'application/json' -TimeoutSec 15).session
    _check 'login code mints a working session' ((get_http_status -Method GET -Url "$workerUrl/api/status" -Headers @{ 'x-shush-session' = $session }) -eq 200)
    _check 'login code is single-use' ((get_http_status -Method POST -Url "$workerUrl/api/session" -Body @{ code = $code }) -eq 401)

    # --- immediate revocation (the DO promise) ---
    $revocationWatch = [System.Diagnostics.Stopwatch]::StartNew()
    Invoke-RestMethod -Method Delete -Uri "$workerUrl/api/machines/$machineId" -Headers $adminHeaders -TimeoutSec 15 | Out-Null
    $afterRevoke = get_http_status -Method GET -Url "$workerUrl/echo/v1/x" -Headers @{ Authorization = "Bearer $machineToken" }
    $revocationWatch.Stop()
    _check 'revocation cuts off the very next request (401)' ($afterRevoke -eq 401) "$($revocationWatch.ElapsedMilliseconds)ms after revoke"

    # --- CLI surface that needs only the config file ---
    $env:SHUSH_CLOUD_CONFIG = $cloudConfigPath
    Set-Content -LiteralPath $cloudConfigPath -Value ('{"worker_url": "' + $workerUrl + '"}')
    $envOutput = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript cloud env openai 2>&1 | Out-String
    _check 'shush cloud env prints the worker base URL' ($envOutput -match [regex]::Escape("$workerUrl/openai/v1"))
    _check 'shush cloud env hides the token without --show' ($envOutput -match '<machine token>')
    Remove-Item Env:SHUSH_CLOUD_CONFIG -ErrorAction SilentlyContinue
}
catch {
    _check "unexpected failure: $($_.Exception.Message)" $false
    if (Test-Path $devErr) {
        Write-Host '--- wrangler stderr (tail) ---' -ForegroundColor Yellow
        Get-Content $devErr -Tail 20 | ForEach-Object { Write-Host "  $_" }
    }
}
finally {
    if ($devProcess -and -not $devProcess.HasExited) {
        # wrangler dev spawns node children; kill the whole tree.
        & taskkill /PID $devProcess.Id /T /F 2>$null | Out-Null
    }
    if ($echoProcess -and -not $echoProcess.HasExited) {
        try { Invoke-WebRequest -Uri "http://127.0.0.1:$echoPort/__shutdown" -UseBasicParsing -TimeoutSec 2 | Out-Null } catch { }
        if (-not $echoProcess.HasExited) { try { Stop-Process -Id $echoProcess.Id -Force } catch { } }
    }
    if ($devVarsWritten) { Remove-Item $devVarsPath -ErrorAction SilentlyContinue }
    Remove-Item Env:SHUSH_CLOUD_CONFIG -ErrorAction SilentlyContinue
    Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue
}

$passed = @($script:checks | Where-Object { $_.Ok }).Count
$total = @($script:checks).Count
Write-Host ''
Write-Host "=== Summary: $passed/$total passed, $($total - $passed) failed ===" -ForegroundColor $(if ($script:exitCode -eq 0) { 'Green' } else { 'Red' })
exit $script:exitCode
