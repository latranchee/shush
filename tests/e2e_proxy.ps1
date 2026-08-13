# Proxy e2e: spins up a loopback echo upstream and the shush proxy, stores a
# throwaway secret, then verifies credential injection, client-auth stripping,
# body round-trip, error routing, and that the secret never leaks into proxy
# output. Self-contained: no internet, no real keys, cleans up after itself.
param(
    [int]$TimeoutSec = 20
)

$ErrorActionPreference = 'Stop'
$script:exitCode = 0
$script:checks = @()

# This suite tests LOCAL vault + proxy behavior. Pin the CLI and daemon to
# local mode even when the machine is in service mode.
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

$testsDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$toolDir = Split-Path -Parent $testsDir
$entryScript = Join-Path $toolDir 'secret_manager.ps1'
$echoFixture = Join-Path $testsDir 'fixtures\echo_server.ps1'
$credentialModule = Join-Path $toolDir 'modules\credential_store.psm1'

$echoPort = 18871
$proxyPort = 18872
$slowPort = 18873
$secretName = "e2e_proxy_$([guid]::NewGuid().ToString('N').Substring(0, 16))"
$sentinel = "proxy-e2e-key:$([guid]::NewGuid().ToString('N'))"

$scratch = Join-Path $env:TEMP "shush_proxy_e2e_$([guid]::NewGuid().ToString('N').Substring(0, 8))"
New-Item -ItemType Directory -Path $scratch | Out-Null
$configPath = Join-Path $scratch 'proxy.json'
$proxyStdout = Join-Path $scratch 'proxy_out.log'
$proxyStderr = Join-Path $scratch 'proxy_err.log'
$echoStdout = Join-Path $scratch 'echo_out.log'
$echoStderr = Join-Path $scratch 'echo_err.log'
$slowStdout = Join-Path $scratch 'slow_out.log'
$slowStderr = Join-Path $scratch 'slow_err.log'

$echoProcess = $null
$proxyProcess = $null
$slowProcess = $null

Write-Host "=== shush proxy E2E ===" -ForegroundColor Cyan
Write-Host "  secret: $secretName  echo:$echoPort  proxy:$proxyPort"

function wait_for_http {
    param([string]$Url, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2 | Out-Null
            return $true
        } catch {
            if ($_.Exception.Response) { return $true }  # got an HTTP status = listening
            Start-Sleep -Milliseconds 250
        }
    }
    return $false
}

$importsOk = $false
try {
    Import-Module $credentialModule -Force
    $importsOk = $true

    foreach ($path in @($entryScript, $echoFixture, $credentialModule)) {
        _check "preflight: $(Split-Path $path -Leaf) exists" (Test-Path $path) $path
    }
    if ($script:exitCode -ne 0) { exit $script:exitCode }

    $storeOutput = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $entryScript create $secretName $sentinel 2>&1
    _check "throwaway secret stored via create" ($LASTEXITCODE -eq 0) ($storeOutput -join "`n")

    @{
        providers = @{
            echo = @{
                secret = $secretName
                auth = 'bearer'
                base_url = "http://127.0.0.1:$echoPort"
                allow_methods = @('GET', 'POST')
                max_body_bytes = 4096
            }
            # Second upstream on its own process, used only by the concurrency
            # check: stalling this one must not affect the 'echo' provider.
            slow = @{
                secret = $secretName
                auth = 'bearer'
                base_url = "http://127.0.0.1:$slowPort"
                allow_methods = @('GET', 'POST')
                max_body_bytes = 4096
            }
        }
    } | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding utf8

    $echoProcess = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $echoFixture, '-Port', $echoPort
    ) -WindowStyle Hidden -PassThru -RedirectStandardOutput $echoStdout -RedirectStandardError $echoStderr
    _check "echo upstream responds" (wait_for_http -Url "http://127.0.0.1:$echoPort/ping" -Seconds $TimeoutSec) ''

    $slowProcess = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $echoFixture, '-Port', $slowPort
    ) -WindowStyle Hidden -PassThru -RedirectStandardOutput $slowStdout -RedirectStandardError $slowStderr
    _check "slow upstream responds" (wait_for_http -Url "http://127.0.0.1:$slowPort/ping" -Seconds $TimeoutSec) ''

    $proxyProcess = Start-Process powershell.exe -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $entryScript,
        'proxy', 'start', '--port', $proxyPort, '--config', $configPath
    ) -WindowStyle Hidden -PassThru -RedirectStandardOutput $proxyStdout -RedirectStandardError $proxyStderr
    _check "proxy responds" (wait_for_http -Url "http://127.0.0.1:$proxyPort/echo/ping" -Seconds $TimeoutSec) ''
    if ($script:exitCode -ne 0) { exit $script:exitCode }

    # 1. GET through the proxy: vault credential injected as Bearer.
    $getResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo/v1/models?limit=5" -UseBasicParsing -TimeoutSec 10
    _check "GET forwarded to upstream path" ($getResponse.path -eq '/v1/models') "path=$($getResponse.path)"
    _check "query string preserved" ($getResponse.query -eq '?limit=5') "query=$($getResponse.query)"
    _check "vault credential injected as Bearer" ($getResponse.headers.Authorization -eq "Bearer $sentinel") ''

    # 2. Client-supplied Authorization is stripped and replaced.
    $spoofed = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo/v1/spoof" -UseBasicParsing -TimeoutSec 10 -Headers @{ Authorization = 'Bearer client-supplied-key'; 'x-api-key' = 'client-supplied-key-2' }
    _check "client Authorization replaced by vault value" ($spoofed.headers.Authorization -eq "Bearer $sentinel") "auth=$($spoofed.headers.Authorization)"
    $spoofedHasApiKey = $null -ne ($spoofed.headers.PSObject.Properties.Match('x-api-key') | Where-Object { $_ })
    _check "client x-api-key stripped" (-not $spoofedHasApiKey) ''

    # 3. POST body + content-type + custom app header round-trip.
    $postBody = '{"model":"test","input":"hello proxy"}'
    $postResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo/v1/chat" -Method Post -Body $postBody -ContentType 'application/json' -UseBasicParsing -TimeoutSec 10 -Headers @{ 'x-custom-app' = 'e2e' }
    _check "POST body forwarded intact" ($postResponse.body -eq $postBody) "body=$($postResponse.body)"
    _check "content-type forwarded" ($postResponse.headers.'Content-Type' -like 'application/json*') ''
    _check "custom app header forwarded" ($postResponse.headers.'x-custom-app' -eq 'e2e') ''

    # 4. Unknown provider -> 404, disallowed method -> 405, oversized body -> 413.
    try { Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/nope/v1/x" -UseBasicParsing -TimeoutSec 10 | Out-Null; $status = 200 }
    catch { $status = [int]$_.Exception.Response.StatusCode }
    _check "unknown provider returns 404" ($status -eq 404) "status=$status"

    try { Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/echo/v1/x" -Method Delete -UseBasicParsing -TimeoutSec 10 | Out-Null; $status = 200 }
    catch { $status = [int]$_.Exception.Response.StatusCode }
    _check "disallowed method returns 405" ($status -eq 405) "status=$status"

    $bigBody = 'x' * 8192
    try { Invoke-WebRequest -Uri "http://127.0.0.1:$proxyPort/echo/v1/big" -Method Post -Body $bigBody -UseBasicParsing -TimeoutSec 10 | Out-Null; $status = 200 }
    catch { $status = [int]$_.Exception.Response.StatusCode }
    _check "oversized body returns 413" ($status -eq 413) "status=$status"

    # 5. Concurrency: a slow provider must not stall unrelated clients.
    # Regression guard for the serial accept loop, where every request was
    # handled inline and one slow upstream blocked the whole proxy.
    Add-Type -AssemblyName System.Net.Http
    $concurrencyClient = [System.Net.Http.HttpClient]::new()
    $concurrencyClient.Timeout = [TimeSpan]::FromSeconds(30)
    try {
        $slowTask = $concurrencyClient.GetAsync("http://127.0.0.1:$proxyPort/slow/__sleep/6000")
        Start-Sleep -Milliseconds 750   # let the slow request occupy the proxy

        $fastTimer = [System.Diagnostics.Stopwatch]::StartNew()
        $fastResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo/v1/models" -UseBasicParsing -TimeoutSec 20
        $fastTimer.Stop()

        _check "fast request not blocked by slow provider" `
            (($fastTimer.ElapsedMilliseconds -lt 2000) -and ($fastResponse.path -eq '/v1/models')) `
            "$($fastTimer.ElapsedMilliseconds)ms (serial proxy would exceed 5000ms)"

        $slowResult = $slowTask.GetAwaiter().GetResult()
        _check "slow request still completes correctly" ([int]$slowResult.StatusCode -eq 200) "status=$([int]$slowResult.StatusCode)"
        $slowResult.Dispose()
    }
    finally {
        $concurrencyClient.Dispose()
    }

    # 6. Config hot-reload. A broken edit is rejected (previous providers stay
    # active), then a valid edit that adds a provider is served without any
    # restart.
    Set-Content $configPath 'this is not json' -Encoding utf8
    Start-Sleep -Seconds 2
    $afterBroken = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo/v1/still-up" -UseBasicParsing -TimeoutSec 10
    _check "broken config edit keeps previous providers serving" ($afterBroken.path -eq '/v1/still-up') ''

    @{
        providers = @{
            echo = @{
                secret = $secretName
                auth = 'bearer'
                base_url = "http://127.0.0.1:$echoPort"
                allow_methods = @('GET', 'POST')
                max_body_bytes = 4096
            }
            slow = @{
                secret = $secretName
                auth = 'bearer'
                base_url = "http://127.0.0.1:$slowPort"
                allow_methods = @('GET', 'POST')
                max_body_bytes = 4096
            }
            echo2 = @{
                secret = $secretName
                auth = 'bearer'
                base_url = "http://127.0.0.1:$echoPort"
                allow_methods = @('GET')
            }
        }
    } | ConvertTo-Json -Depth 5 | Set-Content $configPath -Encoding utf8

    $reloadDeadline = (Get-Date).AddSeconds(10)
    $reloadOk = $false
    while ((Get-Date) -lt $reloadDeadline) {
        try {
            $reloadResponse = Invoke-RestMethod -Uri "http://127.0.0.1:$proxyPort/echo2/v1/reloaded" -UseBasicParsing -TimeoutSec 5
            if ($reloadResponse.path -eq '/v1/reloaded') { $reloadOk = $true; break }
        } catch {
            Start-Sleep -Milliseconds 300
        }
    }
    _check "provider added by hot reload is served without restart" $reloadOk ''

    # 7. The secret value never appears in proxy output.
    $proxyLogText = (Get-Content $proxyStdout -Raw -ErrorAction SilentlyContinue) + (Get-Content $proxyStderr -Raw -ErrorAction SilentlyContinue)
    _check "proxy output does not leak secret value" (-not ($proxyLogText -like "*$sentinel*")) ''
    _check "proxy output lists echo provider" ($proxyLogText -like "*echo*") ''
}
finally {
    foreach ($proc in @($proxyProcess, $echoProcess, $slowProcess)) {
        if ($proc -and -not $proc.HasExited) {
            try { Stop-Process -Id $proc.Id -Force -Confirm:$false } catch { }
        }
    }
    if ($importsOk) {
        try {
            $cleanup = remove_secret_value -Name $secretName
            if (-not $cleanup.success -and $cleanup.error.code -ne 'NOT_FOUND') {
                Write-Host "WARNING: cleanup of $secretName failed: $($cleanup.error.message)" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "WARNING: cleanup threw: $_" -ForegroundColor Yellow
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
