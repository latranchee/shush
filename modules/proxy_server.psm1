# proxy_server.psm1
# Localhost credential-injecting proxy for shush.
#
# The client sends requests to http://127.0.0.1:<port>/<provider>/<path>
# addressed by PROVIDER NAME. The proxy resolves the provider's secret from
# Windows Credential Manager and injects it as the provider's auth header on
# the outbound HTTPS request. The client process never sees the key.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'admin_pipe.psm1')

$script:validAuthModes = @('bearer', 'raw', 'x-api-key', 'x-goog-api-key')
$script:defaultAllowMethods = @('GET', 'POST')
$script:allMethods = @('GET', 'POST', 'PUT', 'PATCH', 'DELETE')
$script:defaultMaxBodyBytes = 10MB

# Never forwarded from client to upstream: hop-by-hop headers plus anything
# managed by the transport itself.
$script:nonForwardableHeaders = @(
    'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
    'te', 'trailer', 'transfer-encoding', 'upgrade',
    'host', 'content-length', 'accept-encoding', 'expect'
)

# Client-supplied credential headers are always stripped so the vault value
# is the only credential that ever reaches the provider.
$script:clientAuthHeaders = @(
    'authorization', 'x-api-key', 'x-goog-api-key', 'api-key'
)

# Response headers owned by the listener transport, never copied back.
$script:nonReturnableHeaders = @(
    'transfer-encoding', 'connection', 'keep-alive', 'content-length'
)

function get_default_providers {
    return @{
        openai = @{
            secret = 'openai_api_key'
            auth = 'bearer'
            base_url = 'https://api.openai.com'
            allow_methods = @('GET', 'POST')
        }
        anthropic = @{
            secret = 'anthropic_api_key'
            auth = 'x-api-key'
            base_url = 'https://api.anthropic.com'
            allow_methods = @('GET', 'POST')
        }
        gemini = @{
            secret = 'gemini_api_key'
            auth = 'x-goog-api-key'
            base_url = 'https://generativelanguage.googleapis.com'
            allow_methods = @('GET', 'POST')
        }
    }
}

function test_provider_base_url {
    param([string]$BaseUrl)

    if (-not $BaseUrl) { return $false }
    if ($BaseUrl -match '^https://[a-zA-Z0-9.-]+(:\d+)?$') { return $true }
    # Plain http is allowed only for loopback (test harnesses).
    if ($BaseUrl -match '^http://(127\.0\.0\.1|localhost)(:\d+)?$') { return $true }
    return $false
}

function parse_proxy_config {
    param([string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_CONFIG'; message = 'Proxy config is empty' }
        }
    }

    try {
        $parsed = $Json | ConvertFrom-Json
    } catch {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_CONFIG'; message = "Proxy config is not valid JSON: $($_.Exception.Message)" }
        }
    }

    if (-not ($parsed.PSObject.Properties.Match('providers').Count -gt 0) -or $null -eq $parsed.providers) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_CONFIG'; message = "Proxy config must contain a 'providers' object" }
        }
    }

    $providers = @{}
    foreach ($prop in $parsed.providers.PSObject.Properties) {
        $providerName = $prop.Name
        $entry = $prop.Value

        if ($providerName -cnotmatch '^[a-z][a-z0-9_-]*$') {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_CONFIG'; message = "Invalid provider name '$providerName'. Use lowercase letters, digits, underscores, hyphens; start with a letter." }
            }
        }

        foreach ($required in @('secret', 'auth', 'base_url')) {
            if (-not ($entry.PSObject.Properties.Match($required).Count -gt 0) -or -not $entry.$required) {
                return @{
                    success = $false; data = $null
                    error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' is missing required field '$required'" }
                }
            }
        }

        if ([string]$entry.secret -cnotmatch '^[a-z][a-z0-9_]*$') {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid secret name '$($entry.secret)'" }
            }
        }

        if ($script:validAuthModes -cnotcontains [string]$entry.auth) {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid auth mode '$($entry.auth)'. Valid: $($script:validAuthModes -join ', ')" }
            }
        }

        $normalizedBaseUrl = ([string]$entry.base_url).TrimEnd('/')
        if (-not (test_provider_base_url -BaseUrl $normalizedBaseUrl)) {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid base_url '$($entry.base_url)'. Must be https://host (http:// allowed for 127.0.0.1/localhost only), no path." }
            }
        }

        $allowMethods = $script:defaultAllowMethods
        if ($entry.PSObject.Properties.Match('allow_methods').Count -gt 0 -and $entry.allow_methods) {
            $allowMethods = @($entry.allow_methods | ForEach-Object { ([string]$_).ToUpperInvariant() })
            foreach ($m in $allowMethods) {
                if ($script:allMethods -cnotcontains $m) {
                    return @{
                        success = $false; data = $null
                        error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid method '$m' in allow_methods" }
                    }
                }
            }
        }

        $maxBody = $script:defaultMaxBodyBytes
        if ($entry.PSObject.Properties.Match('max_body_bytes').Count -gt 0 -and $entry.max_body_bytes) {
            $maxBody = [int64]$entry.max_body_bytes
            if ($maxBody -lt 1) {
                return @{
                    success = $false; data = $null
                    error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid max_body_bytes" }
                }
            }
        }

        # Opt-in per-path regexes where the CLIENT's Authorization header is
        # forwarded untouched and the vault credential is NOT sent. For flows
        # where the provider mints its own short-lived token that the vault key
        # cannot substitute for (e.g. Cloudflare Workers asset-upload JWTs).
        $passthroughPaths = @()
        if ($entry.PSObject.Properties.Match('auth_passthrough_paths').Count -gt 0 -and $entry.auth_passthrough_paths) {
            $passthroughPaths = @($entry.auth_passthrough_paths | ForEach-Object { [string]$_ })
            foreach ($p in $passthroughPaths) {
                try { [void][regex]::new($p) } catch {
                    return @{
                        success = $false; data = $null
                        error = @{ code = 'INVALID_CONFIG'; message = "Provider '$providerName' has invalid auth_passthrough_paths regex '$p'" }
                    }
                }
            }
        }

        $providers[$providerName] = @{
            secret = [string]$entry.secret
            auth = [string]$entry.auth
            base_url = $normalizedBaseUrl
            allow_methods = $allowMethods
            max_body_bytes = $maxBody
            auth_passthrough_paths = $passthroughPaths
        }
    }

    if ($providers.Count -eq 0) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_CONFIG'; message = 'Proxy config defines no providers' }
        }
    }

    return @{ success = $true; data = $providers; error = $null }
}

function merge_provider_maps {
    param(
        [hashtable]$Defaults = @{},
        [hashtable]$Overrides = @{}
    )

    $merged = @{}
    foreach ($key in $Defaults.Keys) { $merged[$key] = $Defaults[$key] }
    foreach ($key in $Overrides.Keys) { $merged[$key] = $Overrides[$key] }
    return $merged
}

# Change stamp for hot-reload comparisons; empty string when the file is
# absent or unreadable.
function get_proxy_config_stamp {
    param([string]$Path)

    try {
        $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
        return "$($item.LastWriteTimeUtc.Ticks):$($item.Length)"
    } catch {
        return ''
    }
}

# Reads the config file, validates it, and merges it onto the given defaults.
function load_proxy_config_file {
    param(
        [string]$Path,
        [hashtable]$Defaults = @{}
    )

    try {
        $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    } catch {
        return @{
            success = $false; data = $null
            error = @{ code = 'CONFIG_READ_FAILED'; message = "Cannot read proxy config '$Path': $($_.Exception.Message)" }
        }
    }

    $parsed = parse_proxy_config -Json $json
    if (-not $parsed.success) { return $parsed }

    return @{ success = $true; data = (merge_provider_maps -Defaults $Defaults -Overrides $parsed.data); error = $null }
}

function resolve_proxy_route {
    param(
        [hashtable]$Providers,
        [string]$Method,
        [string]$Path,
        [string]$Query = ''
    )

    $trimmed = ([string]$Path).Trim('/')
    if (-not $trimmed) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_PATH'; http_status = 404; message = 'Request path must be /<provider>/<upstream-path>' }
        }
    }

    $segments = $trimmed -split '/', 2
    $providerName = $segments[0].ToLowerInvariant()
    $rest = if ($segments.Length -gt 1) { $segments[1] } else { '' }

    if (-not $Providers.ContainsKey($providerName)) {
        return @{
            success = $false; data = $null
            error = @{ code = 'PROVIDER_NOT_FOUND'; http_status = 404; message = "Unknown provider '$providerName'. Configured: $((@($Providers.Keys) | Sort-Object) -join ', ')" }
        }
    }

    $provider = $Providers[$providerName]
    $methodUpper = ([string]$Method).ToUpperInvariant()
    if (@($provider.allow_methods) -cnotcontains $methodUpper) {
        return @{
            success = $false; data = $null
            error = @{ code = 'METHOD_NOT_ALLOWED'; http_status = 405; message = "Method $methodUpper not allowed for provider '$providerName'. Allowed: $($provider.allow_methods -join ', ')" }
        }
    }

    $upstreamPath = '/' + $rest
    $upstreamUrl = $provider.base_url + $upstreamPath + [string]$Query

    return @{
        success = $true
        data = @{
            provider_name = $providerName
            provider = $provider
            upstream_path = $upstreamPath
            upstream_url = $upstreamUrl
            method = $methodUpper
        }
        error = $null
    }
}

function plan_auth_header {
    param([string]$AuthMode)

    switch ($AuthMode) {
        'bearer' { return @{ success = $true; data = @{ header = 'Authorization'; prefix = 'Bearer ' }; error = $null } }
        # 'raw' is for providers that expect the bare key in Authorization
        # with no scheme prefix (e.g. OpenPhone/Quo).
        'raw' { return @{ success = $true; data = @{ header = 'Authorization'; prefix = '' }; error = $null } }
        'x-api-key' { return @{ success = $true; data = @{ header = 'x-api-key'; prefix = '' }; error = $null } }
        'x-goog-api-key' { return @{ success = $true; data = @{ header = 'x-goog-api-key'; prefix = '' }; error = $null } }
        default {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_AUTH_MODE'; message = "Unknown auth mode '$AuthMode'" }
            }
        }
    }
}

function should_forward_header {
    param([string]$Name)

    $lower = ([string]$Name).ToLowerInvariant()
    if ($script:nonForwardableHeaders -contains $lower) { return $false }
    if ($script:clientAuthHeaders -contains $lower) { return $false }
    return $true
}

# --- side-effect layer below: HTTP listener + upstream forwarding ---

# Request handling runs on worker runspaces, so Write-Host is not an option
# (its output would be swallowed by the worker's pipeline instead of reaching
# the daemon log). Console.Out is a synchronized writer shared process-wide,
# so a single WriteLine from any thread lands intact on stdout.
function write_proxy_log {
    param([string]$Message)

    try { [Console]::Out.WriteLine("$(Get-Date -Format 'HH:mm:ss') $Message") } catch { }
}

function write_proxy_error_response {
    param($Response, [int]$StatusCode, [string]$Code, [string]$Message)

    try {
        $Response.StatusCode = $StatusCode
        $Response.ContentType = 'application/json'
        $body = [System.Text.Encoding]::UTF8.GetBytes((@{ error = @{ code = $Code; message = $Message } } | ConvertTo-Json -Compress))
        $Response.ContentLength64 = $body.Length
        $Response.OutputStream.Write($body, 0, $body.Length)
    } catch { }
    finally {
        try { $Response.Close() } catch { }
    }
}

function read_request_body_bytes {
    param($Request, [int64]$MaxBytes)

    if (-not $Request.HasEntityBody) {
        return @{ success = $true; data = [byte[]]@(); error = $null }
    }

    $buffer = New-Object byte[] 8192
    $memory = [System.IO.MemoryStream]::new()
    try {
        while ($true) {
            $read = $Request.InputStream.Read($buffer, 0, $buffer.Length)
            if ($read -le 0) { break }
            $memory.Write($buffer, 0, $read)
            if ($memory.Length -gt $MaxBytes) {
                return @{
                    success = $false; data = $null
                    error = @{ code = 'BODY_TOO_LARGE'; http_status = 413; message = "Request body exceeds limit of $MaxBytes bytes" }
                }
            }
        }
        return @{ success = $true; data = $memory.ToArray(); error = $null }
    }
    finally {
        $memory.Dispose()
    }
}

# Main-loop half of request handling: routing (pure) plus the vault read (a
# local CredRead, microseconds). Everything here is non-blocking by design.
# The blocking work - draining the client body, the upstream call, relaying
# the response - lives in invoke_proxy_exchange and runs on a worker runspace,
# so one slow provider cannot stall every other client.
#
# NOTE: query strings are never logged - some providers put keys there.
function prepare_proxy_request {
    param(
        [hashtable]$Providers,
        [string]$Method,
        [string]$Path,
        [string]$Query = '',
        [scriptblock]$ReadSecret
    )

    $route = resolve_proxy_route -Providers $Providers -Method $Method -Path $Path -Query $Query
    if (-not $route.success) { return $route }

    $provider = $route.data.provider
    $secretResult = & $ReadSecret $provider.secret
    if (-not $secretResult.success) {
        return @{
            success = $false; data = $null
            error = @{
                code = 'SECRET_UNAVAILABLE'; http_status = 502
                message = "Secret '$($provider.secret)' for provider '$($route.data.provider_name)' is not available in the vault"
                log_detail = "SECRET_UNAVAILABLE: $($provider.secret)"
            }
        }
    }

    $authPlan = plan_auth_header -AuthMode $provider.auth
    if (-not $authPlan.success) {
        return @{
            success = $false; data = $null
            error = @{ code = $authPlan.error.code; http_status = 500; message = $authPlan.error.message }
        }
    }

    return @{
        success = $true
        data = @{
            route = $route.data
            auth = $authPlan.data
            secret_value = $secretResult.data
        }
        error = $null
    }
}

# Worker half: runs on a pooled runspace. Owns the response object from here
# on and must always close it, or the client hangs until its own timeout.
function invoke_proxy_exchange {
    param(
        $Context,
        [hashtable]$Plan,
        $HttpClient
    )

    $started = [System.Diagnostics.Stopwatch]::StartNew()
    $request = $Context.Request
    $response = $Context.Response
    $route = $Plan.route
    $provider = $route.provider
    $authPlan = $Plan.auth
    $method = $route.method
    $logPath = $request.Url.AbsolutePath

    $bodyResult = read_request_body_bytes -Request $request -MaxBytes $provider.max_body_bytes
    if (-not $bodyResult.success) {
        write_proxy_log "413 $method $logPath (BODY_TOO_LARGE) $($started.ElapsedMilliseconds)ms"
        write_proxy_error_response -Response $response -StatusCode 413 -Code $bodyResult.error.code -Message $bodyResult.error.message
        return
    }

    $upstreamRequest = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($route.method),
        $route.upstream_url)

    try {
        if ($bodyResult.data.Length -gt 0) {
            $content = [System.Net.Http.ByteArrayContent]::new($bodyResult.data)
            if ($request.ContentType) {
                [void]$content.Headers.TryAddWithoutValidation('Content-Type', $request.ContentType)
            }
            $upstreamRequest.Content = $content
        }

        foreach ($headerName in $request.Headers.AllKeys) {
            if (-not (should_forward_header -Name $headerName)) { continue }
            $headerValue = $request.Headers[$headerName]
            if ($headerName -match '^(?i)content-') {
                if ($null -ne $upstreamRequest.Content -and $headerName -notmatch '^(?i)content-type$') {
                    [void]$upstreamRequest.Content.Headers.TryAddWithoutValidation($headerName, $headerValue)
                }
            } else {
                [void]$upstreamRequest.Headers.TryAddWithoutValidation($headerName, $headerValue)
            }
        }

        # Inject the vault credential - the only auth that reaches the
        # provider, except on an opted-in auth_passthrough_path: there the
        # client's own Authorization (a provider-minted short-lived token)
        # goes through verbatim and the vault value stays home.
        $passthroughAuth = $null
        if (@($provider.auth_passthrough_paths).Count -gt 0) {
            $clientAuth = $request.Headers['Authorization']
            if ($clientAuth) {
                foreach ($pattern in $provider.auth_passthrough_paths) {
                    if ($route.upstream_path -match $pattern) { $passthroughAuth = $clientAuth; break }
                }
            }
        }
        [void]$upstreamRequest.Headers.Remove($authPlan.header)
        if ($passthroughAuth) {
            [void]$upstreamRequest.Headers.TryAddWithoutValidation('Authorization', $passthroughAuth)
        } else {
            [void]$upstreamRequest.Headers.TryAddWithoutValidation($authPlan.header, $authPlan.prefix + $Plan.secret_value)
        }

        $upstreamResponse = $HttpClient.SendAsync(
            $upstreamRequest,
            [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead).GetAwaiter().GetResult()

        try {
            $response.StatusCode = [int]$upstreamResponse.StatusCode

            $allHeaders = @()
            $allHeaders += @($upstreamResponse.Headers)
            $allHeaders += @($upstreamResponse.Content.Headers)
            $hasContentLength = $false
            foreach ($pair in $allHeaders) {
                $lower = $pair.Key.ToLowerInvariant()
                if ($script:nonReturnableHeaders -contains $lower) {
                    if ($lower -eq 'content-length') { $hasContentLength = $true }
                    continue
                }
                foreach ($v in $pair.Value) {
                    try { $response.Headers.Add($pair.Key, $v) } catch { }
                }
            }

            if ($hasContentLength -and $null -ne $upstreamResponse.Content.Headers.ContentLength) {
                $response.ContentLength64 = $upstreamResponse.Content.Headers.ContentLength
            } else {
                $response.SendChunked = $true
            }

            # Manual chunked copy with flush so SSE/streaming responses are
            # relayed as they arrive instead of buffered to completion.
            $upstreamStream = $upstreamResponse.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $copyBuffer = New-Object byte[] 8192
            while ($true) {
                $read = $upstreamStream.Read($copyBuffer, 0, $copyBuffer.Length)
                if ($read -le 0) { break }
                $response.OutputStream.Write($copyBuffer, 0, $read)
                $response.OutputStream.Flush()
            }

            write_proxy_log "$([int]$upstreamResponse.StatusCode) $method $($route.provider_name) $($route.upstream_path) $($started.ElapsedMilliseconds)ms"
        }
        finally {
            $upstreamResponse.Dispose()
        }
        try { $response.Close() } catch { }
    }
    catch {
        write_proxy_log "502 $method $logPath (UPSTREAM_FAILED) $($started.ElapsedMilliseconds)ms"
        write_proxy_error_response -Response $response -StatusCode 502 -Code 'UPSTREAM_FAILED' -Message "Upstream request failed: $($_.Exception.Message)"
    }
    finally {
        $upstreamRequest.Dispose()
    }
}

function start_proxy_listener {
    param(
        [int]$Port,
        [hashtable]$Providers,
        [scriptblock]$ReadSecret,
        [scriptblock]$CheckSecret = $null,
        [string]$AdminPipeName = '',
        [string]$AdminAllowedSid = '',
        [int]$MaxConcurrency = 16,
        [string]$ConfigPath = '',
        [hashtable]$DefaultProviders = @{}
    )

    Add-Type -AssemblyName System.Net.Http

    if ($MaxConcurrency -lt 1) { $MaxConcurrency = 1 }

    # .NET Framework caps outbound connections per endpoint at 2 by default,
    # which would re-serialize upstream calls no matter how many workers run.
    $connectionLimit = $MaxConcurrency * 2
    if ([System.Net.ServicePointManager]::DefaultConnectionLimit -lt $connectionLimit) {
        [System.Net.ServicePointManager]::DefaultConnectionLimit = $connectionLimit
    }

    $listener = [System.Net.HttpListener]::new()
    # Loopback only, by design. Never bind a routable interface.
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")
    try {
        $listener.Start()
    } catch {
        return @{
            success = $false; data = $null
            error = @{ code = 'BIND_FAILED'; message = "Cannot listen on http://127.0.0.1:$Port/ : $($_.Exception.Message)" }
        }
    }

    $adminEnabled = -not [string]::IsNullOrEmpty($AdminPipeName)
    $adminPipe = $null
    if ($adminEnabled) {
        if ([string]::IsNullOrEmpty($AdminAllowedSid)) {
            try { $listener.Stop() } catch { }
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_PARAMS'; message = 'Admin pipe requires an allowed client SID' }
            }
        }
        $pipeResult = new_admin_pipe_server -PipeName $AdminPipeName -AllowedSid $AdminAllowedSid
        if (-not $pipeResult.success) {
            try { $listener.Stop() } catch { }
            return $pipeResult
        }
        $adminPipe = $pipeResult.data
    }

    $client = [System.Net.Http.HttpClient]::new()
    $client.Timeout = [TimeSpan]::FromSeconds(300)

    # Worker pool. Requests are handled off the accept loop so a slow provider
    # cannot block unrelated clients; the pool only needs this module, because
    # the vault read already happened on the main loop and the resolved value
    # is passed in as an argument.
    # No PSHost is attached on purpose: workers log through write_proxy_log
    # (Console.Out), so they never touch the console host from a background
    # thread.
    $initialState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $initialState.ImportPSModule(@((Join-Path $PSScriptRoot 'proxy_server.psm1')))
    $pool = [runspacefactory]::CreateRunspacePool($initialState)
    [void]$pool.SetMinRunspaces(1)
    [void]$pool.SetMaxRunspaces($MaxConcurrency)
    $pool.Open()

    $worker = {
        param($Context, $Plan, $HttpClient)
        Add-Type -AssemblyName System.Net.Http
        try {
            invoke_proxy_exchange -Context $Context -Plan $Plan -HttpClient $HttpClient
        } catch {
            try {
                write_proxy_error_response -Response $Context.Response -StatusCode 500 `
                    -Code 'INTERNAL_ERROR' -Message 'Proxy internal error'
            } catch { }
        }
    }

    # Accepted but not yet finished. Bounded so a runaway client queues up
    # memory instead of unbounded HttpListenerContexts.
    $inflight = [System.Collections.Generic.List[object]]::new()
    $maxQueued = $MaxConcurrency * 8

    Write-Host "shush proxy listening on http://127.0.0.1:$Port/ (up to $MaxConcurrency concurrent requests)"
    Write-Host "Routes: http://127.0.0.1:$Port/<provider>/<upstream-path>"
    foreach ($providerName in (@($Providers.Keys) | Sort-Object)) {
        $provider = $Providers[$providerName]
        $secretState = ''
        if ($null -ne $CheckSecret) {
            $exists = & $CheckSecret $provider.secret
            $secretState = if ($exists) { '[secret OK]' } else { '[secret MISSING]' }
        }
        Write-Host ("  {0,-12} -> {1}  (secret: {2}, auth: {3}) {4}" -f $providerName, $provider.base_url, $provider.secret, $provider.auth, $secretState)
    }
    if ($adminEnabled) {
        Write-Host "Admin pipe: \\.\pipe\$AdminPipeName (write-only; client SID $AdminAllowedSid)"
    }
    $hotReload = -not [string]::IsNullOrEmpty($ConfigPath)
    $configStamp = if ($hotReload) { get_proxy_config_stamp -Path $ConfigPath } else { '' }
    if ($hotReload) {
        Write-Host "Hot-reload: watching $ConfigPath (edits apply within ~1s; invalid edits are ignored)"
    }
    Write-Host "Press Ctrl+C to stop."

    try {
        $httpAsync = $listener.BeginGetContext($null, $null)
        $pipeAsync = if ($adminEnabled) { $adminPipe.BeginWaitForConnection($null, $null) } else { $null }

        while ($listener.IsListening) {
            $handles = [System.Collections.Generic.List[System.Threading.WaitHandle]]::new()
            $handles.Add($httpAsync.AsyncWaitHandle)
            if ($adminEnabled) { $handles.Add($pipeAsync.AsyncWaitHandle) }

            # Bounded wait: workers finish on their own threads, so the loop
            # needs a periodic tick to reap them even when no new traffic
            # arrives. Their handles are deliberately not in the wait set -
            # WaitAny tops out at 64 handles.
            [void][System.Threading.WaitHandle]::WaitAny($handles.ToArray(), 1000)

            # Config hot-reload: a cheap stamp check at most once per loop
            # tick. A bad or half-written file never takes down the daemon -
            # the previous provider set stays active and the rejection is
            # logged; the editor's final save changes the stamp again and
            # triggers a retry. Safe against workers: $Providers is only read
            # on this thread (prepare_proxy_request), workers receive a
            # resolved plan by value.
            if ($hotReload) {
                $stamp = get_proxy_config_stamp -Path $ConfigPath
                if ($stamp -ne $configStamp) {
                    $configStamp = $stamp
                    if (-not $stamp) {
                        write_proxy_log "config $ConfigPath removed; keeping current providers"
                    } else {
                        $reloaded = load_proxy_config_file -Path $ConfigPath -Defaults $DefaultProviders
                        if ($reloaded.success) {
                            $Providers = $reloaded.data
                            write_proxy_log "config reloaded: $((@($Providers.Keys) | Sort-Object) -join ', ')"
                        } else {
                            write_proxy_log "config reload rejected (keeping current providers): $($reloaded.error.message)"
                        }
                    }
                }
            }

            for ($i = $inflight.Count - 1; $i -ge 0; $i--) {
                $job = $inflight[$i]
                if ($job.handle.IsCompleted) {
                    try { [void]$job.shell.EndInvoke($job.handle) } catch { }
                    try { $job.shell.Dispose() } catch { }
                    $inflight.RemoveAt($i)
                }
            }

            # Service every signaled handle, pipe first: WaitAny reports only the
            # lowest signaled index, so keying on its return value starves the
            # pipe whenever HTTP traffic is continuous.
            if ($adminEnabled -and $pipeAsync.IsCompleted) {
                try {
                    $adminPipe.EndWaitForConnection($pipeAsync)
                    $summary = handle_admin_connection -Pipe $adminPipe
                    write_proxy_log "admin $summary"
                } catch {
                    write_proxy_log "admin connection error"
                }
                try { $adminPipe.Disconnect() } catch { }
                try {
                    $pipeAsync = $adminPipe.BeginWaitForConnection($null, $null)
                } catch {
                    # Pipe instance broke; recreate it.
                    try { $adminPipe.Dispose() } catch { }
                    $pipeResult = new_admin_pipe_server -PipeName $AdminPipeName -AllowedSid $AdminAllowedSid
                    if ($pipeResult.success) {
                        $adminPipe = $pipeResult.data
                        $pipeAsync = $adminPipe.BeginWaitForConnection($null, $null)
                    } else {
                        Write-Host "WARNING: admin pipe lost and could not be recreated: $($pipeResult.error.message)"
                        $adminEnabled = $false
                        $pipeAsync = $null
                    }
                }
            }
            if ($httpAsync.IsCompleted) {
                $context = $listener.EndGetContext($httpAsync)
                $httpAsync = $listener.BeginGetContext($null, $null)
                try {
                    if ($inflight.Count -ge $maxQueued) {
                        write_proxy_log "503 $($context.Request.HttpMethod) $($context.Request.Url.AbsolutePath) (OVERLOADED: $($inflight.Count) in flight)"
                        write_proxy_error_response -Response $context.Response -StatusCode 503 `
                            -Code 'OVERLOADED' -Message "Proxy has $($inflight.Count) requests in flight; retry shortly"
                    } else {
                        # Routing and the vault read stay on this thread (both
                        # are microseconds); only the blocking exchange is
                        # handed to a worker.
                        $prepared = prepare_proxy_request -Providers $Providers `
                            -Method $context.Request.HttpMethod `
                            -Path $context.Request.Url.AbsolutePath `
                            -Query $context.Request.Url.Query `
                            -ReadSecret $ReadSecret

                        if (-not $prepared.success) {
                            # Strict mode turns a missing key into a throw, so
                            # probe rather than dereference: routing errors
                            # carry no log_detail.
                            $detail = $prepared.error.code
                            if ($prepared.error.ContainsKey('log_detail')) { $detail = $prepared.error.log_detail }
                            write_proxy_log "$($prepared.error.http_status) $($context.Request.HttpMethod) $($context.Request.Url.AbsolutePath) ($detail)"
                            write_proxy_error_response -Response $context.Response `
                                -StatusCode $prepared.error.http_status -Code $prepared.error.code -Message $prepared.error.message
                        } else {
                            $shell = [powershell]::Create()
                            $shell.RunspacePool = $pool
                            [void]$shell.AddScript($worker).AddArgument($context).AddArgument($prepared.data).AddArgument($client)
                            $inflight.Add(@{ shell = $shell; handle = $shell.BeginInvoke() })
                        }
                    }
                } catch {
                    try { write_proxy_error_response -Response $context.Response -StatusCode 500 -Code 'INTERNAL_ERROR' -Message 'Proxy internal error' } catch { }
                }
            }
        }
    }
    finally {
        try { $listener.Stop() } catch { }
        if ($null -ne $adminPipe) { try { $adminPipe.Dispose() } catch { } }
        foreach ($job in $inflight) {
            try { [void]$job.shell.EndInvoke($job.handle) } catch { }
            try { $job.shell.Dispose() } catch { }
        }
        try { $pool.Close(); $pool.Dispose() } catch { }
        $client.Dispose()
    }

    return @{ success = $true; data = $null; error = $null }
}

Export-ModuleMember -Function @(
    'get_default_providers',
    'test_provider_base_url',
    'parse_proxy_config',
    'merge_provider_maps',
    'get_proxy_config_stamp',
    'load_proxy_config_file',
    'resolve_proxy_route',
    'plan_auth_header',
    'should_forward_header',
    'read_request_body_bytes',
    'prepare_proxy_request',
    'invoke_proxy_exchange',
    'start_proxy_listener',
    'write_proxy_error_response',
    'write_proxy_log'
)
