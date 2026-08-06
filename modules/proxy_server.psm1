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

$script:validAuthModes = @('bearer', 'x-api-key', 'x-goog-api-key')
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

function handle_proxy_request {
    param(
        $Context,
        [hashtable]$Providers,
        [scriptblock]$ReadSecret,
        $HttpClient
    )

    $request = $Context.Request
    $response = $Context.Response
    $method = $request.HttpMethod
    # NOTE: query strings are never logged — some providers put keys there.
    $logPath = $request.Url.AbsolutePath

    $route = resolve_proxy_route -Providers $Providers -Method $method -Path $request.Url.AbsolutePath -Query $request.Url.Query
    if (-not $route.success) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') $($route.error.http_status) $method $logPath ($($route.error.code))"
        write_proxy_error_response -Response $response -StatusCode $route.error.http_status -Code $route.error.code -Message $route.error.message
        return
    }

    $provider = $route.data.provider
    $secretResult = & $ReadSecret $provider.secret
    if (-not $secretResult.success) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') 502 $method $logPath (SECRET_UNAVAILABLE: $($provider.secret))"
        write_proxy_error_response -Response $response -StatusCode 502 -Code 'SECRET_UNAVAILABLE' -Message "Secret '$($provider.secret)' for provider '$($route.data.provider_name)' is not available in the vault"
        return
    }

    $authPlan = plan_auth_header -AuthMode $provider.auth
    if (-not $authPlan.success) {
        write_proxy_error_response -Response $response -StatusCode 500 -Code $authPlan.error.code -Message $authPlan.error.message
        return
    }

    $bodyResult = read_request_body_bytes -Request $request -MaxBytes $provider.max_body_bytes
    if (-not $bodyResult.success) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') 413 $method $logPath (BODY_TOO_LARGE)"
        write_proxy_error_response -Response $response -StatusCode 413 -Code $bodyResult.error.code -Message $bodyResult.error.message
        return
    }

    $upstreamRequest = [System.Net.Http.HttpRequestMessage]::new(
        [System.Net.Http.HttpMethod]::new($route.data.method),
        $route.data.upstream_url)

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

        # Inject the vault credential — the only auth that reaches the
        # provider, except on an opted-in auth_passthrough_path: there the
        # client's own Authorization (a provider-minted short-lived token)
        # goes through verbatim and the vault value stays home.
        $passthroughAuth = $null
        if (@($provider.auth_passthrough_paths).Count -gt 0) {
            $clientAuth = $request.Headers['Authorization']
            if ($clientAuth) {
                foreach ($pattern in $provider.auth_passthrough_paths) {
                    if ($route.data.upstream_path -match $pattern) { $passthroughAuth = $clientAuth; break }
                }
            }
        }
        [void]$upstreamRequest.Headers.Remove($authPlan.data.header)
        if ($passthroughAuth) {
            [void]$upstreamRequest.Headers.TryAddWithoutValidation('Authorization', $passthroughAuth)
        } else {
            [void]$upstreamRequest.Headers.TryAddWithoutValidation($authPlan.data.header, $authPlan.data.prefix + $secretResult.data)
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

            Write-Host "$(Get-Date -Format 'HH:mm:ss') $([int]$upstreamResponse.StatusCode) $method $($route.data.provider_name) $($route.data.upstream_path)"
        }
        finally {
            $upstreamResponse.Dispose()
        }
        try { $response.Close() } catch { }
    }
    catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') 502 $method $logPath (UPSTREAM_FAILED)"
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
        [string]$AdminAllowedSid = ''
    )

    Add-Type -AssemblyName System.Net.Http

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

    Write-Host "shush proxy listening on http://127.0.0.1:$Port/"
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
    Write-Host "Press Ctrl+C to stop."

    try {
        $httpAsync = $listener.BeginGetContext($null, $null)
        $pipeAsync = if ($adminEnabled) { $adminPipe.BeginWaitForConnection($null, $null) } else { $null }

        while ($listener.IsListening) {
            $handles = [System.Collections.Generic.List[System.Threading.WaitHandle]]::new()
            $handles.Add($httpAsync.AsyncWaitHandle)
            if ($adminEnabled) { $handles.Add($pipeAsync.AsyncWaitHandle) }

            [void][System.Threading.WaitHandle]::WaitAny($handles.ToArray())

            # Service every signaled handle, pipe first: WaitAny reports only the
            # lowest signaled index, so keying on its return value starves the
            # pipe whenever HTTP traffic is continuous.
            if ($adminEnabled -and $pipeAsync.IsCompleted) {
                try {
                    $adminPipe.EndWaitForConnection($pipeAsync)
                    $summary = handle_admin_connection -Pipe $adminPipe
                    Write-Host "$(Get-Date -Format 'HH:mm:ss') admin $summary"
                } catch {
                    Write-Host "$(Get-Date -Format 'HH:mm:ss') admin connection error"
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
                    handle_proxy_request -Context $context -Providers $Providers -ReadSecret $ReadSecret -HttpClient $client
                } catch {
                    try { write_proxy_error_response -Response $context.Response -StatusCode 500 -Code 'INTERNAL_ERROR' -Message 'Proxy internal error' } catch { }
                }
            }
        }
    }
    finally {
        try { $listener.Stop() } catch { }
        if ($null -ne $adminPipe) { try { $adminPipe.Dispose() } catch { } }
        $client.Dispose()
    }

    return @{ success = $true; data = $null; error = $null }
}

Export-ModuleMember -Function @(
    'get_default_providers',
    'test_provider_base_url',
    'parse_proxy_config',
    'merge_provider_maps',
    'resolve_proxy_route',
    'plan_auth_header',
    'should_forward_header',
    'read_request_body_bytes',
    'handle_proxy_request',
    'start_proxy_listener',
    'write_proxy_error_response'
)
