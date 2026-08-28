# cloud_client.psm1
# Client-side plumbing for the shush cloud tier: cloud_config.json handling,
# the `shush cloud ...` argument tokenizer, machine/admin token helpers, the
# wrangler wrapper, and the admin API client.
#
# Everything here follows the repo result contract:
#   @{ success; data; error = @{ code; message } }
# and never throws on user-input errors.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'process_runner.psm1')

# Pinned so `npx wrangler` cannot drift under the deploy flow.
$script:wrangler_version = '4.127.0'

$script:secret_name_pattern = '^[a-z][a-z0-9_]*$'
$script:machine_id_pattern = '^[a-z0-9]{4,32}$'
$script:machine_secret_pattern = '^[A-Za-z0-9_-]{16,128}$'

function new_result {
    param($Data)
    return @{ success = $true; data = $Data; error = $null }
}

function new_error {
    param([string]$Code, [string]$Message)
    return @{ success = $false; data = $null; error = @{ code = $Code; message = $Message } }
}

# ---------------------------------------------------------------------------
# cloud_config.json
# ---------------------------------------------------------------------------

function get_cloud_config_path {
    param([string]$ScriptDir)

    if ($env:SHUSH_CLOUD_CONFIG) { return $env:SHUSH_CLOUD_CONFIG }
    return (Join-Path $ScriptDir 'cloud_config.json')
}

function read_cloud_config {
    param([string]$Path)

    if (-not (Test-Path $Path)) {
        return new_error -Code 'NOT_CONFIGURED' -Message "No cloud config at '$Path'. Run: shush cloud deploy"
    }
    try {
        $parsed = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        return new_error -Code 'INVALID_CONFIG' -Message "Cloud config '$Path' is not valid JSON: $($_.Exception.Message)"
    }
    if (-not ($parsed.PSObject.Properties.Match('worker_url').Count -gt 0) -or -not $parsed.worker_url) {
        return new_error -Code 'INVALID_CONFIG' -Message "Cloud config '$Path' is missing 'worker_url'"
    }
    $workerUrl = ([string]$parsed.worker_url).TrimEnd('/')
    if ($workerUrl -notmatch '^https://[a-zA-Z0-9.-]+$' -and $workerUrl -notmatch '^http://(127\.0\.0\.1|localhost)(:\d+)?$') {
        return new_error -Code 'INVALID_CONFIG' -Message "Cloud config worker_url '$workerUrl' must be https://host (http:// allowed for localhost test harnesses)"
    }
    $accountId = ''
    if ($parsed.PSObject.Properties.Match('account_id').Count -gt 0 -and $parsed.account_id) {
        $accountId = [string]$parsed.account_id
    }
    return new_result -Data @{ worker_url = $workerUrl; account_id = $accountId }
}

function write_cloud_config {
    param([string]$Path, [hashtable]$Config)

    try {
        ($Config | ConvertTo-Json) | Set-Content -LiteralPath $Path -Encoding UTF8
        return new_result -Data $null
    } catch {
        return new_error -Code 'WRITE_FAILED' -Message "Cannot write cloud config '$Path': $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# `shush cloud ...` tokenizer
#
# The cloud family parses its own tokens: three positional levels plus a
# fixed flag set. Its flags deliberately never join secret_manager.ps1's
# global promotion loop, so a future cloud flag can never collide with a
# top-level one.
# ---------------------------------------------------------------------------

function parse_cloud_arguments {
    param([string[]]$Tokens = @())

    $positional = @()
    $flags = @{
        grant = @()
        show = $false
        probe = $false
        reset_admin = $false
        from_stdin = $false
        force = $false
        save = $false
    }

    $rest = @($Tokens | Where-Object { $null -ne $_ })
    $i = 0
    while ($i -lt $rest.Count) {
        $tok = [string]$rest[$i]
        switch -CaseSensitive -Regex ($tok) {
            # `break` on every case: PowerShell switch runs EVERY matching
            # case, so without it '--grant' would also hit the '^--' catchall.
            '^(--grant|-grant)$' {
                if ($i + 1 -ge $rest.Count) {
                    return new_error -Code 'INVALID_PARAMS' -Message '--grant requires a comma-separated provider list'
                }
                $flags.grant = @(([string]$rest[$i + 1]) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
                $i += 1
                break
            }
            '^(--show|-show)$' { $flags.show = $true; break }
            '^(--probe|-probe)$' { $flags.probe = $true; break }
            '^(--reset-admin|-reset-admin)$' { $flags.reset_admin = $true; break }
            '^(--from-stdin|-from-stdin)$' { $flags.from_stdin = $true; break }
            '^(--force|-force)$' { $flags.force = $true; break }
            '^(--save|-save)$' { $flags.save = $true; break }
            '^--' {
                return new_error -Code 'INVALID_PARAMS' -Message "Unknown cloud flag '$tok'"
            }
            default { $positional += $tok }
        }
        $i += 1
    }

    if ($positional.Count -gt 3) {
        return new_error -Code 'INVALID_PARAMS' -Message "Too many arguments: '$($positional -join ' ')'"
    }

    return new_result -Data @{ positional = $positional; flags = $flags }
}

# ---------------------------------------------------------------------------
# Tokens and hashes
# ---------------------------------------------------------------------------

function convert_to_base64url {
    param([byte[]]$Bytes)
    return [Convert]::ToBase64String($Bytes).Replace('+', '-').Replace('/', '_').TrimEnd('=')
}

function new_cloud_admin_token {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return (convert_to_base64url -Bytes $bytes)
}

# Same v1:<salt_b64url>:<sha256(salt||token) b64url> format the worker's
# verifyAdminToken expects (cloud/worker/src/auth.ts).
function get_admin_token_hash {
    param([string]$Token)

    $saltBytes = New-Object byte[] 16
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($saltBytes) } finally { $rng.Dispose() }

    $tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($Token)
    $combined = New-Object byte[] ($saltBytes.Length + $tokenBytes.Length)
    [Array]::Copy($saltBytes, 0, $combined, 0, $saltBytes.Length)
    [Array]::Copy($tokenBytes, 0, $combined, $saltBytes.Length, $tokenBytes.Length)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $digest = $sha.ComputeHash($combined) } finally { $sha.Dispose() }

    return "v1:$(convert_to_base64url -Bytes $saltBytes):$(convert_to_base64url -Bytes $digest)"
}

function format_secret_binding_name {
    # PowerShell -match is case-insensitive; the grammar is lowercase-only,
    # so -cmatch everywhere in this module.
    param([string]$Name)

    if ($Name -cnotmatch $script:secret_name_pattern) { return $null }
    return 'SK_' + $Name.ToUpperInvariant()
}

function parse_machine_token {
    param([string]$Token)

    if (-not $Token) {
        return new_error -Code 'INVALID_TOKEN' -Message 'Machine token is empty'
    }
    $parts = $Token -split '\.'
    if ($parts.Count -ne 3 -or $parts[0] -cne 'shm' -or
        $parts[1] -cnotmatch $script:machine_id_pattern -or
        $parts[2] -cnotmatch $script:machine_secret_pattern) {
        return new_error -Code 'INVALID_TOKEN' -Message 'Malformed machine token (expected shm.<id>.<secret>)'
    }
    return new_result -Data @{ id = $parts[1]; secret = $parts[2] }
}

# ---------------------------------------------------------------------------
# wrangler wrapper
#
# One choke point for every wrangler invocation so the Windows footguns are
# handled exactly once: UTF-8 stream capture (PS 5.1 pipes default to the
# OEM codepage and corrupt secrets), no `2>&1` under
# $ErrorActionPreference='Stop' (native stderr becomes a terminating
# ErrorRecord), success judged by exit code only, telemetry off.
# ---------------------------------------------------------------------------

function find_npx_or_error {
    foreach ($candidate in @('npx.cmd', 'npx')) {
        $cmd = Get-Command $candidate -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($cmd) { return new_result -Data $cmd.Source }
    }
    return new_error -Code 'NODE_MISSING' -Message 'npx not found. The cloud tier needs Node.js (https://nodejs.org); install it and retry.'
}

function invoke_wrangler {
    param(
        [string]$WorkerDir,
        [string[]]$Arguments,
        [string]$StdinText = $null,
        [int]$TimeoutSeconds = 600
    )

    $npx = find_npx_or_error
    if (-not $npx.success) { return $npx }

    $allArgs = @('--yes', "wrangler@$script:wrangler_version") + @($Arguments)

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $npx.data
    $psi.WorkingDirectory = $WorkerDir
    $psi.UseShellExecute = $false
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    # Always redirected: with no input it is closed immediately, so a
    # wrangler prompt reads EOF instead of hanging on the console.
    $psi.RedirectStandardInput = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.Arguments = (@($allArgs) | ForEach-Object { quote_native_argument -Argument $_ }) -join ' '
    $psi.Environment['CI'] = '1'
    $psi.Environment['WRANGLER_SEND_METRICS'] = 'false'
    $psi.Environment['NO_COLOR'] = '1'

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi
    try {
        [void]$process.Start()

        if ($null -ne $StdinText) {
            # Raw UTF-8 bytes on the base stream: the StreamWriter wrapper
            # cannot be re-encoded on .NET Framework and would mojibake any
            # non-ASCII secret (same failure class read_secret_from_stdin
            # fixes on the way in).
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($StdinText)
            $process.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            $process.StandardInput.BaseStream.Flush()
        }
        $process.StandardInput.Close()

        # Async reads so neither full pipe can deadlock WaitForExit.
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()

        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { }
            return new_error -Code 'WRANGLER_TIMEOUT' -Message "wrangler did not finish within $TimeoutSeconds seconds"
        }
        $process.WaitForExit()  # flush async output after the timed wait

        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()

        $payload = @{ exit_code = $process.ExitCode; stdout = $stdout; stderr = $stderr }
        if ($process.ExitCode -ne 0) {
            $firstError = (@($stderr -split "`r?`n" | Where-Object { $_ -match '\S' }) | Select-Object -First 3) -join ' / '
            return @{
                success = $false; data = $payload
                error = @{ code = 'WRANGLER_FAILED'; message = "wrangler $($Arguments -join ' ') failed (exit $($process.ExitCode)): $firstError" }
            }
        }
        return new_result -Data $payload
    } catch {
        return new_error -Code 'WRANGLER_START_FAILED' -Message "Cannot run wrangler: $($_.Exception.Message)"
    } finally {
        $process.Dispose()
    }
}

# Get-or-create by title: `wrangler kv namespace create` is not idempotent
# (a second run errors), so list first and only create on a miss.
function get_or_create_kv_namespace {
    param([string]$WorkerDir, [string]$WorkerName = 'shush-cloud', [string]$Binding = 'SHUSH_KV')

    $titles = @("$WorkerName-$Binding", $Binding)

    $found = find_kv_namespace_id -WorkerDir $WorkerDir -Titles $titles
    if (-not $found.success) { return $found }
    if ($found.data) { return new_result -Data $found.data }

    $created = invoke_wrangler -WorkerDir $WorkerDir -Arguments @('kv', 'namespace', 'create', $Binding)
    if (-not $created.success) { return $created }

    $found = find_kv_namespace_id -WorkerDir $WorkerDir -Titles $titles
    if (-not $found.success) { return $found }
    if ($found.data) { return new_result -Data $found.data }
    return new_error -Code 'KV_CREATE_FAILED' -Message 'KV namespace was created but could not be found in the namespace list'
}

function find_kv_namespace_id {
    param([string]$WorkerDir, [string[]]$Titles)

    $listed = invoke_wrangler -WorkerDir $WorkerDir -Arguments @('kv', 'namespace', 'list')
    if (-not $listed.success) { return $listed }
    try {
        # wrangler may print banner lines before the JSON; take from the
        # first '[' onward.
        $raw = [string]$listed.data.stdout
        $start = $raw.IndexOf('[')
        if ($start -lt 0) { return new_error -Code 'KV_LIST_FAILED' -Message 'kv namespace list returned no JSON array' }
        $namespaces = @($raw.Substring($start) | ConvertFrom-Json)
    } catch {
        return new_error -Code 'KV_LIST_FAILED' -Message "Cannot parse kv namespace list output: $($_.Exception.Message)"
    }
    foreach ($ns in $namespaces) {
        if ($Titles -contains [string]$ns.title) {
            return new_result -Data ([string]$ns.id)
        }
    }
    return new_result -Data $null
}

# wrangler.jsonc is kept comment-free (plain JSON in a .jsonc file) exactly
# so this round-trip works on Windows PowerShell 5.1.
function update_wrangler_kv_id {
    param([string]$Path, [string]$NamespaceId)

    try {
        $config = Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
    } catch {
        return new_error -Code 'INVALID_CONFIG' -Message "Cannot parse '$Path': $($_.Exception.Message)"
    }
    if (-not ($config.PSObject.Properties.Match('kv_namespaces').Count -gt 0) -or @($config.kv_namespaces).Count -eq 0) {
        return new_error -Code 'INVALID_CONFIG' -Message "'$Path' has no kv_namespaces entry"
    }
    $config.kv_namespaces[0].id = $NamespaceId
    try {
        ($config | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $Path -Encoding UTF8
        return new_result -Data $null
    } catch {
        return new_error -Code 'WRITE_FAILED' -Message "Cannot write '$Path': $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# Admin API client
# ---------------------------------------------------------------------------

function invoke_cloud_api {
    param(
        [string]$WorkerUrl,
        [string]$Method,
        [string]$Path,
        $Body = $null,
        [string]$AdminToken = ''
    )

    # PS 5.1 defaults to TLS 1.0 on some machines; Cloudflare requires 1.2+.
    try {
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12
    } catch { }

    $uri = $WorkerUrl.TrimEnd('/') + $Path
    $headers = @{}
    if ($AdminToken) { $headers['Authorization'] = "Bearer $AdminToken" }

    $splat = @{
        Method = $Method
        Uri = $uri
        Headers = $headers
        TimeoutSec = 60
        ErrorAction = 'Stop'
    }
    if ($null -ne $Body) {
        $splat['Body'] = ($Body | ConvertTo-Json -Depth 10)
        $splat['ContentType'] = 'application/json'
    }

    try {
        $response = Invoke-RestMethod @splat
        return new_result -Data $response
    } catch {
        $status = 0
        $code = 'API_FAILED'
        $message = $_.Exception.Message
        $errorBody = $null
        if ($_.Exception.PSObject.Properties.Match('Response').Count -gt 0 -and $null -ne $_.Exception.Response) {
            try {
                $status = [int]$_.Exception.Response.StatusCode
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = [System.IO.StreamReader]::new($stream, [System.Text.Encoding]::UTF8)
                $errorBody = $reader.ReadToEnd()
                $reader.Dispose()
            } catch { }
        }
        if ($errorBody) {
            try {
                $parsed = $errorBody | ConvertFrom-Json
                if ($parsed.PSObject.Properties.Match('error').Count -gt 0 -and $null -ne $parsed.error) {
                    $code = [string]$parsed.error.code
                    $message = [string]$parsed.error.message
                }
            } catch { }
        }
        if ($status -gt 0 -and $message -eq $_.Exception.Message) {
            $message = "HTTP $status from $uri : $message"
        }
        return @{
            success = $false; data = @{ http_status = $status }
            error = @{ code = $code; message = $message }
        }
    }
}

# ---------------------------------------------------------------------------
# `run --cloud` env planning
#
# Maps ENV_VAR=provider to the child environment: the machine token stands in
# for the API key, and the client-correct base-URL variable points at the
# worker. The variable NAME picks the client convention; the provider name
# picks the route.
# ---------------------------------------------------------------------------

function get_cloud_env_mappings {
    param(
        [string]$EnvVar,
        [string]$Provider,
        [string]$WorkerUrl,
        [string]$Token
    )

    if ($Provider -cnotmatch $script:secret_name_pattern) {
        return new_error -Code 'INVALID_ENV_MAPPING' -Message "Invalid provider name '$Provider' (lowercase letters, digits, underscores; start with a letter)"
    }

    $base = $WorkerUrl.TrimEnd('/') + '/' + $Provider
    $values = @{ $EnvVar = $Token }
    $notes = @()

    switch -CaseSensitive ($EnvVar) {
        'OPENAI_API_KEY' {
            # OpenAI SDKs expect the /v1 prefix inside the base URL.
            $values['OPENAI_BASE_URL'] = "$base/v1"
        }
        'ANTHROPIC_API_KEY' {
            $values['ANTHROPIC_BASE_URL'] = $base
        }
        'GEMINI_API_KEY' {
            # gemini-cli reads GOOGLE_GEMINI_BASE_URL and must be pinned off
            # Vertex mode; the google-genai SDK ignores env base URLs and
            # needs http_options in code instead.
            $values['GOOGLE_GEMINI_BASE_URL'] = $base
            $values['GOOGLE_GENAI_USE_VERTEXAI'] = 'false'
            $notes += "google-genai SDK users: env base URLs are ignored; pass http_options={'base_url': '$base'} to genai.Client instead."
        }
        default {
            $guess = ($EnvVar -replace '_API_KEY$', '') + '_BASE_URL'
            $notes += "No known base-URL convention for $EnvVar; if the client supports one, point it at $base (e.g. $guess)."
        }
    }

    return new_result -Data @{ values = $values; notes = $notes }
}

# Clients whose default auth path silently bypasses a base-URL override.
function get_cloud_preflight_warnings {
    param([string]$ChildCommand, [string[]]$Providers = @())

    $warnings = @()
    $child = [System.IO.Path]::GetFileNameWithoutExtension([string]$ChildCommand).ToLowerInvariant()
    if ($child -eq 'codex' -and $Providers -contains 'openai') {
        $warnings += 'codex: a ChatGPT-account login ignores OPENAI_BASE_URL and goes straight to OpenAI. Use API-key mode (preferred_auth_method = "apikey") or the proxy is bypassed.'
    }
    if ($child -eq 'claude' -and $Providers -contains 'anthropic') {
        $warnings += 'claude: a Claude subscription (OAuth) login ignores ANTHROPIC_BASE_URL. Sign in with an API key (ANTHROPIC_API_KEY) or the proxy is bypassed.'
    }
    return $warnings
}

Export-ModuleMember -Function @(
    'get_cloud_config_path',
    'read_cloud_config',
    'write_cloud_config',
    'parse_cloud_arguments',
    'convert_to_base64url',
    'new_cloud_admin_token',
    'get_admin_token_hash',
    'format_secret_binding_name',
    'parse_machine_token',
    'find_npx_or_error',
    'invoke_wrangler',
    'get_or_create_kv_namespace',
    'find_kv_namespace_id',
    'update_wrangler_kv_id',
    'invoke_cloud_api',
    'get_cloud_env_mappings',
    'get_cloud_preflight_warnings'
)
