param(
    [Parameter(Position=0)]
    [string]$command,

    [Parameter(Position=1)]
    [string]$name,

    [Alias('from-stdin')]
    [switch]$from_stdin,

    [switch]$force,

    [Alias('if-exists')]
    [switch]$if_exists,

    [Alias('env')]
    [string[]]$secret_env,

    [Alias('env-optional')]
    [string[]]$secret_env_optional,

    [int]$port = 8765,

    [string]$config,

    [switch]$local,

    [Alias('admin-pipe')]
    [string]$admin_pipe,

    [Alias('allow-sid')]
    [string]$allow_sid,

    [Parameter(ValueFromRemainingArguments=$true)]
    [string[]]$arguments
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Post-binding fixup. PowerShell parameter aliases don't match GNU
# `--double-dash` literals, so any such flags fall through into the
# ValueFromRemainingArguments bucket — promote them back into the
# corresponding params here so `--force`/`--from-stdin`/etc. work the
# same as their single-dash forms.
if ($null -ne $arguments) {
    $tail = @()
    $rest = @($arguments)
    $i = 0
    while ($i -lt $rest.Count) {
        $tok = $rest[$i]
        $consumed = $true
        switch -CaseSensitive -Regex ($tok) {
            '^--from-stdin$' { $from_stdin = $true }
            '^--force$' { $force = $true }
            '^--if-exists$' { $if_exists = $true }
            '^--env$' {
                if ($i + 1 -lt $rest.Count) {
                    $current = if ($null -ne $secret_env) { @($secret_env) } else { @() }
                    $secret_env = $current + @($rest[$i + 1])
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--env-optional$' {
                if ($i + 1 -lt $rest.Count) {
                    $current = if ($null -ne $secret_env_optional) { @($secret_env_optional) } else { @() }
                    $secret_env_optional = $current + @($rest[$i + 1])
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--port$' {
                if ($i + 1 -lt $rest.Count) {
                    $port = [int]$rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--config$' {
                if ($i + 1 -lt $rest.Count) {
                    $config = $rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--local$' { $local = $true }
            '^--admin-pipe$' {
                if ($i + 1 -lt $rest.Count) {
                    $admin_pipe = $rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--allow-sid$' {
                if ($i + 1 -lt $rest.Count) {
                    $allow_sid = $rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            default { $consumed = $false; $tail += $tok }
        }
        $i += 1
    }
    $arguments = $tail
}

$scriptDir = $PSScriptRoot
$moduleDir = Join-Path $scriptDir 'modules'

Import-Module (Join-Path $moduleDir 'credential_store.psm1') -Force
Import-Module (Join-Path $moduleDir 'process_runner.psm1') -Force
Import-Module (Join-Path $moduleDir 'admin_pipe.psm1') -Force
Import-Module (Join-Path $moduleDir 'proxy_server.psm1') -Force

# Service mode: when service_config.json exists (written by
# install_proxy_service.ps1), secrets live in the service account's vault
# and management commands travel over the daemon's admin pipe instead of
# touching the local vault. --local forces local-vault behavior.
# SHUSH_SERVICE_CONFIG overrides the config path (used by tests).
$serviceConfigPath = if ($env:SHUSH_SERVICE_CONFIG) { $env:SHUSH_SERVICE_CONFIG } else { Join-Path $scriptDir 'service_config.json' }
$script:serviceConfig = $null
if (Test-Path $serviceConfigPath) {
    try {
        $script:serviceConfig = Get-Content $serviceConfigPath -Raw | ConvertFrom-Json
    } catch {
        Write-Host "WARNING: service_config.json is unreadable; falling back to local vault." -ForegroundColor Yellow
    }
}

function use_service_pipe {
    return ($null -ne $script:serviceConfig) -and (-not $local)
}

function get_service_pipe_name {
    return [string]$script:serviceConfig.pipe_name
}

function show_usage {
    Write-Host "Usage:"
    Write-Host "  .\secret_manager.ps1 set <name> [--from-stdin] [--force]"
    Write-Host "  .\secret_manager.ps1 create <name> <value> [--force]"
    Write-Host "  .\secret_manager.ps1 list"
    Write-Host "  .\secret_manager.ps1 exists <name>"
    Write-Host "  .\secret_manager.ps1 delete <name> [--if-exists]"
    Write-Host "  .\secret_manager.ps1 run <command> [args...] --env ENV_VAR=secret_name [--env-optional ENV_VAR=secret_name]"
    Write-Host "  .\secret_manager.ps1 proxy start [--port 8765] [--config proxy.json]"
    Write-Host ""
    Write-Host "  set             prompts securely (or reads a pipe with --from-stdin)."
    Write-Host "  create          one-liner: takes the value from the command line."
    Write-Host "                  Convenient, but the value is visible in shell history"
    Write-Host "                  and process listings; prefer 'set' for interactive use."
    Write-Host "  --env           required mapping; missing secret aborts before launch."
    Write-Host "  --env-optional  best-effort mapping; missing secret logs a warning"
    Write-Host "                  to stderr and the child launches with that env var unset."
    Write-Host "  --if-exists     for delete: exit 0 even when the secret is not present."
    Write-Host "  --local         force local-vault behavior in service mode (see"
    Write-Host "                  docs/service_mode.md; no effect otherwise)."
    Write-Host "  proxy start     localhost credential-injecting proxy: clients call"
    Write-Host "                  http://127.0.0.1:<port>/<provider>/<path> and the vault"
    Write-Host "                  key is injected upstream; the client never sees it."
    Write-Host "                  Built-in providers: openai, anthropic, gemini."
    Write-Host "                  Optional proxy.json (next to this script) adds/overrides"
    Write-Host "                  providers; see docs/proxy.md."
}

function read_secret_from_secure_prompt {
    param([string]$Name)

    $secure = Read-Host "Secret value for $Name" -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    }
    finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }
}

function read_secret_from_stdin {
    if (-not [Console]::IsInputRedirected) {
        Write-Host "ERROR: --from-stdin requires redirected stdin (pipe a value into this command)." -ForegroundColor Red
        exit 1
    }

    # Force UTF-8 so non-ASCII secrets and UTF-8 BOM-prefixed input round-trip
    # correctly. The default Console.InputEncoding is the OEM codepage on
    # Windows, which mojibakes anything outside the local 8-bit set.
    try { [Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false) } catch { }

    $value = [Console]::In.ReadToEnd()

    # Strip a single UTF-8 BOM if present.
    if ($value.Length -gt 0 -and [int]$value[0] -eq 0xFEFF) {
        $value = $value.Substring(1)
    }

    # Strip exactly one trailing newline produced by the shell pipeline
    # (\r\n or \n). Secrets ending in CR/LF beyond that are preserved.
    if ($value.EndsWith("`r`n")) {
        $value = $value.Substring(0, $value.Length - 2)
    } elseif ($value.EndsWith("`n")) {
        $value = $value.Substring(0, $value.Length - 1)
    }

    return $value
}

function assert_valid_secret_name_or_exit {
    if (-not $name) {
        Write-Host "ERROR: Missing secret name" -ForegroundColor Red
        exit 1
    }

    if (-not (test_secret_name -Name $name)) {
        Write-Host "ERROR: Invalid secret name '$name'. Use lowercase letters, digits, and underscores; start with a lowercase letter." -ForegroundColor Red
        exit 1
    }
}

# Existence pre-check (without --force) BEFORE the value is acquired, so a
# typed value is never discarded. With --force, we always overwrite.
function assert_secret_slot_available_or_exit {
    if ($force) { return }

    $existsResult = if (use_service_pipe) {
        send_admin_request -PipeName (get_service_pipe_name) -Request @{ op = 'exists'; name = $name }
    } else {
        query_secret_exists -Name $name
    }

    if (-not $existsResult.success) {
        Write-Host "ERROR: $($existsResult.error.message)" -ForegroundColor Red
        Write-Host "       Use --force to overwrite anyway." -ForegroundColor Yellow
        exit 1
    }
    if ($existsResult.data.exists) {
        Write-Host "ERROR: Secret already exists: $name. Use --force to overwrite." -ForegroundColor Red
        exit 1
    }
}

function store_secret_and_report {
    param([string]$Value)

    if ([string]::IsNullOrEmpty($Value)) {
        Write-Host "ERROR: Secret value is empty. Refusing to store empty secret for '$name'." -ForegroundColor Red
        exit 1
    }

    $result = if (use_service_pipe) {
        send_admin_request -PipeName (get_service_pipe_name) -Request @{ op = 'create'; name = $name; value = $Value; force = [bool]$force }
    } else {
        set_secret_value -Name $name -Value $Value -Force:$force
    }

    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }

    if ($result.data -and $result.data.PSObject.Properties.Match('was_overwritten') -and $result.data.was_overwritten) {
        Write-Host "Updated existing secret: $name"
    } else {
        Write-Host "Stored new secret: $name"
    }
}

function invoke_set_command {
    assert_valid_secret_name_or_exit
    assert_secret_slot_available_or_exit

    $value = if ($from_stdin) {
        read_secret_from_stdin
    } else {
        read_secret_from_secure_prompt -Name $name
    }

    store_secret_and_report -Value $value
}

function invoke_create_command {
    assert_valid_secret_name_or_exit

    $rest = @($arguments | Where-Object { $null -ne $_ })
    if ($rest.Count -lt 1) {
        Write-Host "ERROR: Missing secret value. Usage: create <name> <value> [--force]" -ForegroundColor Red
        exit 1
    }
    if ($rest.Count -gt 1) {
        Write-Host "ERROR: Too many arguments for create. Quote values that contain spaces." -ForegroundColor Red
        exit 1
    }

    assert_secret_slot_available_or_exit
    store_secret_and_report -Value ([string]$rest[0])
}

function invoke_list_command {
    $result = if (use_service_pipe) {
        send_admin_request -PipeName (get_service_pipe_name) -Request @{ op = 'list' }
    } else {
        get_secret_names
    }
    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }
    foreach ($secretName in @($result.data)) {
        Write-Host $secretName
    }
}

function invoke_delete_command {
    if (-not $name) {
        Write-Host "ERROR: Missing secret name" -ForegroundColor Red
        exit 1
    }

    if (-not (test_secret_name -Name $name)) {
        Write-Host "ERROR: Invalid secret name '$name'. Use lowercase letters, digits, and underscores; start with a lowercase letter." -ForegroundColor Red
        exit 1
    }

    $result = if (use_service_pipe) {
        send_admin_request -PipeName (get_service_pipe_name) -Request @{ op = 'delete'; name = $name }
    } else {
        remove_secret_value -Name $name
    }
    if (-not $result.success) {
        if ($if_exists -and $result.error.code -eq 'NOT_FOUND') {
            Write-Host "Secret not present (idempotent delete): $name"
            exit 0
        }
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }

    Write-Host "Deleted secret: $name"
}

function invoke_exists_command {
    if (-not $name) {
        Write-Host "ERROR: Missing secret name" -ForegroundColor Red
        exit 1
    }

    if (-not (test_secret_name -Name $name)) {
        Write-Host "ERROR: Invalid secret name '$name'. Use lowercase letters, digits, and underscores; start with a lowercase letter." -ForegroundColor Red
        exit 1
    }

    $result = if (use_service_pipe) {
        send_admin_request -PipeName (get_service_pipe_name) -Request @{ op = 'exists'; name = $name }
    } else {
        query_secret_exists -Name $name
    }
    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }
    if ($result.data.exists) {
        Write-Host "Secret exists: $name"
        exit 0
    }

    Write-Host "Secret not found: $name" -ForegroundColor Red
    exit 1
}

function invoke_run_command {
    if (-not $name) {
        Write-Host "ERROR: Missing command to run" -ForegroundColor Red
        exit 1
    }

    $mappings = @($secret_env | Where-Object { $_ })
    $optionalMappings = @($secret_env_optional | Where-Object { $_ })
    if ($mappings.Count -eq 0 -and $optionalMappings.Count -eq 0) {
        Write-Host "ERROR: At least one --env or --env-optional ENV_VAR=secret_name mapping is required" -ForegroundColor Red
        exit 1
    }

    $resolved = resolve_secret_env_mappings `
        -Mappings $mappings `
        -OptionalMappings $optionalMappings `
        -ReadSecret {
            param($secretName)
            get_secret_value -Name $secretName
        }

    if (-not $resolved.success) {
        Write-Host "ERROR: $($resolved.error.message)" -ForegroundColor Red
        if ((use_service_pipe) -and $resolved.error.code -eq 'NOT_FOUND') {
            Write-Host "       Service mode: secrets in the service vault cannot be injected as env vars." -ForegroundColor Yellow
            Write-Host "       Use the proxy (http://127.0.0.1:$($script:serviceConfig.port)/<provider>/...) instead," -ForegroundColor Yellow
            Write-Host "       or store a local copy with: secret_manager.ps1 set <name> --local" -ForegroundColor Yellow
        }
        exit 1
    }

    foreach ($missing in @($resolved.missing_optional)) {
        [Console]::Error.WriteLine("WARNING: optional secret '$($missing.secret_name)' not found; child env $($missing.env_var) will be unset")
    }

    $result = invoke_secret_process -FilePath $name -ArgumentList @($arguments) -Environment $resolved.data -WorkingDirectory (Get-Location).Path
    if (-not $result.success -and $result.error -and $result.error.code -eq 'PROCESS_START_FAILED') {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
    }
    exit ([int]$result.data.exit_code)
}

function invoke_proxy_command {
    if ($name -ne 'start') {
        Write-Host "ERROR: Unknown proxy subcommand '$name'. Usage: proxy start [--port 8765] [--config proxy.json]" -ForegroundColor Red
        exit 1
    }

    $providers = get_default_providers

    $configPath = $config
    if (-not $configPath) {
        $defaultConfig = Join-Path $scriptDir 'proxy.json'
        if (Test-Path $defaultConfig) { $configPath = $defaultConfig }
    }

    if ($configPath) {
        if (-not (Test-Path $configPath)) {
            Write-Host "ERROR: Proxy config not found: $configPath" -ForegroundColor Red
            exit 1
        }
        $parsed = parse_proxy_config -Json (Get-Content $configPath -Raw)
        if (-not $parsed.success) {
            Write-Host "ERROR: $($parsed.error.message)" -ForegroundColor Red
            exit 1
        }
        $providers = merge_provider_maps -Defaults $providers -Overrides $parsed.data
        Write-Host "Loaded provider config: $configPath"
    }

    # Admin pipe: explicit flags win (test harnesses); otherwise service
    # mode config enables it (daemon runs as the service account, clients
    # connect as the installing user).
    $pipeName = $admin_pipe
    $pipeSid = $allow_sid
    if (-not $pipeName -and ($null -ne $script:serviceConfig)) {
        $pipeName = [string]$script:serviceConfig.pipe_name
        $pipeSid = [string]$script:serviceConfig.allowed_sid
    }

    $result = start_proxy_listener -Port $port -Providers $providers `
        -AdminPipeName $pipeName -AdminAllowedSid $pipeSid `
        -ReadSecret {
            param($secretName)
            get_secret_value -Name $secretName
        } `
        -CheckSecret {
            param($secretName)
            test_secret_exists -Name $secretName
        }

    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }
}

if (-not $command -or $command -in @('-h', '--help', '/?', 'help')) {
    show_usage
    exit 0
}

try {
    switch ($command.ToLowerInvariant()) {
        'set' { invoke_set_command }
        'create' { invoke_create_command }
        'list' { invoke_list_command }
        'exists' { invoke_exists_command }
        'delete' { invoke_delete_command }
        'run' { invoke_run_command }
        'proxy' { invoke_proxy_command }
        default {
            Write-Host "Unknown command: $command" -ForegroundColor Red
            show_usage
            exit 1
        }
    }
} catch {
    # Catch unexpected initialization failures (e.g., Add-Type blocked under
    # ConstrainedLanguage, locked .NET assembly) so the user sees a single
    # ERROR line instead of a raw stack trace.
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}
