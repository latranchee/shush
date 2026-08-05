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

function show_usage {
    Write-Host "Usage:"
    Write-Host "  .\secret_manager.ps1 set <name> [--from-stdin] [--force]"
    Write-Host "  .\secret_manager.ps1 list"
    Write-Host "  .\secret_manager.ps1 exists <name>"
    Write-Host "  .\secret_manager.ps1 delete <name> [--if-exists]"
    Write-Host "  .\secret_manager.ps1 run <command> [args...] --env ENV_VAR=secret_name [--env-optional ENV_VAR=secret_name]"
    Write-Host ""
    Write-Host "  --env           required mapping; missing secret aborts before launch."
    Write-Host "  --env-optional  best-effort mapping; missing secret logs a warning"
    Write-Host "                  to stderr and the child launches with that env var unset."
    Write-Host "  --if-exists     for delete: exit 0 even when the secret is not present."
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

function invoke_set_command {
    if (-not $name) {
        Write-Host "ERROR: Missing secret name" -ForegroundColor Red
        exit 1
    }

    if (-not (test_secret_name -Name $name)) {
        Write-Host "ERROR: Invalid secret name '$name'. Use lowercase letters, digits, and underscores; start with a lowercase letter." -ForegroundColor Red
        exit 1
    }

    # Existence pre-check (without --force) BEFORE prompting, so a typed value
    # is never discarded. With --force, we always prompt and overwrite.
    if (-not $force) {
        $existsResult = query_secret_exists -Name $name
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

    $value = if ($from_stdin) {
        read_secret_from_stdin
    } else {
        read_secret_from_secure_prompt -Name $name
    }

    if ([string]::IsNullOrEmpty($value)) {
        Write-Host "ERROR: Secret value is empty. Refusing to store empty secret for '$name'." -ForegroundColor Red
        exit 1
    }

    $result = set_secret_value -Name $name -Value $value -Force:$force
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

function invoke_list_command {
    $result = get_secret_names
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

    $result = remove_secret_value -Name $name
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

    $result = query_secret_exists -Name $name
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

if (-not $command -or $command -in @('-h', '--help', '/?', 'help')) {
    show_usage
    exit 0
}

try {
    switch ($command.ToLowerInvariant()) {
        'set' { invoke_set_command }
        'list' { invoke_list_command }
        'exists' { invoke_exists_command }
        'delete' { invoke_delete_command }
        'run' { invoke_run_command }
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
