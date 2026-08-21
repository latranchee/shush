# process_runner.psm1
# Child-process environment injection for secret_manager.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Reserved env-var names that, if shadowed by an --env mapping, would break the
# child process invocation itself. The runner passes these through from parent.
$script:envInheritWhitelist = @(
    'PATH', 'PATHEXT', 'SYSTEMROOT', 'SYSTEMDRIVE',
    'WINDIR', 'COMSPEC', 'TEMP', 'TMP',
    'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH',
    'APPDATA', 'LOCALAPPDATA', 'PROGRAMDATA',
    'PROGRAMFILES', 'PROGRAMFILES(X86)', 'PROGRAMW6432',
    'COMMONPROGRAMFILES', 'COMMONPROGRAMFILES(X86)', 'COMMONPROGRAMW6432',
    'COMPUTERNAME', 'USERNAME', 'USERDOMAIN', 'LOGONSERVER',
    'NUMBER_OF_PROCESSORS', 'PROCESSOR_ARCHITECTURE', 'PROCESSOR_IDENTIFIER',
    'OS', 'PSMODULEPATH'
)

function expand_env_mappings {
    <#
    .SYNOPSIS
    Pure: split comma-joined ENV=secret tokens into individual mappings.

    .DESCRIPTION
    A raw command line (NSSM AppParameters, powershell.exe -File) has no
    PowerShell array syntax, so `-secret_env "A=a","B=b"` arrives as the single
    token `A=a,B=b`. Env-var and secret names can never contain commas, so
    splitting on ',' is lossless. Blank fragments (stray commas) are dropped.
    #>
    param([string[]]$Tokens = @())

    @($Tokens |
        Where-Object { $_ } |
        ForEach-Object { $_ -split ',' } |
        ForEach-Object { $_.Trim() } |
        Where-Object { $_ })
}

function parse_secret_env_mapping {
    param([string]$Mapping)

    if ($Mapping -notmatch '=') {
        return @{
            success = $false
            data = $null
            error = @{ code = 'INVALID_ENV_MAPPING'; message = "Invalid env mapping '$Mapping': missing '=' separator (expected ENV_VAR=secret_name)" }
        }
    }

    if ($Mapping -cnotmatch '^([A-Za-z_][A-Za-z0-9_]*)=([a-z][a-z0-9_]*)$') {
        $parts = $Mapping -split '=', 2
        $envSide = $parts[0]
        $secretSide = if ($parts.Length -gt 1) { $parts[1] } else { '' }
        $detail = if ($envSide -cnotmatch '^[A-Za-z_][A-Za-z0-9_]*$') {
            "env-var name '$envSide' must start with a letter or underscore and contain only letters, digits, underscores"
        } else {
            "secret name '$secretSide' must be lowercase letters, digits, underscores; start with a lowercase letter"
        }
        return @{
            success = $false
            data = $null
            error = @{ code = 'INVALID_ENV_MAPPING'; message = "Invalid env mapping '$Mapping': $detail" }
        }
    }

    return @{
        success = $true
        data = @{
            env_var = $Matches[1]
            secret_name = $Matches[2]
        }
        error = $null
    }
}

function resolve_secret_env_mappings {
    param(
        [string[]]$Mappings = @(),
        [string[]]$OptionalMappings = @(),
        [scriptblock]$ReadSecret
    )

    $envValues = @{}
    $missingOptional = @()
    # Case-insensitive on Windows: env vars folded by ProcessStartInfo. Detect
    # collisions early so the user knows which mapping won.
    $seenEnvCi = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    $missingRequired = @()
    $invalidMappings = @()

    foreach ($mapping in $Mappings) {
        if (-not $mapping) { continue }
        $parsed = parse_secret_env_mapping -Mapping $mapping
        if (-not $parsed.success) {
            $invalidMappings += $parsed.error.message
            continue
        }

        if (-not $seenEnvCi.Add($parsed.data.env_var)) {
            $invalidMappings += "Duplicate env var '$($parsed.data.env_var)' (case-insensitive on Windows)"
            continue
        }

        $secretResult = & $ReadSecret $parsed.data.secret_name
        if (-not $secretResult.success) {
            $missingRequired += [pscustomobject]@{
                env_var = $parsed.data.env_var
                secret_name = $parsed.data.secret_name
                error = $secretResult.error
            }
            continue
        }

        $envValues[$parsed.data.env_var] = $secretResult.data
    }

    foreach ($mapping in $OptionalMappings) {
        if (-not $mapping) { continue }
        $parsed = parse_secret_env_mapping -Mapping $mapping
        if (-not $parsed.success) {
            $invalidMappings += $parsed.error.message
            continue
        }

        if (-not $seenEnvCi.Add($parsed.data.env_var)) {
            $invalidMappings += "Duplicate env var '$($parsed.data.env_var)' (case-insensitive on Windows)"
            continue
        }

        $secretResult = & $ReadSecret $parsed.data.secret_name
        if (-not $secretResult.success) {
            $missingOptional += [pscustomobject]@{
                env_var = $parsed.data.env_var
                secret_name = $parsed.data.secret_name
            }
            continue
        }

        $envValues[$parsed.data.env_var] = $secretResult.data
    }

    if ($invalidMappings.Count -gt 0) {
        return @{
            success = $false
            data = $null
            error = @{
                code = 'INVALID_ENV_MAPPING'
                message = ($invalidMappings -join '; ')
            }
        }
    }

    if ($missingRequired.Count -gt 0) {
        $names = ($missingRequired | ForEach-Object { $_.secret_name }) -join ', '
        return @{
            success = $false
            data = $null
            error = @{
                code = 'NOT_FOUND'
                message = "Required secret(s) not available: $names"
                missing = $missingRequired
            }
        }
    }

    return @{
        success = $true
        data = $envValues
        missing_optional = $missingOptional
        error = $null
    }
}

function quote_native_argument {
    param([AllowNull()][AllowEmptyString()][string]$Argument)

    if ($null -eq $Argument -or $Argument.Length -eq 0) {
        return '""'
    }

    if ($Argument.IndexOfAny([char[]]@([char]0, [char]13, [char]10)) -ge 0) {
        throw "Argument contains a control character (NUL/CR/LF) that cannot be safely quoted on Windows: '$Argument'"
    }

    if ($Argument -notmatch '[\s"]') {
        return $Argument
    }

    $builder = [System.Text.StringBuilder]::new()
    [void]$builder.Append('"')
    $backslashes = 0

    foreach ($char in $Argument.ToCharArray()) {
        if ($char -eq '\') {
            $backslashes += 1
            continue
        }

        if ($char -eq '"') {
            [void]$builder.Append('\' * ($backslashes * 2 + 1))
            [void]$builder.Append('"')
            $backslashes = 0
            continue
        }

        if ($backslashes -gt 0) {
            [void]$builder.Append('\' * $backslashes)
            $backslashes = 0
        }
        [void]$builder.Append($char)
    }

    if ($backslashes -gt 0) {
        [void]$builder.Append('\' * ($backslashes * 2))
    }

    [void]$builder.Append('"')
    return $builder.ToString()
}

function resolve_executable_path {
    param([string]$FilePath)

    if ([System.IO.Path]::IsPathRooted($FilePath)) {
        return $FilePath
    }

    $cmd = Get-Command -Name $FilePath -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) {
        return $cmd.Source
    }
    return $FilePath
}

function invoke_secret_process {
    param(
        [string]$FilePath,
        [string[]]$ArgumentList = @(),
        [hashtable]$Environment = @{},
        [string]$WorkingDirectory = (Get-Location).Path
    )

    if (-not $FilePath) {
        return @{
            success = $false
            data = @{ exit_code = 127 }
            error = @{ code = 'INVALID_PARAMS'; message = 'Missing command to run' }
        }
    }

    $resolvedPath = resolve_executable_path -FilePath $FilePath

    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $resolvedPath
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.UseShellExecute = $false
    $psi.Arguments = (@($ArgumentList) | ForEach-Object { quote_native_argument -Argument $_ }) -join ' '

    # Reduce inherited-environment leakage. Start by clearing every parent env
    # var that isn't on the OS-essential whitelist, then overlay the declared
    # secret mappings. This stops stray $env:OPENAI_API_KEY etc. from leaking
    # into a child that didn't ask for it via --env.
    $whitelistCi = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($n in $script:envInheritWhitelist) { [void]$whitelistCi.Add($n) }
    foreach ($k in $Environment.Keys) { [void]$whitelistCi.Add([string]$k) }

    $existingKeys = @($psi.Environment.Keys)
    foreach ($key in $existingKeys) {
        if (-not $whitelistCi.Contains($key)) {
            [void]$psi.Environment.Remove($key)
        }
    }

    foreach ($key in $Environment.Keys) {
        $psi.Environment[$key] = [string]$Environment[$key]
    }

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $psi

    try {
        [void]$process.Start()
        $process.WaitForExit()
        return @{
            success = ($process.ExitCode -eq 0)
            data = @{ exit_code = $process.ExitCode }
            error = $(if ($process.ExitCode -eq 0) { $null } else { @{ code = 'CHILD_FAILED'; message = "Child process exited with code $($process.ExitCode)" } })
        }
    }
    catch {
        return @{
            success = $false
            data = @{ exit_code = 127 }
            error = @{ code = 'PROCESS_START_FAILED'; message = $_.Exception.Message }
        }
    }
    finally {
        $process.Dispose()
    }
}

Export-ModuleMember -Function @(
    'expand_env_mappings',
    'parse_secret_env_mapping',
    'resolve_secret_env_mappings',
    'quote_native_argument',
    'resolve_executable_path',
    'invoke_secret_process'
)
