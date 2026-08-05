# admin_pipe.psm1
# Write-only named-pipe admin channel for shush service mode.
#
# In service mode the secrets live in a dedicated service account's vault.
# The interactive user's CLI cannot read that vault (different DPAPI scope),
# so management commands travel over a named pipe to the daemon, which does
# the vault writes under its own identity.
#
# The protocol is deliberately write-only with respect to secret VALUES:
# values flow in (create), names flow out (list/exists). There is no
# operation that returns a secret value, so a process that can reach the
# pipe can manage secrets but never extract one.
#
# NOTE: the SERVER side (pipe creation with an ACL) requires Windows
# PowerShell 5.1 (.NET Framework PipeSecurity constructor). The client
# side works on both Windows PowerShell and PowerShell 7+.

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'credential_store.psm1')

$script:adminOps = @('ping', 'create', 'list', 'exists', 'delete')
$script:maxRequestBytes = 16384
$script:secretNamePattern = '^[a-z][a-z0-9_]*$'

function get_admin_pipe_ops {
    return $script:adminOps
}

function parse_admin_request {
    param([string]$Json)

    if ([string]::IsNullOrWhiteSpace($Json)) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_REQUEST'; message = 'Empty admin request' }
        }
    }

    if ([System.Text.Encoding]::UTF8.GetByteCount($Json) -gt $script:maxRequestBytes) {
        return @{
            success = $false; data = $null
            error = @{ code = 'REQUEST_TOO_LARGE'; message = "Admin request exceeds $script:maxRequestBytes bytes" }
        }
    }

    try {
        $parsed = $Json | ConvertFrom-Json
    } catch {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_REQUEST'; message = 'Admin request is not valid JSON' }
        }
    }

    if (-not ($parsed.PSObject.Properties.Match('op').Count -gt 0) -or -not $parsed.op) {
        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_REQUEST'; message = "Admin request is missing 'op'" }
        }
    }

    $op = ([string]$parsed.op).ToLowerInvariant()
    if ($script:adminOps -cnotcontains $op) {
        return @{
            success = $false; data = $null
            error = @{ code = 'UNSUPPORTED_OP'; message = "Unsupported admin op '$op'. Secret values are write-only: supported ops are $($script:adminOps -join ', ')." }
        }
    }

    $name = $null
    if ($parsed.PSObject.Properties.Match('name').Count -gt 0 -and $parsed.name) {
        $name = [string]$parsed.name
    }

    if ($op -in @('create', 'exists', 'delete')) {
        if (-not $name) {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_REQUEST'; message = "Admin op '$op' requires 'name'" }
            }
        }
        if ($name -cnotmatch $script:secretNamePattern) {
            return @{
                success = $false; data = $null
                error = @{ code = 'INVALID_NAME'; message = "Invalid secret name '$name'. Use lowercase letters, digits, and underscores; start with a lowercase letter." }
            }
        }
    }

    $value = $null
    if ($op -eq 'create') {
        if (-not ($parsed.PSObject.Properties.Match('value').Count -gt 0) -or [string]::IsNullOrEmpty([string]$parsed.value)) {
            return @{
                success = $false; data = $null
                error = @{ code = 'EMPTY_VALUE'; message = "Admin op 'create' requires a non-empty 'value'" }
            }
        }
        $value = [string]$parsed.value
    }

    $force = $false
    if ($parsed.PSObject.Properties.Match('force').Count -gt 0 -and $parsed.force) {
        $force = [bool]$parsed.force
    }

    return @{
        success = $true
        data = @{ op = $op; name = $name; value = $value; force = $force }
        error = $null
    }
}

function dispatch_admin_request {
    param([hashtable]$Request)

    switch ($Request.op) {
        'ping' { return @{ success = $true; data = 'pong'; error = $null } }
        'create' { return set_secret_value -Name $Request.name -Value $Request.value -Force:$Request.force }
        'list' { return get_secret_names }
        'exists' { return query_secret_exists -Name $Request.name }
        'delete' { return remove_secret_value -Name $Request.name }
    }

    return @{
        success = $false; data = $null
        error = @{ code = 'UNSUPPORTED_OP'; message = "Unsupported admin op '$($Request.op)'" }
    }
}

function new_admin_pipe_server {
    param(
        [string]$PipeName,
        [string]$AllowedSid
    )

    try {
        $security = [System.IO.Pipes.PipeSecurity]::new()

        # The daemon's own identity gets full control.
        $self = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
        $security.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
            $self, [System.IO.Pipes.PipeAccessRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow))

        # Exactly one client identity may connect.
        $clientSid = [System.Security.Principal.SecurityIdentifier]::new($AllowedSid)
        $security.AddAccessRule([System.IO.Pipes.PipeAccessRule]::new(
            $clientSid, [System.IO.Pipes.PipeAccessRights]::ReadWrite,
            [System.Security.AccessControl.AccessControlType]::Allow))

        $pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
            $PipeName,
            [System.IO.Pipes.PipeDirection]::InOut,
            1,
            [System.IO.Pipes.PipeTransmissionMode]::Byte,
            [System.IO.Pipes.PipeOptions]::Asynchronous,
            $script:maxRequestBytes,
            $script:maxRequestBytes,
            $security)

        return @{ success = $true; data = $pipe; error = $null }
    } catch {
        return @{
            success = $false; data = $null
            error = @{ code = 'PIPE_CREATE_FAILED'; message = "Cannot create admin pipe '$PipeName': $($_.Exception.Message)" }
        }
    }
}

function read_pipe_request_line {
    param($Pipe, [int]$TimeoutMs = 3000)

    $buffer = New-Object byte[] $script:maxRequestBytes
    $total = 0
    $deadline = (Get-Date).AddMilliseconds($TimeoutMs)

    while ($total -lt $buffer.Length) {
        $task = $Pipe.ReadAsync($buffer, $total, $buffer.Length - $total)
        $remaining = [int][Math]::Max(1, ($deadline - (Get-Date)).TotalMilliseconds)
        if (-not $task.Wait($remaining)) {
            return @{
                success = $false; data = $null
                error = @{ code = 'READ_TIMEOUT'; message = 'Admin request read timed out' }
            }
        }
        $read = $task.Result
        if ($read -le 0) { break }
        $total += $read
        $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $total)
        $newline = $text.IndexOf("`n")
        if ($newline -ge 0) {
            return @{ success = $true; data = $text.Substring(0, $newline).TrimEnd("`r"); error = $null }
        }
        if ((Get-Date) -gt $deadline) {
            return @{
                success = $false; data = $null
                error = @{ code = 'READ_TIMEOUT'; message = 'Admin request read timed out' }
            }
        }
    }

    return @{
        success = $false; data = $null
        error = @{ code = 'INVALID_REQUEST'; message = 'Admin request ended without a newline' }
    }
}

function write_pipe_response {
    param($Pipe, $Response)

    $json = $Response | ConvertTo-Json -Compress -Depth 6
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
    $Pipe.Write($bytes, 0, $bytes.Length)
    $Pipe.Flush()
    try { $Pipe.WaitForPipeDrain() } catch { }
}

# Serves exactly one connected client request, then leaves the pipe ready
# for Disconnect + re-arm by the caller. Never returns secret values and
# never logs request bodies (a create request contains the plaintext).
function handle_admin_connection {
    param($Pipe, [int]$TimeoutMs = 3000)

    $summary = 'unknown'
    try {
        $lineResult = read_pipe_request_line -Pipe $Pipe -TimeoutMs $TimeoutMs
        if (-not $lineResult.success) {
            write_pipe_response -Pipe $Pipe -Response $lineResult
            return $summary
        }

        $parsed = parse_admin_request -Json $lineResult.data
        if (-not $parsed.success) {
            $summary = "rejected ($($parsed.error.code))"
            write_pipe_response -Pipe $Pipe -Response $parsed
            return $summary
        }

        $summary = $parsed.data.op
        if ($parsed.data.name) { $summary += " $($parsed.data.name)" }

        $result = dispatch_admin_request -Request $parsed.data
        write_pipe_response -Pipe $Pipe -Response $result
        return $summary
    } catch {
        return "error ($($_.Exception.Message))"
    }
}

function send_admin_request {
    param(
        [string]$PipeName,
        [hashtable]$Request,
        [int]$TimeoutMs = 5000
    )

    $pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', $PipeName, [System.IO.Pipes.PipeDirection]::InOut)
    try {
        try {
            $pipe.Connect($TimeoutMs)
        } catch {
            return @{
                success = $false; data = $null
                error = @{ code = 'PIPE_UNAVAILABLE'; message = "Cannot reach shush service pipe '$PipeName'. Is the proxy service running? ($($_.Exception.Message))" }
            }
        }

        $json = $Request | ConvertTo-Json -Compress -Depth 4
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($json + "`n")
        $pipe.Write($bytes, 0, $bytes.Length)
        $pipe.Flush()

        $buffer = New-Object byte[] $script:maxRequestBytes
        $total = 0
        $deadline = (Get-Date).AddMilliseconds($TimeoutMs)
        while ($total -lt $buffer.Length) {
            $task = $pipe.ReadAsync($buffer, $total, $buffer.Length - $total)
            $remaining = [int][Math]::Max(1, ($deadline - (Get-Date)).TotalMilliseconds)
            if (-not $task.Wait($remaining)) {
                return @{
                    success = $false; data = $null
                    error = @{ code = 'PIPE_TIMEOUT'; message = 'Timed out waiting for the shush service response' }
                }
            }
            $read = $task.Result
            if ($read -le 0) { break }
            $total += $read
            $text = [System.Text.Encoding]::UTF8.GetString($buffer, 0, $total)
            if ($text.IndexOf("`n") -ge 0) {
                $line = $text.Substring(0, $text.IndexOf("`n")).TrimEnd("`r")
                try {
                    $response = $line | ConvertFrom-Json
                } catch {
                    return @{
                        success = $false; data = $null
                        error = @{ code = 'INVALID_RESPONSE'; message = 'Service returned an unparseable response' }
                    }
                }
                return $response
            }
        }

        return @{
            success = $false; data = $null
            error = @{ code = 'INVALID_RESPONSE'; message = 'Service closed the pipe without a response' }
        }
    }
    finally {
        $pipe.Dispose()
    }
}

# Copies every secret in the CURRENT user's local vault into the service
# vault through the admin pipe. Values transit this process's memory once,
# during migration, and are never written to disk or output.
function invoke_vault_migration {
    param(
        [string]$PipeName,
        [int]$TimeoutMs = 5000
    )

    $namesResult = get_secret_names
    if (-not $namesResult.success) {
        return @{ success = $false; data = $null; error = $namesResult.error }
    }

    $migrated = @()
    $failed = @()

    foreach ($name in @($namesResult.data)) {
        $valueResult = get_secret_value -Name $name
        if (-not $valueResult.success) {
            $failed += @{ name = $name; error = $valueResult.error.message }
            continue
        }

        $response = send_admin_request -PipeName $PipeName -TimeoutMs $TimeoutMs -Request @{
            op = 'create'; name = $name; value = $valueResult.data; force = $true
        }

        if ($response.success) {
            $migrated += $name
        } else {
            $failed += @{ name = $name; error = $response.error.message }
        }
    }

    return @{
        success = ($failed.Count -eq 0)
        data = @{ migrated = $migrated; failed = $failed; total = @($namesResult.data).Count }
        error = $(if ($failed.Count -eq 0) { $null } else { @{ code = 'MIGRATION_PARTIAL'; message = "$($failed.Count) secret(s) failed to migrate" } })
    }
}

Export-ModuleMember -Function @(
    'get_admin_pipe_ops',
    'parse_admin_request',
    'dispatch_admin_request',
    'new_admin_pipe_server',
    'read_pipe_request_line',
    'write_pipe_response',
    'handle_admin_connection',
    'send_admin_request',
    'invoke_vault_migration'
)
