$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'modules\credential_store.psm1') -DisableNameChecking
$fixture = Join-Path $PSScriptRoot 'fixtures\backup_prompt.ps1'
$name = 'e2e_backup_' + [guid]::NewGuid().ToString('N')
$second_name = $name + '_second'
$value = 'synthetic-' + [guid]::NewGuid().ToString('N')
$archive = Join-Path $env:TEMP ($name + '.shushbak')
$passed = 0
$daemon = $null
$old_config = $env:SHUSH_SERVICE_CONFIG
$config_path = Join-Path $env:TEMP ($name + '.json')
$stdout = Join-Path $env:TEMP ($name + '.out.log')
$stderr = Join-Path $env:TEMP ($name + '.err.log')
function check {
    param([string]$Label, [bool]$Condition)
    if (-not $Condition) { throw "FAIL: $Label" }
    $script:passed++
    Write-Host "PASS: $Label"
}
try {
    $created = set_secret_value -Name $name -Value $value
    check 'create synthetic credential' $created.success
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Backup -Path $archive -Name $name 2>&1
    check 'backup CLI succeeds' ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $archive))
    check 'backup output contains no value' (-not (($output -join '') -like "*$value*"))
    $original = [IO.File]::ReadAllBytes($archive)
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Backup -Path $archive -Name $name 2>&1
    check 'existing archive is not overwritten' ($LASTEXITCODE -ne 0 -and [Convert]::ToBase64String([IO.File]::ReadAllBytes($archive)) -eq [Convert]::ToBase64String($original))
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive 2>&1
    check 'existing credential blocks restore' ($LASTEXITCODE -ne 0 -and (get_secret_value -Name $name).data -eq $value)
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive -SkipExisting 2>&1
    check 'explicit skip keeps existing value' ($LASTEXITCODE -eq 0 -and (get_secret_value -Name $name).data -eq $value)
    $removed = remove_secret_value -Name $name
    check 'remove synthetic source' $removed.success
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive -WrongPassphrase 2>&1
    check 'wrong passphrase writes nothing' ($LASTEXITCODE -ne 0 -and -not (test_secret_exists -Name $name))
    $damaged = $original.Clone()
    $damaged[$damaged.Length - 1] = $damaged[$damaged.Length - 1] -bxor 1
    [IO.File]::WriteAllBytes($archive, $damaged)
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive 2>&1
    check 'tampered archive writes nothing' ($LASTEXITCODE -ne 0 -and -not (test_secret_exists -Name $name))
    [IO.File]::WriteAllBytes($archive, $original)
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive 2>&1
    check 'restore CLI succeeds' ($LASTEXITCODE -eq 0)
    check 'restored credential matches' ((get_secret_value -Name $name).data -ceq $value)
    check 'restore output contains no value' (-not (($output -join '') -like "*$value*"))

    Import-Module (Join-Path $root 'modules\vault_backup.psm1') -DisableNameChecking
    $multi = protect_backup_archive -Records @(@{ name = $second_name; value = 'synthetic-second-value' }, @{ name = $name; value = $value }) -Passphrase 'synthetic backup test passphrase'
    [IO.File]::WriteAllBytes($archive, $multi.data)
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive 2>&1
    check 'late collision blocks all earlier pending writes' ($LASTEXITCODE -ne 0 -and -not (test_secret_exists -Name $second_name))
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive -SkipExisting 2>&1
    check 'skip imports missing names while preserving existing credentials' ($LASTEXITCODE -eq 0 -and (get_secret_value -Name $second_name).data -ceq 'synthetic-second-value' -and (get_secret_value -Name $name).data -ceq $value)
    $null = remove_secret_value -Name $second_name

    # Exercise the service path with a dedicated same-user daemon and synthetic
    # config, never the machine's real service account or real admin pipe.
    Import-Module (Join-Path $root 'modules\admin_pipe.psm1') -DisableNameChecking
    $pipe = $name + '_pipe'
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    $env:SHUSH_SERVICE_CONFIG = $config_path
    $entry = Join-Path $root 'secret_manager.ps1'
    $daemon = Start-Process powershell.exe -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"' + $entry + '"'), 'proxy', 'start', '--port', $port, '--admin-pipe', $pipe, '--allow-sid', $sid) -WindowStyle Hidden -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $ready = $false
    $deadline = (Get-Date).AddSeconds(20)
    while ((Get-Date) -lt $deadline) {
        $ping = send_admin_request -PipeName $pipe -TimeoutMs 500 -Request @{ op = 'ping' }
        if ($ping.success) { $ready = $true; break }
        Start-Sleep -Milliseconds 200
    }
    check 'isolated service pipe ready' $ready
    @{ mode = 'service'; account = $env:USERNAME; pipe_name = $pipe; allowed_sid = $sid; port = $port } | ConvertTo-Json | Set-Content -LiteralPath $config_path -Encoding ascii
    Remove-Item -LiteralPath $archive -Force
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Backup -Path $archive -Name $name -Vault Service 2>&1
    check 'service-owner backup succeeds' ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $archive))
    $null = remove_secret_value -Name $name
    $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Restore -Path $archive -Vault Service 2>&1
    check 'restore writes through service pipe' ($LASTEXITCODE -eq 0 -and (get_secret_value -Name $name).data -ceq $value)
    $rejected = send_admin_request -PipeName $pipe -Request @{ op = 'export' }
    check 'pipe still rejects export requests' (-not $rejected.success)
    # Use a real, different local SID without logging in as that account.
    $other = Get-LocalUser | Where-Object { $_.SID.Value -ne $sid } | Select-Object -First 1
    if ($other) {
        @{ mode = 'service'; account = $other.Name; pipe_name = $pipe } | ConvertTo-Json | Set-Content -LiteralPath $config_path -Encoding ascii
        Remove-Item -LiteralPath $archive -Force
        $output = powershell.exe -NoProfile -ExecutionPolicy Bypass -File $fixture -Action Backup -Path $archive -Name $name -Vault Service 2>&1
        check 'other identity cannot request service export' ($LASTEXITCODE -ne 0 -and -not (Test-Path -LiteralPath $archive))
    }
    Write-Host "Backup E2E: $passed passed"
} finally {
    if ($daemon -and -not $daemon.HasExited) { Stop-Process -Id $daemon.Id -Force }
    $env:SHUSH_SERVICE_CONFIG = $old_config
    $null = remove_secret_value -Name $name
    if (Test-Path -LiteralPath $archive) { Remove-Item -LiteralPath $archive -Force }
    $null = remove_secret_value -Name $second_name
    foreach ($file in @($config_path, $stdout, $stderr)) {
        if (Test-Path -LiteralPath $file) { Remove-Item -LiteralPath $file -Force }
    }
}
