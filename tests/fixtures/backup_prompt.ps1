# Test-only secure prompt substitute. Never use against production archives.
param([string]$Action, [string]$Path, [string]$Name, [string]$Vault = 'Local', [switch]$SkipExisting, [switch]$WrongPassphrase)
function global:Read-Host {
    param([string]$Prompt, [switch]$AsSecureString)
    $value = if ($WrongPassphrase) { 'wrong test passphrase' } else { 'synthetic backup test passphrase' }
    return (ConvertTo-SecureString $value -AsPlainText -Force)
}
$entry = Join-Path (Split-Path (Split-Path $PSScriptRoot -Parent) -Parent) 'backup_vault.ps1'
if ($Action -eq 'Backup') { & $entry -Action Backup -Path $Path -Vault $Vault -Names @($Name) }
else { & $entry -Action Restore -Path $Path -Vault $Vault -SkipExisting:$SkipExisting }
exit $LASTEXITCODE
