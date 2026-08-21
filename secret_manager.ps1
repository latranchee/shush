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

    # No [Alias('env')] here on purpose: an alias would let the binder capture
    # `--env` flags meant for run's hand-parser below. Bound once, a repeated
    # `--env A=x --env B=y` either collapses or errors ("specified more than
    # once") depending on host, so services injecting 2+ secrets from a raw
    # command line (-File) could never launch. `-env`/`--env` both fall through
    # to $arguments and are promoted there.
    [string[]]$secret_env,

    [string[]]$secret_env_optional,

    [int]$port = 8765,

    [string]$config,

    [switch]$local,

    [Alias('admin-pipe')]
    [string]$admin_pipe,

    [Alias('allow-sid')]
    [string]$allow_sid,

    [switch]$passphrase,

    [Alias('passphrase-stdin')]
    [switch]$passphrase_stdin,

    [switch]$hello,

    [switch]$yubikey,

    [string]$keyfile,

    [Alias('with-passphrase')]
    [switch]$with_passphrase,

    [string]$label,

    [string]$slot,

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
                    # @() around the whole if-expression: a 1-element array
                    # returned from `if` unrolls to a scalar string, and
                    # string + array is string CONCATENATION ("A=x" + "B=y"
                    # -> "A=xB=y"), silently merging mappings.
                    $current = @(if ($null -ne $secret_env) { $secret_env } else { @() })
                    $secret_env = $current + @($rest[$i + 1])
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--env-optional$' {
                if ($i + 1 -lt $rest.Count) {
                    $current = @(if ($null -ne $secret_env_optional) { $secret_env_optional } else { @() })
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
            '^--passphrase$' { $passphrase = $true }
            '^--passphrase-stdin$' { $passphrase_stdin = $true }
            '^--hello$' { $hello = $true }
            '^--yubikey$' { $yubikey = $true }
            '^--with-passphrase$' { $with_passphrase = $true }
            # --keyfile takes an optional path: bare means "find the drive".
            # 'auto' is the sentinel because an empty string cannot be
            # distinguished from the flag being absent.
            '^--keyfile$' {
                if ($i + 1 -lt $rest.Count -and -not ([string]$rest[$i + 1]).StartsWith('-')) {
                    $keyfile = $rest[$i + 1]
                    $i += 1
                } else {
                    $keyfile = 'auto'
                }
            }
            '^--label$' {
                if ($i + 1 -lt $rest.Count) {
                    $label = $rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
            '^--slot$' {
                if ($i + 1 -lt $rest.Count) {
                    $slot = $rest[$i + 1]
                    $i += 1
                } else { $consumed = $false; $tail += $tok }
            }
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
Import-Module (Join-Path $moduleDir 'vault_crypto.psm1') -Force -DisableNameChecking
Import-Module (Join-Path $moduleDir 'vault_keyslots.psm1') -Force -DisableNameChecking

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
    Write-Host "  .\secret_manager.ps1 create <name> [<value>] [--force]"
    Write-Host "  .\secret_manager.ps1 list"
    Write-Host "  .\secret_manager.ps1 exists <name>"
    Write-Host "  .\secret_manager.ps1 delete <name> [--if-exists]"
    Write-Host "  .\secret_manager.ps1 run <command> [args...] --env ENV_VAR=secret_name [--env-optional ENV_VAR=secret_name]"
    Write-Host "  .\secret_manager.ps1 proxy start [--port 8765] [--config proxy.json]"
    Write-Host "  .\secret_manager.ps1 enroll --passphrase|--hello|--yubikey|--keyfile [<path>] [--label <text>]"
    Write-Host "  .\secret_manager.ps1 protect <name>"
    Write-Host "  .\secret_manager.ps1 unprotect <name>"
    Write-Host "  .\secret_manager.ps1 slots [--slot <id>]"
    Write-Host ""
    Write-Host "  set             prompts securely (or reads a pipe with --from-stdin)."
    Write-Host "  create          one-liner: takes the value from the command line;"
    Write-Host "                  omit the value to get a secure prompt instead."
    Write-Host "                  Inline values are visible in shell history and"
    Write-Host "                  process listings; prompt or pipe when that matters."
    Write-Host "  --env           required mapping; missing secret aborts before launch."
    Write-Host "  --env-optional  best-effort mapping; missing secret logs a warning"
    Write-Host "                  to stderr and the child launches with that env var unset."
    Write-Host "  --if-exists     for delete: exit 0 even when the secret is not present."
    Write-Host "  --local         force local-vault behavior in service mode (see"
    Write-Host "                  docs/service_mode.md; no effect otherwise)."
    Write-Host "  enroll          add an unlock factor: --passphrase, --hello (Windows"
    Write-Host "                  Hello), --yubikey (FIDO2 security key), or --keyfile"
    Write-Host "                  (thumbdrive; bare flag finds the removable drive)."
    Write-Host "                  Enroll two so a lost key is not a lost vault."
    Write-Host "  --keyfile       also selects the keyfile at unlock time, and names an"
    Write-Host "                  explicit path when the drive is not removable."
    Write-Host "  --with-passphrase  for enroll --keyfile: require both file and"
    Write-Host "                  passphrase, so a copied keyfile alone is not enough."
    Write-Host "  protect         encrypt one secret under the vault master key; reading"
    Write-Host "                  it then requires an unlock factor. Per-secret, so"
    Write-Host "                  low-value keys can stay friction-free."
    Write-Host "  unprotect       decrypt a secret back to plain vault storage."
    Write-Host "  slots           list enrolled factors; --slot <id> removes one."
    Write-Host "  --passphrase-stdin  read the passphrase from a pipe instead of"
    Write-Host "                  prompting (automation; prefer the prompt otherwise)."
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

# ---------------------------------------------------------------------------
# Protected secrets
#
# A protected secret is stored encrypted under a vault master key, which is
# itself wrapped by each enrolled unlock factor. Reading one costs a
# passphrase, a Hello gesture, or a touch on a security key. See
# docs/protected_secrets.md.
# ---------------------------------------------------------------------------

$script:cachedMasterKey = $null

# Factor modules are imported on demand: both compile native interop on
# first use, which is wasted work for `list` or `delete`.
function import_factor_module {
    param([string]$Type)

    switch ($Type) {
        'hello' { Import-Module (Join-Path $moduleDir 'factor_hello.psm1') -Force -DisableNameChecking }
        'fido2' { Import-Module (Join-Path $moduleDir 'factor_fido2.psm1') -Force -DisableNameChecking }
        'keyfile' { Import-Module (Join-Path $moduleDir 'factor_keyfile.psm1') -Force -DisableNameChecking }
    }
}

function read_passphrase_prompt {
    param([string]$Prompt, [switch]$Confirm)

    # Automation path, same trade-off as --from-stdin for values: it keeps the
    # passphrase off the command line and out of shell history, but a pipe is
    # readable by anything that can already see the process, so an interactive
    # prompt is better whenever a human is present.
    if ($passphrase_stdin) {
        if (-not [Console]::IsInputRedirected) {
            Write-Host 'ERROR: --passphrase-stdin requires redirected stdin.' -ForegroundColor Red
            exit 1
        }
        $piped = [Console]::In.ReadLine()
        if ($null -eq $piped) {
            Write-Host 'ERROR: --passphrase-stdin got no input.' -ForegroundColor Red
            exit 1
        }
        return $piped.TrimEnd("`r")
    }

    $secure = Read-Host $Prompt -AsSecureString
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    }

    if ($Confirm) {
        $secondSecure = Read-Host 'Confirm passphrase' -AsSecureString
        $secondPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secondSecure)
        try {
            $second = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($secondPtr)
        } finally {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($secondPtr)
        }
        if ($value -cne $second) {
            Write-Host 'ERROR: Passphrases do not match.' -ForegroundColor Red
            exit 1
        }
    }

    return $value
}

function assert_local_vault_or_exit {
    param([string]$Action)

    if (use_service_pipe) {
        Write-Host "ERROR: '$Action' applies to the local vault, and this machine runs in service mode." -ForegroundColor Red
        Write-Host '       Service mode already isolates secrets in a separate account that you cannot read from here.' -ForegroundColor Yellow
        Write-Host '       Use --local to manage a local-vault copy instead. See docs/service_mode.md.' -ForegroundColor Yellow
        exit 1
    }
}

function read_vault_keys_or_exit {
    $result = read_vault_keys
    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }
    return $result.data
}

function write_vault_keys_or_exit {
    param($Keys)

    $result = write_vault_keys -Keys $Keys
    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }
}

function get_requested_factor_type {
    $requested = @()
    if ($passphrase) { $requested += 'passphrase' }
    if ($hello) { $requested += 'hello' }
    if ($yubikey) { $requested += 'fido2' }
    if ($keyfile) { $requested += 'keyfile' }

    if ($requested.Count -gt 1) {
        Write-Host 'ERROR: Choose one of --passphrase, --hello, --yubikey, or --keyfile.' -ForegroundColor Red
        exit 1
    }
    if ($requested.Count -eq 0) { return $null }
    return $requested[0]
}

function open_slot_interactive {
    param($Slot)

    switch ([string]$Slot.type) {
        'passphrase' {
            $value = read_passphrase_prompt -Prompt "Vault passphrase ($($Slot.label))"
            return (open_passphrase_slot -Slot $Slot -Passphrase $value)
        }
        'hello' {
            import_factor_module -Type 'hello'
            return (open_hello_slot -Slot $Slot)
        }
        'fido2' {
            import_factor_module -Type 'fido2'
            $pin = ''
            if ([bool]$Slot.uses_pin) {
                $pin = read_passphrase_prompt -Prompt 'Security key PIN'
            }
            return (open_fido2_slot -Slot $Slot -Pin $pin)
        }
        'keyfile' {
            import_factor_module -Type 'keyfile'
            $bound = ''
            if ([bool]$Slot.uses_passphrase) {
                $bound = read_passphrase_prompt -Prompt "Passphrase bound to keyfile ($($Slot.label))"
            }
            return (open_keyfile_slot -Slot $Slot -Path $keyfile -Passphrase $bound)
        }
        default {
            return @{
                success = $false
                data = $null
                error = @{ code = 'UNKNOWN_SLOT_TYPE'; message = "Key slot '$($Slot.id)' has unknown type '$($Slot.type)'" }
            }
        }
    }
}

# Picks which enrolled factor to ask for. An attached security key wins
# because touching it is faster than typing a passphrase and cheaper than a
# 2-second PBKDF2 on Windows PowerShell 5.1; Hello comes next; passphrase is
# the fallback that always works.
function select_unlock_slot {
    param($Keys, [string]$PreferredType)

    $slots = @($Keys.slots)
    if ($PreferredType) {
        $matching = @($slots | Where-Object { [string]$_.type -eq $PreferredType })
        if ($matching.Count -eq 0) {
            Write-Host "ERROR: No '$PreferredType' key slot is enrolled. Run: secret_manager.ps1 slots" -ForegroundColor Red
            exit 1
        }
        return $matching[0]
    }

    if ($slot) {
        $matching = @($slots | Where-Object { [string]$_.id -eq $slot })
        if ($matching.Count -eq 0) {
            Write-Host "ERROR: No key slot with id '$slot'." -ForegroundColor Red
            exit 1
        }
        return $matching[0]
    }

    # A plugged-in keyfile costs no interaction at all, so it outranks even a
    # touch - unless a passphrase is bound to it, in which case it costs the
    # same as a passphrase slot and is tried later.
    $keyfileSlots = @($slots | Where-Object { [string]$_.type -eq 'keyfile' })
    $freeKeyfileSlots = @($keyfileSlots | Where-Object { -not [bool]$_.uses_passphrase })
    if ($freeKeyfileSlots.Count -gt 0) {
        import_factor_module -Type 'keyfile'
        foreach ($candidate in $freeKeyfileSlots) {
            $availability = test_keyfile_available -ExplicitPath $keyfile -KeyfileId ([string]$candidate.keyfile_id)
            if ($availability.data.available) { return $candidate }
        }
    }

    $fido2Slots = @($slots | Where-Object { [string]$_.type -eq 'fido2' })
    if ($fido2Slots.Count -gt 0) {
        import_factor_module -Type 'fido2'
        $availability = test_fido2_available
        if ($availability.data.available) { return $fido2Slots[0] }
    }

    $helloSlots = @($slots | Where-Object { [string]$_.type -eq 'hello' })
    if ($helloSlots.Count -gt 0) {
        import_factor_module -Type 'hello'
        $availability = test_hello_available
        if ($availability.data.available) { return $helloSlots[0] }
    }

    $boundKeyfileSlots = @($keyfileSlots | Where-Object { [bool]$_.uses_passphrase })
    if ($boundKeyfileSlots.Count -gt 0) {
        import_factor_module -Type 'keyfile'
        foreach ($candidate in $boundKeyfileSlots) {
            $availability = test_keyfile_available -ExplicitPath $keyfile -KeyfileId ([string]$candidate.keyfile_id)
            if ($availability.data.available) { return $candidate }
        }
    }

    $passphraseSlots = @($slots | Where-Object { [string]$_.type -eq 'passphrase' })
    if ($passphraseSlots.Count -gt 0) { return $passphraseSlots[0] }

    Write-Host 'ERROR: No enrolled unlock factor is currently available.' -ForegroundColor Red
    Write-Host '       Plug in the enrolled security key, or enroll another factor while you still have access.' -ForegroundColor Yellow
    exit 1
}

function unlock_vault_or_exit {
    # -AnyFactor is for enrollment, where the factor flag names the slot being
    # ADDED, not the one to unlock with. Without it, `enroll --keyfile` would
    # demand an existing keyfile slot to open the vault it is about to join.
    param([switch]$AnyFactor)

    if ($null -ne $script:cachedMasterKey) { return $script:cachedMasterKey }

    $keys = read_vault_keys_or_exit
    if (-not (test_vault_initialized -Keys $keys)) {
        Write-Host 'ERROR: No protected vault on this machine. Run: secret_manager.ps1 protect <name>' -ForegroundColor Red
        exit 1
    }

    $preferred = if ($AnyFactor) { $null } else { get_requested_factor_type }
    $chosen = select_unlock_slot -Keys $keys -PreferredType $preferred
    $result = open_slot_interactive -Slot $chosen
    if (-not $result.success) {
        Write-Host "ERROR: $($result.error.message)" -ForegroundColor Red
        exit 1
    }

    # Held for this process only. Nothing is written to disk and nothing
    # outlives the command, which is the whole point on a shared machine.
    $script:cachedMasterKey = $result.data
    return $script:cachedMasterKey
}

# Authoritative protection check: the stored envelope prefix, not the slot
# file's display list, which can lag behind a secret deleted out from under it.
function test_secret_currently_protected {
    param([string]$SecretName)

    $stored = get_secret_value -Name $SecretName
    if (-not $stored.success) { return $false }
    return (test_protected_value -Value $stored.data)
}

# The single read path for secret values: unwraps a protected envelope,
# unlocking the vault on demand, and passes legacy plaintext through.
function read_secret_plaintext {
    param([string]$SecretName)

    $stored = get_secret_value -Name $SecretName
    if (-not $stored.success) { return $stored }

    if (-not (test_protected_value -Value $stored.data)) { return $stored }

    $masterKey = unlock_vault_or_exit
    return (unprotect_secret_string -Value $stored.data -MasterKey $masterKey)
}

function build_enrolled_slot {
    param([string]$Type, [byte[]]$MasterKey)

    switch ($Type) {
        'passphrase' {
            $value = read_passphrase_prompt -Prompt 'New vault passphrase' -Confirm
            return (build_passphrase_slot -Passphrase $value -MasterKey $MasterKey -Label $label)
        }
        'hello' {
            import_factor_module -Type 'hello'
            return (build_hello_slot -MasterKey $MasterKey -Label $label)
        }
        'fido2' {
            import_factor_module -Type 'fido2'
            $selected = select_fido2_device
            if (-not $selected.success) { return $selected }

            $pin = ''
            $pinState = test_fido2_pin_required -DevicePath $selected.data.Path
            if (-not $pinState.success) { return $pinState }
            if ($pinState.data.pin_required) {
                Write-Host 'This security key has a PIN set; it is required for enrollment.'
                $pin = read_passphrase_prompt -Prompt 'Security key PIN'
            }
            return (build_fido2_slot -MasterKey $MasterKey -Label $label -Pin $pin)
        }
        'keyfile' {
            import_factor_module -Type 'keyfile'
            $bound = ''
            if ($with_passphrase) {
                Write-Host 'Binding a passphrase to this keyfile: both will be required to unlock.'
                $bound = read_passphrase_prompt -Prompt 'Passphrase to bind to the keyfile' -Confirm
            }
            return (build_keyfile_slot -MasterKey $MasterKey -Path $keyfile -Label $label -Passphrase $bound -Force:$force)
        }
    }
}

function invoke_enroll_command {
    assert_local_vault_or_exit -Action 'enroll'

    $type = get_requested_factor_type
    if (-not $type) {
        Write-Host 'ERROR: Specify the factor to enroll: --passphrase, --hello, --yubikey, or --keyfile.' -ForegroundColor Red
        exit 1
    }

    $keys = read_vault_keys_or_exit
    if ($null -eq $keys) { $keys = new_vault_keys }

    if (test_vault_initialized -Keys $keys) {
        # Adding a slot means wrapping the existing master key again, so an
        # existing factor has to open the vault first.
        Write-Host 'Unlock the vault with an existing factor to add a new one.'
        $masterKey = unlock_vault_or_exit -AnyFactor
    } else {
        $masterKey = new_master_key
    }

    $built = build_enrolled_slot -Type $type -MasterKey $masterKey
    if (-not $built.success) {
        Write-Host "ERROR: $($built.error.message)" -ForegroundColor Red
        exit 1
    }

    $keys = add_key_slot -Keys $keys -Slot $built.data
    write_vault_keys_or_exit -Keys $keys
    Write-Host "Enrolled $type key slot: $($built.data.id) ($($built.data.label))"
}

function invoke_slots_command {
    assert_local_vault_or_exit -Action 'slots'

    $keys = read_vault_keys_or_exit
    if (-not (test_vault_initialized -Keys $keys)) {
        Write-Host 'No key slots enrolled. Run: secret_manager.ps1 enroll --passphrase'
        return
    }

    if ($slot) {
        $removal = remove_key_slot -Keys $keys -SlotId $slot
        if (-not $removal.success) {
            Write-Host "ERROR: $($removal.error.message)" -ForegroundColor Red
            exit 1
        }
        write_vault_keys_or_exit -Keys $keys
        Write-Host "Removed key slot: $slot ($($removal.data.remaining) remaining)"
        return
    }

    Write-Host ("{0,-14} {1,-12} {2}" -f 'SLOT', 'TYPE', 'LABEL')
    foreach ($entry in @($keys.slots)) {
        Write-Host ("{0,-14} {1,-12} {2}" -f $entry.id, $entry.type, $entry.label)
    }
    $protectedCount = @($keys.protected).Count
    Write-Host ''
    Write-Host "$protectedCount secret(s) protected. Remove a slot with: slots --slot <id>"
}

function invoke_protect_command {
    assert_valid_secret_name_or_exit
    assert_local_vault_or_exit -Action 'protect'

    $keys = read_vault_keys_or_exit
    if ($null -eq $keys) { $keys = new_vault_keys }

    if (-not (test_vault_initialized -Keys $keys)) {
        Write-Host 'No unlock factor is enrolled yet. Enroll one first:'
        Write-Host '  secret_manager.ps1 enroll --passphrase   (or --hello, or --yubikey)'
        exit 1
    }

    $stored = get_secret_value -Name $name
    if (-not $stored.success) {
        Write-Host "ERROR: $($stored.error.message)" -ForegroundColor Red
        exit 1
    }
    if (test_protected_value -Value $stored.data) {
        Write-Host "Secret is already protected: $name"
        exit 0
    }

    $masterKey = unlock_vault_or_exit
    $wrapped = protect_secret_string -Value $stored.data -MasterKey $masterKey
    if (-not $wrapped.success) {
        Write-Host "ERROR: $($wrapped.error.message)" -ForegroundColor Red
        exit 1
    }

    # Verify the round trip before overwriting the only copy of the secret.
    $verify = unprotect_secret_string -Value $wrapped.data -MasterKey $masterKey
    if (-not $verify.success -or $verify.data -cne $stored.data) {
        Write-Host 'ERROR: Encrypted value failed verification; the secret was left unchanged.' -ForegroundColor Red
        exit 1
    }

    $write = set_secret_value -Name $name -Value $wrapped.data -Force
    if (-not $write.success) {
        Write-Host "ERROR: $($write.error.message)" -ForegroundColor Red
        exit 1
    }

    $keys = mark_secret_protected -Keys $keys -Name $name
    write_vault_keys_or_exit -Keys $keys
    Write-Host "Protected secret: $name"
    Write-Host 'Reading it now requires your unlock factor.'
}

function invoke_unprotect_command {
    assert_valid_secret_name_or_exit
    assert_local_vault_or_exit -Action 'unprotect'

    $stored = get_secret_value -Name $name
    if (-not $stored.success) {
        Write-Host "ERROR: $($stored.error.message)" -ForegroundColor Red
        exit 1
    }

    $keys = read_vault_keys_or_exit
    if (-not (test_protected_value -Value $stored.data)) {
        Write-Host "Secret is not protected: $name"
        if ($null -ne $keys) {
            $keys = unmark_secret_protected -Keys $keys -Name $name
            write_vault_keys_or_exit -Keys $keys
        }
        exit 0
    }

    $masterKey = unlock_vault_or_exit
    $plain = unprotect_secret_string -Value $stored.data -MasterKey $masterKey
    if (-not $plain.success) {
        Write-Host "ERROR: $($plain.error.message)" -ForegroundColor Red
        exit 1
    }

    $write = set_secret_value -Name $name -Value $plain.data -Force
    if (-not $write.success) {
        Write-Host "ERROR: $($write.error.message)" -ForegroundColor Red
        exit 1
    }

    $keys = unmark_secret_protected -Keys $keys -Name $name
    write_vault_keys_or_exit -Keys $keys
    Write-Host "Unprotected secret: $name"
    Write-Host 'It is now readable by anything running as your Windows user.'
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
        # Overwriting a protected secret must stay protected. Without this, a
        # plain `set --force` would quietly downgrade it to plaintext while
        # `list` still advertised it as protected.
        $outgoing = $Value
        if (test_secret_currently_protected -SecretName $name) {
            $masterKey = unlock_vault_or_exit
            $wrapped = protect_secret_string -Value $Value -MasterKey $masterKey
            if (-not $wrapped.success) {
                Write-Host "ERROR: $($wrapped.error.message)" -ForegroundColor Red
                exit 1
            }
            $outgoing = $wrapped.data
            Write-Host 'Secret is protected; the new value was encrypted before storing.'
        }
        set_secret_value -Name $name -Value $outgoing -Force:$force
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
    if ($rest.Count -gt 1) {
        Write-Host "ERROR: Too many arguments for create. Quote values that contain spaces." -ForegroundColor Red
        exit 1
    }

    assert_secret_slot_available_or_exit

    # Value inline for one-liners; without it, fall back to the same
    # secure acquisition paths as `set`.
    $value = if ($rest.Count -eq 1) {
        [string]$rest[0]
    } elseif ($from_stdin) {
        read_secret_from_stdin
    } else {
        read_secret_from_secure_prompt -Name $name
    }

    store_secret_and_report -Value $value
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
    # The stored envelope prefix is the authority on whether a secret is
    # protected, but checking it would mean reading every value. The slot
    # file's list is display-only and costs no reads.
    $keys = $null
    if (-not (use_service_pipe)) {
        $keysResult = read_vault_keys
        if ($keysResult.success) { $keys = $keysResult.data }
    }

    foreach ($secretName in @($result.data)) {
        if ($null -ne $keys -and (test_secret_marked_protected -Keys $keys -Name $secretName)) {
            Write-Host "$secretName  [protected]"
        } else {
            Write-Host $secretName
        }
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

    # Keep the slot file's protected list from drifting once the secret it
    # names is gone; a stale entry would misreport `list` and block slot
    # removal for a secret that no longer exists.
    if (-not (use_service_pipe)) {
        $keysResult = read_vault_keys
        if ($keysResult.success -and $null -ne $keysResult.data -and
            (test_secret_marked_protected -Keys $keysResult.data -Name $name)) {
            $keys = unmark_secret_protected -Keys $keysResult.data -Name $name
            write_vault_keys_or_exit -Keys $keys
        }
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

    # expand_env_mappings splits comma-joined tokens: a raw command line
    # (NSSM AppParameters, powershell -File) has no array syntax, so
    # `-secret_env "A=a","B=b"` arrives here as the single token "A=a,B=b".
    $mappings = @(expand_env_mappings -Tokens $secret_env)
    $optionalMappings = @(expand_env_mappings -Tokens $secret_env_optional)
    if ($mappings.Count -eq 0 -and $optionalMappings.Count -eq 0) {
        Write-Host "ERROR: At least one --env or --env-optional ENV_VAR=secret_name mapping is required" -ForegroundColor Red
        exit 1
    }

    $resolved = resolve_secret_env_mappings `
        -Mappings $mappings `
        -OptionalMappings $optionalMappings `
        -ReadSecret {
            param($secretName)
            read_secret_plaintext -SecretName $secretName
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

    # An explicit --config must exist; the default proxy.json may be absent
    # (the daemon still watches the path and hot-loads it if it appears).
    $configPath = $config
    if ($configPath -and -not (Test-Path $configPath)) {
        Write-Host "ERROR: Proxy config not found: $configPath" -ForegroundColor Red
        exit 1
    }
    if (-not $configPath) { $configPath = Join-Path $scriptDir 'proxy.json' }

    if (Test-Path $configPath) {
        $loaded = load_proxy_config_file -Path $configPath -Defaults $providers
        if (-not $loaded.success) {
            Write-Host "ERROR: $($loaded.error.message)" -ForegroundColor Red
            exit 1
        }
        $providers = $loaded.data
        Write-Host "Loaded provider config: $configPath"
    }

    # Unlock before the listener starts. A prompt inside a request handler
    # would hang that request instead of asking anyone, so a daemon serving a
    # protected secret has to hold the master key from the outset. Prompting
    # is skipped entirely when no configured provider uses a protected secret.
    if (-not (use_service_pipe)) {
        $keys = read_vault_keys_or_exit
        if (test_vault_initialized -Keys $keys) {
            $protectedProviders = @()
            foreach ($providerName in @($providers.Keys)) {
                if (test_secret_marked_protected -Keys $keys -Name ([string]$providers[$providerName].secret)) {
                    $protectedProviders += $providerName
                }
            }
            if ($protectedProviders.Count -gt 0) {
                Write-Host "Protected secrets in use by: $($protectedProviders -join ', ')"
                [void](unlock_vault_or_exit)
                Write-Host 'Vault unlocked for this proxy session. It stays unlocked until the proxy stops.'
            }
        }
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
        -ConfigPath $configPath -DefaultProviders (get_default_providers) `
        -AdminPipeName $pipeName -AdminAllowedSid $pipeSid `
        -ReadSecret {
            param($secretName)
            read_secret_plaintext -SecretName $secretName
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
        'protect' { invoke_protect_command }
        'unprotect' { invoke_unprotect_command }
        'enroll' { invoke_enroll_command }
        'slots' { invoke_slots_command }
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
