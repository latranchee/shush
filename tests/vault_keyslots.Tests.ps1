$modulesPath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules"
Import-Module (Join-Path $modulesPath "vault_crypto.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "vault_keyslots.psm1") -Force -DisableNameChecking

# Slot tests use a low iteration count: PBKDF2 cost is the point in
# production and pure overhead in a unit test. This has to live in a
# file-level BeforeAll - Pester 5 does not carry plain top-level script
# variables into It blocks, and a $null here silently falls back to the full
# 600k iterations, turning a 3-second suite into a 30-second one.
BeforeAll {
    $script:testIterations = 1000
}

Describe "passphrase key slots" {
    BeforeAll {
        $script:masterKey = new_master_key
        $script:slot = (build_passphrase_slot -Passphrase 'open sesame' -MasterKey $script:masterKey `
            -Label 'test' -Iterations $script:testIterations).data
    }

    It "wraps the master key without storing it" {
        $script:slot.wrapped_key | Should -Not -BeNullOrEmpty
        $script:slot.wrapped_key | Should -Not -Match ([regex]::Escape([Convert]::ToBase64String($script:masterKey)))
    }

    It "recovers exactly the same master key" {
        $opened = open_passphrase_slot -Slot $script:slot -Passphrase 'open sesame'
        $opened.success | Should -Be $true
        [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($script:masterKey))
    }

    It "refuses a wrong passphrase" {
        $opened = open_passphrase_slot -Slot $script:slot -Passphrase 'wrong'
        $opened.success | Should -Be $false
        $opened.error.code | Should -Be 'UNLOCK_FAILED'
    }

    It "refuses an empty passphrase at enrollment" {
        $built = build_passphrase_slot -Passphrase '' -MasterKey $script:masterKey -Iterations $script:testIterations
        $built.success | Should -Be $false
        $built.error.code | Should -Be 'EMPTY_PASSPHRASE'
    }

    It "gives every slot a distinct salt" {
        $other = (build_passphrase_slot -Passphrase 'open sesame' -MasterKey $script:masterKey `
            -Iterations $script:testIterations).data
        $other.kdf_salt | Should -Not -Be $script:slot.kdf_salt
        $other.wrapped_key | Should -Not -Be $script:slot.wrapped_key
    }

    It "lets several factors open the one master key" {
        # This is what makes a lost YubiKey survivable: any enrolled slot
        # reaches the same master key.
        $backup = (build_passphrase_slot -Passphrase 'backup phrase' -MasterKey $script:masterKey `
            -Iterations $script:testIterations).data
        $viaFirst = open_passphrase_slot -Slot $script:slot -Passphrase 'open sesame'
        $viaBackup = open_passphrase_slot -Slot $backup -Passphrase 'backup phrase'
        [Convert]::ToBase64String($viaBackup.data) | Should -Be ([Convert]::ToBase64String($viaFirst.data))
    }
}

Describe "slot file persistence" {
    BeforeEach {
        $script:keyPath = Join-Path ([System.IO.Path]::GetTempPath()) "shush_slots_test_$([guid]::NewGuid().ToString('n')).json"
        $env:SHUSH_VAULT_KEYS = $script:keyPath
    }

    AfterEach {
        if (Test-Path $script:keyPath) { Remove-Item $script:keyPath -Force }
        Remove-Item env:SHUSH_VAULT_KEYS -ErrorAction SilentlyContinue
    }

    It "reports no vault before anything is enrolled" {
        $keys = (read_vault_keys).data
        $keys | Should -Be $null
        test_vault_initialized -Keys $keys | Should -Be $false
    }

    It "round-trips slots through the file" {
        $master = new_master_key
        $keys = new_vault_keys
        $slot = (build_passphrase_slot -Passphrase 'p' -MasterKey $master -Iterations $script:testIterations).data
        $keys = add_key_slot -Keys $keys -Slot $slot
        (write_vault_keys -Keys $keys).success | Should -Be $true

        $reloaded = (read_vault_keys).data
        test_vault_initialized -Keys $reloaded | Should -Be $true
        @($reloaded.slots).Count | Should -Be 1
        $opened = open_passphrase_slot -Slot $reloaded.slots[0] -Passphrase 'p'
        [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($master))
    }

    It "tracks which secrets are protected" {
        $keys = new_vault_keys
        $keys = mark_secret_protected -Keys $keys -Name 'openai_api_key'
        $keys = mark_secret_protected -Keys $keys -Name 'openai_api_key'
        @($keys.protected).Count | Should -Be 1
        test_secret_marked_protected -Keys $keys -Name 'openai_api_key' | Should -Be $true

        $keys = unmark_secret_protected -Keys $keys -Name 'openai_api_key'
        test_secret_marked_protected -Keys $keys -Name 'openai_api_key' | Should -Be $false
    }

    It "reports an unreadable slot file instead of throwing" {
        Set-Content -Path $script:keyPath -Value 'this is not json' -Encoding UTF8
        $result = read_vault_keys
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'KEYS_UNREADABLE'
    }
}

Describe "remove_key_slot" {
    It "removes a slot by id" {
        $master = new_master_key
        $keys = new_vault_keys
        $first = (build_passphrase_slot -Passphrase 'a' -MasterKey $master -Iterations $script:testIterations).data
        $second = (build_passphrase_slot -Passphrase 'b' -MasterKey $master -Iterations $script:testIterations).data
        $keys = add_key_slot -Keys $keys -Slot $first
        $keys = add_key_slot -Keys $keys -Slot $second

        $removed = remove_key_slot -Keys $keys -SlotId $first.id
        $removed.success | Should -Be $true
        @($keys.slots).Count | Should -Be 1
    }

    It "reports an unknown slot id" {
        $keys = new_vault_keys
        $removed = remove_key_slot -Keys $keys -SlotId 'nope'
        $removed.success | Should -Be $false
        $removed.error.code | Should -Be 'SLOT_NOT_FOUND'
    }

    It "refuses to orphan protected secrets by removing the last slot" {
        $master = new_master_key
        $keys = new_vault_keys
        $only = (build_passphrase_slot -Passphrase 'a' -MasterKey $master -Iterations $script:testIterations).data
        $keys = add_key_slot -Keys $keys -Slot $only
        $keys = mark_secret_protected -Keys $keys -Name 'openai_api_key'

        $removed = remove_key_slot -Keys $keys -SlotId $only.id
        $removed.success | Should -Be $false
        $removed.error.code | Should -Be 'LAST_SLOT'
        @($keys.slots).Count | Should -Be 1
    }

    It "allows removing the last slot when nothing is protected" {
        $master = new_master_key
        $keys = new_vault_keys
        $only = (build_passphrase_slot -Passphrase 'a' -MasterKey $master -Iterations $script:testIterations).data
        $keys = add_key_slot -Keys $keys -Slot $only

        $removed = remove_key_slot -Keys $keys -SlotId $only.id
        $removed.success | Should -Be $true
        @($keys.slots).Count | Should -Be 0
    }
}
