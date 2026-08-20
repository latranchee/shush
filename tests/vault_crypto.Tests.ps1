$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\vault_crypto.psm1"
Import-Module $modulePath -Force -DisableNameChecking

Describe "protect_secret_string / unprotect_secret_string" {
    BeforeAll {
        $script:key = new_random_bytes -Count 32
    }

    It "round-trips a value" {
        $wrapped = protect_secret_string -Value "sk-abc123" -MasterKey $script:key
        $wrapped.success | Should -Be $true
        $opened = unprotect_secret_string -Value $wrapped.data -MasterKey $script:key
        $opened.data | Should -Be "sk-abc123"
    }

    It "round-trips non-ASCII values" {
        $value = [char]0x00E9 + "-key-" + [char]0x4E2D
        $wrapped = protect_secret_string -Value $value -MasterKey $script:key
        $opened = unprotect_secret_string -Value $wrapped.data -MasterKey $script:key
        $opened.data | Should -Be $value
    }

    It "tags stored values with the envelope prefix" {
        $wrapped = protect_secret_string -Value "v" -MasterKey $script:key
        $wrapped.data.StartsWith('shush.v1:') | Should -Be $true
        test_protected_value -Value $wrapped.data | Should -Be $true
    }

    It "produces different ciphertext for the same input" {
        $first = protect_secret_string -Value "same" -MasterKey $script:key
        $second = protect_secret_string -Value "same" -MasterKey $script:key
        $first.data | Should -Not -Be $second.data
    }

    It "rejects a wrong key without leaking why" {
        $wrapped = protect_secret_string -Value "sk-abc123" -MasterKey $script:key
        $other = new_random_bytes -Count 32
        $opened = unprotect_secret_string -Value $wrapped.data -MasterKey $other
        $opened.success | Should -Be $false
        $opened.error.code | Should -Be 'AUTH_FAILED'
        $opened.error.message | Should -Not -Match 'sk-abc123'
    }

    It "detects tampering with the ciphertext" {
        $wrapped = protect_secret_string -Value "sk-abc123" -MasterKey $script:key
        $characters = $wrapped.data.ToCharArray()
        $characters[30] = if ($characters[30] -eq 'A') { 'B' } else { 'A' }
        $opened = unprotect_secret_string -Value (-join $characters) -MasterKey $script:key
        $opened.success | Should -Be $false
        $opened.error.code | Should -Be 'AUTH_FAILED'
    }

    It "passes legacy plaintext values through untouched" {
        $opened = unprotect_secret_string -Value 'plain-old-secret' -MasterKey $script:key
        $opened.success | Should -Be $true
        $opened.data | Should -Be 'plain-old-secret'
    }

    It "refuses values too large to fit the credential blob" {
        $tooBig = 'a' * ((get_max_protected_plaintext_bytes) + 1)
        $wrapped = protect_secret_string -Value $tooBig -MasterKey $script:key
        $wrapped.success | Should -Be $false
        $wrapped.error.code | Should -Be 'VALUE_TOO_LARGE_PROTECTED'
    }

    It "keeps the largest allowed value within the 2560-byte blob ceiling" {
        $largest = 'a' * (get_max_protected_plaintext_bytes)
        $wrapped = protect_secret_string -Value $largest -MasterKey $script:key
        $wrapped.success | Should -Be $true
        # Stored as UTF-16 by credential_store, so two bytes per character.
        ($wrapped.data.Length * 2) | Should -BeLessOrEqual 2560
    }

    It "rejects a malformed envelope instead of throwing" {
        $opened = unprotect_secret_string -Value 'shush.v1:not-base64!!' -MasterKey $script:key
        $opened.success | Should -Be $false
        $opened.error.code | Should -Be 'MALFORMED_ENVELOPE'
    }

    It "rejects a key of the wrong length" {
        $result = protect_bytes -Plaintext ([byte[]](1, 2, 3)) -MasterKey ([byte[]](1, 2, 3))
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'BAD_KEY'
    }
}

Describe "derive_key_from_passphrase" {
    It "is deterministic for the same passphrase and salt" {
        $salt = new_random_bytes -Count 16
        $first = derive_key_from_passphrase -Passphrase 'hunter2' -Salt $salt -Iterations 1000
        $second = derive_key_from_passphrase -Passphrase 'hunter2' -Salt $salt -Iterations 1000
        [Convert]::ToBase64String($first.data) | Should -Be ([Convert]::ToBase64String($second.data))
        $first.data.Length | Should -Be 32
    }

    It "produces a different key for a different salt" {
        $first = derive_key_from_passphrase -Passphrase 'hunter2' -Salt (new_random_bytes -Count 16) -Iterations 1000
        $second = derive_key_from_passphrase -Passphrase 'hunter2' -Salt (new_random_bytes -Count 16) -Iterations 1000
        [Convert]::ToBase64String($first.data) | Should -Not -Be ([Convert]::ToBase64String($second.data))
    }
}

Describe "derive_subkey" {
    It "gives encryption and authentication distinct keys" {
        $master = new_random_bytes -Count 32
        $encryption = derive_subkey -MasterKey $master -Label 'shush-enc-v1'
        $authentication = derive_subkey -MasterKey $master -Label 'shush-mac-v1'
        [Convert]::ToBase64String($encryption) | Should -Not -Be ([Convert]::ToBase64String($authentication))
    }
}

Describe "compare_bytes_constant_time" {
    It "matches equal arrays" {
        compare_bytes_constant_time -Left ([byte[]](1, 2, 3)) -Right ([byte[]](1, 2, 3)) | Should -Be $true
    }

    It "rejects differing arrays" {
        compare_bytes_constant_time -Left ([byte[]](1, 2, 3)) -Right ([byte[]](1, 2, 4)) | Should -Be $false
    }

    It "rejects arrays of different lengths" {
        compare_bytes_constant_time -Left ([byte[]](1, 2, 3)) -Right ([byte[]](1, 2)) | Should -Be $false
    }

    It "rejects null input" {
        compare_bytes_constant_time -Left $null -Right ([byte[]](1)) | Should -Be $false
    }
}
