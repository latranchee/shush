BeforeAll {
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'modules\vault_backup.psm1') -Force -DisableNameChecking
    Import-Module (Join-Path (Split-Path $PSScriptRoot -Parent) 'modules\vault_crypto.psm1') -DisableNameChecking
    $script:pass = 'test-only archive passphrase'
    $script:records = @(@{ name = 'test_alpha'; value = ('unicode-' + [char]0x4E2D) }, @{ name = 'test_beta'; value = 'second-value' })
    $script:sealed = protect_backup_archive -Records $script:records -Passphrase $script:pass
}

Describe 'Portable backup archives' {
    It 'round trips multiple Unicode records' {
        $script:sealed.success | Should -BeTrue
        $opened = unprotect_backup_archive -Archive $script:sealed.data -Passphrase $script:pass
        $opened.success | Should -BeTrue
        $opened.data.Count | Should -Be 2
        $opened.data[0].value | Should -Be $script:records[0].value
    }
    It 'does not expose names or values in the archive' {
        $text = [Text.Encoding]::UTF8.GetString($script:sealed.data)
        $text | Should -Not -Match 'test_alpha|second-value|unicode'
    }
    It 'uses fresh salt and IV for each archive' {
        $other = protect_backup_archive -Records $script:records -Passphrase $script:pass
        [Convert]::ToBase64String($other.data) | Should -Not -Be ([Convert]::ToBase64String($script:sealed.data))
    }
    It 'rejects a wrong passphrase' {
        $result = unprotect_backup_archive -Archive $script:sealed.data -Passphrase 'wrong password'
        $result.error.code | Should -Be 'AUTH_FAILED'
        $result.data | Should -BeNullOrEmpty
    }
    It 'rejects changes to salt, IV, ciphertext, and MAC' {
        foreach ($index in @(9, 42, 60, ($script:sealed.data.Length - 1))) {
            $copy = $script:sealed.data.Clone()
            $copy[$index] = $copy[$index] -bxor 1
            (unprotect_backup_archive -Archive $copy -Passphrase $script:pass).success | Should -BeFalse
        }
    }
    It 'rejects truncation and unknown archive versions' {
        (unprotect_backup_archive -Archive ([byte[]](1, 2)) -Passphrase $script:pass).error.code | Should -Be 'INVALID_ARCHIVE'
        $copy = $script:sealed.data.Clone()
        $copy[8] = [byte][char]'2'
        (unprotect_backup_archive -Archive $copy -Passphrase $script:pass).error.code | Should -Be 'INVALID_ARCHIVE'
    }
    It 'rejects oversized files before deriving keys' {
        (unprotect_backup_archive -Archive (New-Object byte[] (8MB + 1)) -Passphrase $script:pass).error.code | Should -Be 'INVALID_ARCHIVE'
    }
    It 'refuses weak passphrases' {
        (protect_backup_archive -Records $script:records -Passphrase 'short').error.code | Should -Be 'WEAK_PASSPHRASE'
    }
    It 'handles single and empty arrays without scalar collapse' {
        foreach ($records in @(@(), @(@{ name = 'one'; value = 'one-value' }))) {
            $sealed = protect_backup_archive -Records $records -Passphrase $script:pass
            $opened = unprotect_backup_archive -Archive $sealed.data -Passphrase $script:pass
            $opened.success | Should -BeTrue
            @($opened.data).Count | Should -Be @($records).Count
        }
    }
    It 'rejects duplicates, invalid names, nonstrings, and overlong values' {
        $invalid = @(
            @(@{ name = 'same'; value = 'a' }, @{ name = 'same'; value = 'b' }),
            @(@{ name = 'Uppercase'; value = 'a' }),
            @(@{ name = "newline`n"; value = 'a' }),
            @(@{ name = 'one'; value = 42 }),
            @(@{ name = 'one'; value = ('x' * 1281) }),
            @(@{ name = 'one' }),
            @(@{ name = 'one'; value = '' })
        )
        foreach ($records in $invalid) {
            (test_backup_records -Records $records).error.code | Should -Be 'INVALID_RECORDS'
        }
    }
    It 'accepts the Windows credential size boundary' {
        (test_backup_records -Records @(@{ name = 'one'; value = ('x' * 1280) })).success | Should -BeTrue
    }
    It 'refuses protected local credentials' {
        (protect_backup_archive -Records @(@{ name = 'one'; value = 'shush.v1:wrapped' }) -Passphrase $script:pass).error.code | Should -Be 'PROTECTED_SECRET'
    }
    It 'sanitizes authenticated but malformed payload errors' {
        $salt = new_random_bytes -Count 32
        $key = derive_key_from_passphrase -Passphrase $script:pass -Salt $salt -Iterations 600000
        try {
            $payload = protect_bytes -Plaintext ([Text.Encoding]::UTF8.GetBytes('invalid-json-SECRET-SENTINEL')) -MasterKey $key.data
            $archive = [byte[]]([Text.Encoding]::ASCII.GetBytes('SHUSHBAK1') + $salt + $payload.data)
            $result = unprotect_backup_archive -Archive $archive -Passphrase $script:pass
            $result.success | Should -BeFalse
            ($result | ConvertTo-Json) | Should -Not -Match 'SECRET-SENTINEL'
        } finally { clear_bytes $key.data }
    }
}
