$modulesPath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules"
Import-Module (Join-Path $modulesPath "vault_crypto.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "vault_keyslots.psm1") -Force -DisableNameChecking
Import-Module (Join-Path $modulesPath "factor_keyfile.psm1") -Force -DisableNameChecking

# Bound-passphrase tests pass -Iterations 1000 as a literal on purpose. A
# $script: variable set in a file-level BeforeAll reaches a Describe-level
# BeforeAll but NOT the It blocks below, where it arrives as $null, silently
# falls back to the full 600k iterations, and turns a 1-second file into a
# 13-second one.
BeforeAll {
    # A temp directory stands in for the thumbdrive. SHUSH_KEYFILE is the
    # documented override and makes the whole factor testable without one.

    function new_test_keyfile_path {
        return (Join-Path ([System.IO.Path]::GetTempPath()) "shush_keyfile_test_$([guid]::NewGuid().ToString('n')).key")
    }
}

Describe "write_keyfile / read_keyfile" {
    It "writes a keyfile that reads back" {
        $path = new_test_keyfile_path
        try {
            $written = write_keyfile -Path $path
            $written.success | Should -Be $true
            $written.data.key.Length | Should -Be 32

            $read = read_keyfile -Path $path
            $read.success | Should -Be $true
            $read.data.id | Should -Be $written.data.id
            [Convert]::ToBase64String($read.data.key) | Should -Be ([Convert]::ToBase64String($written.data.key))
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "gives every keyfile a distinct id and key" {
        $first = new_test_keyfile_path
        $second = new_test_keyfile_path
        try {
            $a = write_keyfile -Path $first
            $b = write_keyfile -Path $second
            $a.data.id | Should -Not -Be $b.data.id
            [Convert]::ToBase64String($a.data.key) | Should -Not -Be ([Convert]::ToBase64String($b.data.key))
        } finally {
            foreach ($p in @($first, $second)) { if (Test-Path $p) { Remove-Item $p -Force } }
        }
    }

    It "refuses to clobber an existing keyfile without force" {
        $path = new_test_keyfile_path
        try {
            [void](write_keyfile -Path $path)
            $second = write_keyfile -Path $path
            $second.success | Should -Be $false
            $second.error.code | Should -Be 'KEYFILE_EXISTS'
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "reports a missing keyfile" {
        $read = read_keyfile -Path (new_test_keyfile_path)
        $read.success | Should -Be $false
        $read.error.code | Should -Be 'KEYFILE_NOT_FOUND'
    }

    It "rejects a file that is not a shush keyfile" {
        $path = new_test_keyfile_path
        try {
            Set-Content -Path $path -Value 'just some file' -Encoding ASCII
            $read = read_keyfile -Path $path
            $read.success | Should -Be $false
            $read.error.code | Should -Be 'KEYFILE_MALFORMED'
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "rejects a keyfile whose key is the wrong length" {
        $path = new_test_keyfile_path
        try {
            Set-Content -Path $path -Encoding ASCII -Value @(
                'shush-keyfile-v1'
                'id=abc123'
                "key=$([Convert]::ToBase64String([byte[]](1, 2, 3)))"
            )
            $read = read_keyfile -Path $path
            $read.success | Should -Be $false
            $read.error.code | Should -Be 'KEYFILE_MALFORMED'
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }
}

Describe "keyfile key slots" {
    It "round-trips the master key with the file present" {
        $path = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $path -Label 'thumbdrive'
            $built.success | Should -Be $true
            $built.data.uses_passphrase | Should -Be $false

            $opened = open_keyfile_slot -Slot $built.data -Path $path
            $opened.success | Should -Be $true
            [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($master))
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "does not store the master key or the keyfile key in the slot" {
        $path = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $path
            $keyMaterial = (read_keyfile -Path $path).data.key
            $built.data.wrapped_key | Should -Not -Match ([regex]::Escape([Convert]::ToBase64String($master)))
            $built.data.wrapped_key | Should -Not -Match ([regex]::Escape([Convert]::ToBase64String($keyMaterial)))
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "refuses to unlock when the keyfile is gone" {
        $path = new_test_keyfile_path
        $master = new_master_key
        $built = build_keyfile_slot -MasterKey $master -Path $path
        Remove-Item $path -Force

        $opened = open_keyfile_slot -Slot $built.data -Path $path
        $opened.success | Should -Be $false
        $opened.error.code | Should -Be 'KEYFILE_NOT_PRESENT'
    }

    It "refuses a different keyfile" {
        $path = new_test_keyfile_path
        $impostor = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $path
            [void](write_keyfile -Path $impostor)

            $opened = open_keyfile_slot -Slot $built.data -Path $impostor
            $opened.success | Should -Be $false
            $opened.error.code | Should -Be 'KEYFILE_NOT_PRESENT'
        } finally {
            foreach ($p in @($path, $impostor)) { if (Test-Path $p) { Remove-Item $p -Force } }
        }
    }

    It "finds the keyfile by id when the path has changed" {
        # The drive-letter case: same file, different location.
        $original = new_test_keyfile_path
        $moved = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $original
            Move-Item -Path $original -Destination $moved

            $opened = open_keyfile_slot -Slot $built.data -Path $moved
            $opened.success | Should -Be $true
            [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($master))
        } finally {
            foreach ($p in @($original, $moved)) { if (Test-Path $p) { Remove-Item $p -Force } }
        }
    }

    It "finds the keyfile through the SHUSH_KEYFILE override" {
        $path = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $path
            $env:SHUSH_KEYFILE = $path

            $opened = open_keyfile_slot -Slot $built.data
            $opened.success | Should -Be $true
            [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($master))
        } finally {
            Remove-Item env:SHUSH_KEYFILE -ErrorAction SilentlyContinue
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "reuses an existing keyfile rather than replacing it" {
        # One drive should be able to unlock several machines' vaults.
        $path = new_test_keyfile_path
        try {
            $first = build_keyfile_slot -MasterKey (new_master_key) -Path $path
            $second = build_keyfile_slot -MasterKey (new_master_key) -Path $path
            $second.data.keyfile_id | Should -Be $first.data.keyfile_id
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }
}

Describe "keyfile bound to a passphrase" {
    It "requires both the file and the passphrase" {
        $path = new_test_keyfile_path
        try {
            $master = new_master_key
            $built = build_keyfile_slot -MasterKey $master -Path $path -Passphrase 'both factors' -Iterations 1000
            $built.data.uses_passphrase | Should -Be $true

            $opened = open_keyfile_slot -Slot $built.data -Path $path -Passphrase 'both factors'
            $opened.success | Should -Be $true
            [Convert]::ToBase64String($opened.data) | Should -Be ([Convert]::ToBase64String($master))
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "refuses the file alone" {
        $path = new_test_keyfile_path
        try {
            $built = build_keyfile_slot -MasterKey (new_master_key) -Path $path -Passphrase 'both factors' -Iterations 1000
            $opened = open_keyfile_slot -Slot $built.data -Path $path
            $opened.success | Should -Be $false
            $opened.error.code | Should -Be 'UNLOCK_FAILED'
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }

    It "refuses a wrong passphrase" {
        $path = new_test_keyfile_path
        try {
            $built = build_keyfile_slot -MasterKey (new_master_key) -Path $path -Passphrase 'both factors' -Iterations 1000
            $opened = open_keyfile_slot -Slot $built.data -Path $path -Passphrase 'wrong'
            $opened.success | Should -Be $false
            $opened.error.code | Should -Be 'UNLOCK_FAILED'
        } finally {
            if (Test-Path $path) { Remove-Item $path -Force }
        }
    }
}

Describe "derive_keyfile_kek" {
    It "is deterministic for the same key bytes" {
        $bytes = new_random_bytes -Count 32
        $first = derive_keyfile_kek -KeyBytes $bytes
        $second = derive_keyfile_kek -KeyBytes $bytes
        [Convert]::ToBase64String($first.data) | Should -Be ([Convert]::ToBase64String($second.data))
        $first.data.Length | Should -Be 32
    }

    It "differs once a passphrase is bound" {
        $bytes = new_random_bytes -Count 32
        $salt = new_random_bytes -Count 16
        $plain = derive_keyfile_kek -KeyBytes $bytes
        $bound = derive_keyfile_kek -KeyBytes $bytes -Passphrase 'p' -Salt $salt -Iterations 1000
        [Convert]::ToBase64String($plain.data) | Should -Not -Be ([Convert]::ToBase64String($bound.data))
    }
}
