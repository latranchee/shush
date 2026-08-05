$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\credential_store.psm1"
Import-Module $modulePath -Force

Describe "test_secret_name" {
    It "accepts lowercase names with numbers and underscores" {
        test_secret_name -Name "openai_api_key" | Should -Be $true
        test_secret_name -Name "github_token2" | Should -Be $true
    }

    It "rejects uppercase, hyphenated, empty, and digit-prefixed names" {
        test_secret_name -Name "OpenAI" | Should -Be $false
        test_secret_name -Name "openai-api-key" | Should -Be $false
        test_secret_name -Name "" | Should -Be $false
        test_secret_name -Name "1secret" | Should -Be $false
    }
}

Describe "get_secret_target" {
    It "builds the expected Credential Manager target" {
        get_secret_target -Name "openai_api_key" | Should -Be "windows-helper-scripts/secret_manager/openai_api_key"
    }

    It "throws for invalid names" {
        { get_secret_target -Name "bad-name" } | Should -Throw
    }
}

Describe "set_secret_value validation" {
    It "returns INVALID_NAME instead of throwing on bad name" {
        $result = set_secret_value -Name "Bad-Name" -Value "v" -Force
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_NAME'
    }

    It "returns EMPTY_VALUE on empty value" {
        $result = set_secret_value -Name "valid_name" -Value "" -Force
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'EMPTY_VALUE'
    }

    It "returns VALUE_TOO_LARGE when value exceeds 2560 bytes" {
        $large = "a" * 2000
        $result = set_secret_value -Name "valid_name" -Value $large -Force
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'VALUE_TOO_LARGE'
    }
}

Describe "get_secret_value validation" {
    It "returns INVALID_NAME instead of throwing on bad name" {
        $result = get_secret_value -Name "Bad-Name"
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_NAME'
    }
}

Describe "remove_secret_value validation" {
    It "returns INVALID_NAME instead of throwing on bad name" {
        $result = remove_secret_value -Name "Bad-Name"
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_NAME'
    }
}

Describe "query_secret_exists" {
    It "returns INVALID_NAME instead of throwing on bad name" {
        $result = query_secret_exists -Name "Bad-Name"
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_NAME'
    }

    It "reports exists=false (not error) when secret is missing" {
        $name = "nonexistent_$([guid]::NewGuid().ToString('N').Substring(0,16))"
        $result = query_secret_exists -Name $name
        $result.success | Should -Be $true
        $result.data.exists | Should -Be $false
    }
}

Describe "set/get/remove round trip with overwrite signal" {
    It "set then get returns the same value, set --force flags was_overwritten" {
        $name = "rt_$([guid]::NewGuid().ToString('N').Substring(0,16))"
        try {
            $first = set_secret_value -Name $name -Value "value-one"
            $first.success | Should -Be $true
            $first.data.was_overwritten | Should -Be $false

            $existsBlocked = set_secret_value -Name $name -Value "value-two"
            $existsBlocked.success | Should -Be $false
            $existsBlocked.error.code | Should -Be 'ALREADY_EXISTS'
            $existsBlocked.error.message | Should -Match 'force'

            $overwrite = set_secret_value -Name $name -Value "value-two" -Force
            $overwrite.success | Should -Be $true
            $overwrite.data.was_overwritten | Should -Be $true

            $get = get_secret_value -Name $name
            $get.success | Should -Be $true
            $get.data | Should -Be "value-two"
        }
        finally {
            [void](remove_secret_value -Name $name)
        }
    }
}

Describe "format_win32_error" {
    It "returns a human-readable string including the code" {
        (format_win32_error -Code 1168) | Should -Match '1168'
    }
}
