$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\process_runner.psm1"
Import-Module $modulePath -Force

Describe "parse_secret_env_mapping" {
    It "parses valid env mappings" {
        $result = parse_secret_env_mapping -Mapping "OPENAI_API_KEY=openai_api_key"
        $result.success | Should -Be $true
        $result.data.env_var | Should -Be "OPENAI_API_KEY"
        $result.data.secret_name | Should -Be "openai_api_key"
    }

    It "rejects malformed mappings" {
        (parse_secret_env_mapping -Mapping "OPENAI_API_KEY").success | Should -Be $false
        (parse_secret_env_mapping -Mapping "OPENAI_API_KEY=BadName").success | Should -Be $false
        (parse_secret_env_mapping -Mapping "1BAD=openai_api_key").success | Should -Be $false
    }

    It "diagnoses which side is malformed" {
        $missingEq = parse_secret_env_mapping -Mapping "OPENAI_API_KEY"
        $missingEq.error.message | Should -Match "missing '=' separator"

        $badEnv = parse_secret_env_mapping -Mapping "1BAD=openai_api_key"
        $badEnv.error.message | Should -Match "env-var name"

        $badSecret = parse_secret_env_mapping -Mapping "OPENAI_API_KEY=BadName"
        $badSecret.error.message | Should -Match "secret name"
    }
}

Describe "resolve_secret_env_mappings" {
    It "returns resolved environment values" {
        $result = resolve_secret_env_mappings `
            -Mappings @("OPENAI_API_KEY=openai_api_key") `
            -ReadSecret { param($name) @{ success = $true; data = "secret-for-$name"; error = $null } }

        $result.success | Should -Be $true
        $result.data.OPENAI_API_KEY | Should -Be "secret-for-openai_api_key"
    }

    It "returns a not-found result before launch when a required secret is missing" {
        $result = resolve_secret_env_mappings `
            -Mappings @("OPENAI_API_KEY=missing_secret") `
            -ReadSecret { param($name) @{ success = $false; data = $null; error = @{ code = "NOT_FOUND"; message = "missing" } } }

        $result.success | Should -Be $false
        $result.error.code | Should -Be "NOT_FOUND"
    }

    It "skips missing optional mappings and reports them" {
        $result = resolve_secret_env_mappings `
            -OptionalMappings @("SCREEN_ARCHIVE_TOKEN=screen_archive_token") `
            -ReadSecret { param($name) @{ success = $false; data = $null; error = @{ code = "NOT_FOUND"; message = "missing" } } }

        $result.success | Should -Be $true
        $result.data.ContainsKey("SCREEN_ARCHIVE_TOKEN") | Should -Be $false
        @($result.missing_optional).Count | Should -Be 1
        $result.missing_optional[0].env_var | Should -Be "SCREEN_ARCHIVE_TOKEN"
        $result.missing_optional[0].secret_name | Should -Be "screen_archive_token"
    }

    It "resolves present optional mappings into the env hashtable" {
        $result = resolve_secret_env_mappings `
            -OptionalMappings @("SCREEN_ARCHIVE_TOKEN=screen_archive_token") `
            -ReadSecret { param($name) @{ success = $true; data = "sa_pk_xyz"; error = $null } }

        $result.success | Should -Be $true
        $result.data.SCREEN_ARCHIVE_TOKEN | Should -Be "sa_pk_xyz"
        @($result.missing_optional).Count | Should -Be 0
    }

    It "still aborts when a required mapping fails even if optional ones are fine" {
        $result = resolve_secret_env_mappings `
            -Mappings @("REQ=required_secret") `
            -OptionalMappings @("OPT=optional_secret") `
            -ReadSecret {
                param($name)
                if ($name -eq 'required_secret') {
                    return @{ success = $false; data = $null; error = @{ code = "NOT_FOUND"; message = "missing" } }
                }
                return @{ success = $true; data = "ok"; error = $null }
            }

        $result.success | Should -Be $false
        $result.error.code | Should -Be "NOT_FOUND"
    }

    It "collects ALL missing required secrets in one report" {
        $result = resolve_secret_env_mappings `
            -Mappings @("A=missing_a", "B=missing_b") `
            -ReadSecret { param($name) @{ success = $false; data = $null; error = @{ code = "NOT_FOUND"; message = "missing" } } }

        $result.success | Should -Be $false
        $result.error.code | Should -Be "NOT_FOUND"
        $result.error.message | Should -Match "missing_a"
        $result.error.message | Should -Match "missing_b"
    }

    It "rejects duplicate env vars (case-insensitive)" {
        $result = resolve_secret_env_mappings `
            -Mappings @("Foo=secret_a", "FOO=secret_b") `
            -ReadSecret { param($name) @{ success = $true; data = "v"; error = $null } }

        $result.success | Should -Be $false
        $result.error.code | Should -Be "INVALID_ENV_MAPPING"
        $result.error.message | Should -Match "Duplicate"
    }
}

Describe "quote_native_argument" {
    It "wraps the empty string as two-character literal" {
        quote_native_argument -Argument "" | Should -Be '""'
    }

    It "returns simple unescaped values verbatim" {
        quote_native_argument -Argument "hello" | Should -Be "hello"
    }

    It "rejects NUL/CR/LF" {
        { quote_native_argument -Argument "abc`ndef" } | Should -Throw
        { quote_native_argument -Argument "abc`rdef" } | Should -Throw
        { quote_native_argument -Argument "abc`0def" } | Should -Throw
    }

    It "quotes values with spaces" {
        quote_native_argument -Argument "hello world" | Should -Be '"hello world"'
    }
}

Describe "invoke_secret_process default Environment" {
    It "accepts default Environment without throwing on cast" {
        $result = invoke_secret_process -FilePath '' -ArgumentList @()
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_PARAMS'
    }
}

Describe "expand_env_mappings" {
    It "passes through distinct tokens unchanged" {
        $result = @(expand_env_mappings -Tokens @('A=a', 'B=b'))
        $result | Should -Be @('A=a', 'B=b')
    }

    It "splits a comma-joined token as produced by a raw -File command line" {
        $result = @(expand_env_mappings -Tokens @('A=a,B=b,C=c'))
        $result | Should -Be @('A=a', 'B=b', 'C=c')
    }

    It "splits comma-joined fragments inside a mixed token list" {
        $result = @(expand_env_mappings -Tokens @('A=a,B=b', 'C=c'))
        $result | Should -Be @('A=a', 'B=b', 'C=c')
    }

    It "drops blank fragments and trims whitespace" {
        $result = @(expand_env_mappings -Tokens @('A=a, B=b,', '', $null))
        $result | Should -Be @('A=a', 'B=b')
    }

    It "returns an empty array for empty or null input" {
        @(expand_env_mappings -Tokens @()).Count | Should -Be 0
        @(expand_env_mappings).Count | Should -Be 0
    }
}
