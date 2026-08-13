$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\proxy_server.psm1"
Import-Module $modulePath -Force

Describe "test_provider_base_url" {
    It "accepts https hosts" {
        test_provider_base_url -BaseUrl "https://api.openai.com" | Should -Be $true
        test_provider_base_url -BaseUrl "https://api.example.com:8443" | Should -Be $true
    }

    It "accepts plain http only for loopback" {
        test_provider_base_url -BaseUrl "http://127.0.0.1:9999" | Should -Be $true
        test_provider_base_url -BaseUrl "http://localhost:9999" | Should -Be $true
        test_provider_base_url -BaseUrl "http://evil.example.com" | Should -Be $false
    }

    It "rejects URLs with paths, empty values, and other schemes" {
        test_provider_base_url -BaseUrl "https://api.openai.com/v1" | Should -Be $false
        test_provider_base_url -BaseUrl "" | Should -Be $false
        test_provider_base_url -BaseUrl "ftp://api.openai.com" | Should -Be $false
    }
}

Describe "parse_proxy_config" {
    It "parses a valid provider config" {
        $json = '{"providers":{"openai":{"secret":"openai_api_key","auth":"bearer","base_url":"https://api.openai.com/"}}}'
        $result = parse_proxy_config -Json $json
        $result.success | Should -Be $true
        $result.data.openai.secret | Should -Be "openai_api_key"
        $result.data.openai.base_url | Should -Be "https://api.openai.com"
        $result.data.openai.allow_methods | Should -Be @('GET', 'POST')
    }

    It "rejects invalid JSON, empty config, and missing providers" {
        (parse_proxy_config -Json 'not json').success | Should -Be $false
        (parse_proxy_config -Json '').success | Should -Be $false
        (parse_proxy_config -Json '{"nope":1}').error.code | Should -Be 'INVALID_CONFIG'
    }

    It "rejects invalid auth modes, secret names, and base URLs" {
        (parse_proxy_config -Json '{"providers":{"p":{"secret":"s_key","auth":"cookie","base_url":"https://x.com"}}}').success | Should -Be $false
        (parse_proxy_config -Json '{"providers":{"p":{"secret":"Bad-Name","auth":"bearer","base_url":"https://x.com"}}}').success | Should -Be $false
        (parse_proxy_config -Json '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"http://x.com"}}}').success | Should -Be $false
    }

    It "honors allow_methods and rejects unknown methods" {
        $json = '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"https://x.com","allow_methods":["get","delete"]}}}'
        $result = parse_proxy_config -Json $json
        $result.success | Should -Be $true
        $result.data.p.allow_methods | Should -Be @('GET', 'DELETE')

        (parse_proxy_config -Json '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"https://x.com","allow_methods":["TRACE"]}}}').success | Should -Be $false
    }

    It "parses auth_passthrough_paths and rejects invalid regexes" {
        $json = '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"https://x.com","auth_passthrough_paths":["^/v4/accounts/[0-9a-f]{32}/workers/assets/upload$"]}}}'
        $result = parse_proxy_config -Json $json
        $result.success | Should -Be $true
        $result.data.p.auth_passthrough_paths | Should -Be @('^/v4/accounts/[0-9a-f]{32}/workers/assets/upload$')

        $noField = parse_proxy_config -Json '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"https://x.com"}}}'
        @($noField.data.p.auth_passthrough_paths).Count | Should -Be 0

        (parse_proxy_config -Json '{"providers":{"p":{"secret":"s_key","auth":"bearer","base_url":"https://x.com","auth_passthrough_paths":["[unclosed"]}}}').error.code | Should -Be 'INVALID_CONFIG'
    }
}

Describe "merge_provider_maps" {
    It "overlays overrides on defaults" {
        $defaults = @{ a = @{ base_url = 'https://a.com' }; b = @{ base_url = 'https://b.com' } }
        $overrides = @{ b = @{ base_url = 'https://b2.com' }; c = @{ base_url = 'https://c.com' } }
        $merged = merge_provider_maps -Defaults $defaults -Overrides $overrides
        $merged.Keys.Count | Should -Be 3
        $merged.b.base_url | Should -Be 'https://b2.com'
        $merged.a.base_url | Should -Be 'https://a.com'
    }
}

Describe "get_proxy_config_stamp" {
    It "returns empty for a missing file" {
        get_proxy_config_stamp -Path (Join-Path $TestDrive 'nope.json') | Should -Be ''
    }

    It "changes when the file content changes" {
        $path = Join-Path $TestDrive 'stamp.json'
        Set-Content $path 'first' -Encoding utf8
        $first = get_proxy_config_stamp -Path $path
        $first | Should -Not -Be ''

        Start-Sleep -Milliseconds 50
        Set-Content $path 'second version' -Encoding utf8
        get_proxy_config_stamp -Path $path | Should -Not -Be $first
    }
}

Describe "load_proxy_config_file" {
    It "loads a valid config merged onto defaults" {
        $path = Join-Path $TestDrive 'good.json'
        Set-Content $path '{"providers":{"extra":{"secret":"extra_key","auth":"bearer","base_url":"https://extra.example.com"}}}' -Encoding utf8
        $defaults = @{ base = @{ base_url = 'https://base.example.com' } }
        $result = load_proxy_config_file -Path $path -Defaults $defaults
        $result.success | Should -Be $true
        $result.data.Keys.Count | Should -Be 2
        $result.data.extra.secret | Should -Be 'extra_key'
        $result.data.base.base_url | Should -Be 'https://base.example.com'
    }

    It "fails with CONFIG_READ_FAILED for a missing file" {
        $result = load_proxy_config_file -Path (Join-Path $TestDrive 'absent.json') -Defaults @{}
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'CONFIG_READ_FAILED'
    }

    It "fails with INVALID_CONFIG for a broken file and leaves no partial data" {
        $path = Join-Path $TestDrive 'broken.json'
        Set-Content $path '{"providers":{' -Encoding utf8
        $result = load_proxy_config_file -Path $path -Defaults @{}
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'INVALID_CONFIG'
        $result.data | Should -Be $null
    }
}

Describe "resolve_proxy_route" {
    BeforeAll {
        $script:providers = @{
            openai = @{
                secret = 'openai_api_key'; auth = 'bearer'
                base_url = 'https://api.openai.com'
                allow_methods = @('GET', 'POST'); max_body_bytes = 1024
            }
        }
    }

    It "routes to a known provider and joins the upstream URL" {
        $result = resolve_proxy_route -Providers $providers -Method 'POST' -Path '/openai/v1/chat/completions'
        $result.success | Should -Be $true
        $result.data.provider_name | Should -Be 'openai'
        $result.data.upstream_url | Should -Be 'https://api.openai.com/v1/chat/completions'
    }

    It "preserves the query string" {
        $result = resolve_proxy_route -Providers $providers -Method 'GET' -Path '/openai/v1/models' -Query '?limit=5'
        $result.data.upstream_url | Should -Be 'https://api.openai.com/v1/models?limit=5'
    }

    It "is case-insensitive on provider name and method" {
        $result = resolve_proxy_route -Providers $providers -Method 'post' -Path '/OPENAI/v1/x'
        $result.success | Should -Be $true
        $result.data.method | Should -Be 'POST'
    }

    It "returns PROVIDER_NOT_FOUND with 404 for unknown providers" {
        $result = resolve_proxy_route -Providers $providers -Method 'GET' -Path '/nope/v1/x'
        $result.success | Should -Be $false
        $result.error.code | Should -Be 'PROVIDER_NOT_FOUND'
        $result.error.http_status | Should -Be 404
    }

    It "returns METHOD_NOT_ALLOWED with 405 for disallowed methods" {
        $result = resolve_proxy_route -Providers $providers -Method 'DELETE' -Path '/openai/v1/x'
        $result.error.code | Should -Be 'METHOD_NOT_ALLOWED'
        $result.error.http_status | Should -Be 405
    }

    It "rejects the bare root path" {
        $result = resolve_proxy_route -Providers $providers -Method 'GET' -Path '/'
        $result.error.code | Should -Be 'INVALID_PATH'
    }
}

Describe "plan_auth_header" {
    It "plans bearer, x-api-key, and x-goog-api-key injection" {
        $bearer = plan_auth_header -AuthMode 'bearer'
        $bearer.data.header | Should -Be 'Authorization'
        $bearer.data.prefix | Should -Be 'Bearer '

        (plan_auth_header -AuthMode 'x-api-key').data.header | Should -Be 'x-api-key'
        (plan_auth_header -AuthMode 'x-goog-api-key').data.header | Should -Be 'x-goog-api-key'
    }

    It "plans raw Authorization injection with no scheme prefix" {
        $raw = plan_auth_header -AuthMode 'raw'
        $raw.data.header | Should -Be 'Authorization'
        $raw.data.prefix | Should -Be ''
    }

    It "rejects unknown auth modes" {
        (plan_auth_header -AuthMode 'cookie').success | Should -Be $false
    }
}

Describe "should_forward_header" {
    It "strips client credential headers regardless of case" {
        should_forward_header -Name 'Authorization' | Should -Be $false
        should_forward_header -Name 'X-API-KEY' | Should -Be $false
        should_forward_header -Name 'x-goog-api-key' | Should -Be $false
        should_forward_header -Name 'api-key' | Should -Be $false
    }

    It "strips hop-by-hop and transport headers" {
        should_forward_header -Name 'Host' | Should -Be $false
        should_forward_header -Name 'Connection' | Should -Be $false
        should_forward_header -Name 'Content-Length' | Should -Be $false
        should_forward_header -Name 'Transfer-Encoding' | Should -Be $false
    }

    It "forwards application headers" {
        should_forward_header -Name 'Content-Type' | Should -Be $true
        should_forward_header -Name 'anthropic-version' | Should -Be $true
        should_forward_header -Name 'OpenAI-Beta' | Should -Be $true
        should_forward_header -Name 'User-Agent' | Should -Be $true
    }
}
