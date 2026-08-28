# cloud_client.Tests.ps1
# Pester 5 unit tests for modules/cloud_client.psm1: the cloud tokenizer,
# token/hash helpers, SK_ binding round-trip (shared vectors with the worker
# vitest suite), env planning, config round-trips, and the wrangler wrapper
# against a fake npx.

BeforeAll {
    $modulePath = Join-Path $PSScriptRoot '..\modules\cloud_client.psm1'
    Import-Module $modulePath -Force

    $script:vectors = Get-Content (Join-Path $PSScriptRoot 'fixtures\cloud_vectors.json') -Raw | ConvertFrom-Json
}

Describe 'shared vectors: SK_ binding round-trip' {
    It "maps '<name>' to '<binding>'" -ForEach @(
        (Get-Content (Join-Path $PSScriptRoot 'fixtures\cloud_vectors.json') -Raw | ConvertFrom-Json).secret_name_to_binding |
            ForEach-Object { @{ name = $_.name; binding = $_.binding; valid = $_.valid } }
    ) {
        $result = format_secret_binding_name -Name $name
        if ($valid) {
            $result | Should -BeExactly $binding
        } else {
            $result | Should -BeNullOrEmpty
        }
    }
}

Describe 'shared vectors: machine token parse fuzz' {
    It "parses '<token>' as valid=<valid>" -ForEach @(
        (Get-Content (Join-Path $PSScriptRoot 'fixtures\cloud_vectors.json') -Raw | ConvertFrom-Json).machine_tokens |
            ForEach-Object { @{ token = $_.token; valid = $_.valid; id = $_.id } }
    ) {
        $result = parse_machine_token -Token $token
        $result.success | Should -Be $valid
        if ($valid) {
            $result.data.id | Should -BeExactly $id
        }
    }
}

Describe 'parse_cloud_arguments' {
    It 'splits positionals and flags' {
        $result = parse_cloud_arguments -Tokens @('machine', 'add', 'laptop', '--grant', 'openai,anthropic', '--save')
        $result.success | Should -BeTrue
        @($result.data.positional) | Should -Be @('machine', 'add', 'laptop')
        @($result.data.flags.grant) | Should -Be @('openai', 'anthropic')
        $result.data.flags.save | Should -BeTrue
        $result.data.flags.show | Should -BeFalse
    }

    It 'accepts single-dash spellings' {
        $result = parse_cloud_arguments -Tokens @('status', '-probe')
        $result.success | Should -BeTrue
        $result.data.flags.probe | Should -BeTrue
    }

    It 'rejects unknown double-dash flags' {
        $result = parse_cloud_arguments -Tokens @('deploy', '--port', '9000')
        $result.success | Should -BeFalse
        $result.error.code | Should -Be 'INVALID_PARAMS'
    }

    It 'rejects --grant without a value' {
        $result = parse_cloud_arguments -Tokens @('machine', 'add', '--grant')
        $result.success | Should -BeFalse
    }

    It 'rejects more than three positionals' {
        $result = parse_cloud_arguments -Tokens @('a', 'b', 'c', 'd')
        $result.success | Should -BeFalse
    }

    It 'handles an empty token list' {
        $result = parse_cloud_arguments -Tokens @()
        $result.success | Should -BeTrue
        @($result.data.positional).Count | Should -Be 0
    }
}

Describe 'admin token and hash' {
    It 'mints distinct high-entropy base64url tokens' {
        $first = new_cloud_admin_token
        $second = new_cloud_admin_token
        $first | Should -Not -Be $second
        $first | Should -Match '^[A-Za-z0-9_-]{43}$'
    }

    It 'produces the v1:<salt>:<hash> format the worker verifies' {
        $hash = get_admin_token_hash -Token 'known-token'
        $hash | Should -Match '^v1:[A-Za-z0-9_-]+:[A-Za-z0-9_-]+$'
    }

    It 'hash is salted: same token, different hashes, both verifiable by recomputation' {
        $token = 'same-token-twice'
        $first = get_admin_token_hash -Token $token
        $second = get_admin_token_hash -Token $token
        $first | Should -Not -Be $second

        # Recompute sha256(salt || token) exactly like the worker does.
        foreach ($stored in @($first, $second)) {
            $parts = $stored -split ':'
            $b64 = $parts[1].Replace('-', '+').Replace('_', '/')
            if ($b64.Length % 4) { $b64 += ('=' * (4 - ($b64.Length % 4))) }
            $salt = [Convert]::FromBase64String($b64)
            $tokenBytes = [System.Text.Encoding]::UTF8.GetBytes($token)
            $combined = New-Object byte[] ($salt.Length + $tokenBytes.Length)
            [Array]::Copy($salt, 0, $combined, 0, $salt.Length)
            [Array]::Copy($tokenBytes, 0, $combined, $salt.Length, $tokenBytes.Length)
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $digest = $sha.ComputeHash($combined) } finally { $sha.Dispose() }
            $expected = [Convert]::ToBase64String($digest).Replace('+', '-').Replace('/', '_').TrimEnd('=')
            $parts[2] | Should -BeExactly $expected
        }
    }
}

Describe 'get_cloud_env_mappings' {
    It 'openai gets OPENAI_BASE_URL with /v1' {
        $plan = get_cloud_env_mappings -EnvVar 'OPENAI_API_KEY' -Provider 'openai' -WorkerUrl 'https://w.example.workers.dev' -Token 'shm.x.y'
        $plan.success | Should -BeTrue
        $plan.data.values['OPENAI_API_KEY'] | Should -Be 'shm.x.y'
        $plan.data.values['OPENAI_BASE_URL'] | Should -Be 'https://w.example.workers.dev/openai/v1'
    }

    It 'anthropic gets ANTHROPIC_BASE_URL without /v1' {
        $plan = get_cloud_env_mappings -EnvVar 'ANTHROPIC_API_KEY' -Provider 'anthropic' -WorkerUrl 'https://w.example.workers.dev' -Token 't'
        $plan.data.values['ANTHROPIC_BASE_URL'] | Should -Be 'https://w.example.workers.dev/anthropic'
    }

    It 'gemini pins gemini-cli vars and notes the SDK caveat' {
        $plan = get_cloud_env_mappings -EnvVar 'GEMINI_API_KEY' -Provider 'gemini' -WorkerUrl 'https://w.example.workers.dev' -Token 't'
        $plan.data.values['GOOGLE_GEMINI_BASE_URL'] | Should -Be 'https://w.example.workers.dev/gemini'
        $plan.data.values['GOOGLE_GENAI_USE_VERTEXAI'] | Should -Be 'false'
        @($plan.data.notes).Count | Should -BeGreaterThan 0
    }

    It 'unknown env var still injects the token and advises on the base URL' {
        $plan = get_cloud_env_mappings -EnvVar 'QUO_API_KEY' -Provider 'quo' -WorkerUrl 'https://w.example.workers.dev' -Token 't'
        $plan.data.values['QUO_API_KEY'] | Should -Be 't'
        @($plan.data.notes)[0] | Should -Match 'QUO_BASE_URL'
    }

    It 'rejects an invalid provider name (case-sensitive grammar)' {
        (get_cloud_env_mappings -EnvVar 'X' -Provider 'Bad-Name' -WorkerUrl 'https://w' -Token 't').success | Should -BeFalse
        (get_cloud_env_mappings -EnvVar 'X' -Provider 'OPENAI' -WorkerUrl 'https://w' -Token 't').success | Should -BeFalse
    }
}

Describe 'preflight warnings' {
    It 'warns for codex + openai' {
        @(get_cloud_preflight_warnings -ChildCommand 'codex' -Providers @('openai')).Count | Should -Be 1
    }
    It 'warns for claude.exe + anthropic' {
        @(get_cloud_preflight_warnings -ChildCommand 'claude.exe' -Providers @('anthropic')).Count | Should -Be 1
    }
    It 'silent for unrelated commands' {
        @(get_cloud_preflight_warnings -ChildCommand 'python' -Providers @('openai', 'anthropic')).Count | Should -Be 0
    }
}

Describe 'cloud config round-trip' {
    It 'writes and reads back worker_url' {
        $path = Join-Path $TestDrive 'cloud_config.json'
        (write_cloud_config -Path $path -Config @{ worker_url = 'https://shush-cloud.acme.workers.dev' }).success | Should -BeTrue
        $read = read_cloud_config -Path $path
        $read.success | Should -BeTrue
        $read.data.worker_url | Should -Be 'https://shush-cloud.acme.workers.dev'
    }

    It 'trims a trailing slash' {
        $path = Join-Path $TestDrive 'cloud_config2.json'
        Set-Content -LiteralPath $path -Value '{"worker_url": "https://w.example.workers.dev/"}'
        (read_cloud_config -Path $path).data.worker_url | Should -Be 'https://w.example.workers.dev'
    }

    It 'rejects http:// for non-loopback hosts' {
        $path = Join-Path $TestDrive 'cloud_config3.json'
        Set-Content -LiteralPath $path -Value '{"worker_url": "http://evil.example.com"}'
        (read_cloud_config -Path $path).success | Should -BeFalse
    }

    It 'accepts http://127.0.0.1 for test harnesses' {
        $path = Join-Path $TestDrive 'cloud_config4.json'
        Set-Content -LiteralPath $path -Value '{"worker_url": "http://127.0.0.1:8787"}'
        (read_cloud_config -Path $path).success | Should -BeTrue
    }

    It 'missing file reports NOT_CONFIGURED' {
        (read_cloud_config -Path (Join-Path $TestDrive 'absent.json')).error.code | Should -Be 'NOT_CONFIGURED'
    }

    It 'SHUSH_CLOUD_CONFIG overrides the default path' {
        $override = Join-Path $TestDrive 'elsewhere.json'
        $env:SHUSH_CLOUD_CONFIG = $override
        try {
            get_cloud_config_path -ScriptDir 'C:\anything' | Should -Be $override
        } finally {
            Remove-Item Env:SHUSH_CLOUD_CONFIG -ErrorAction SilentlyContinue
        }
    }
}

Describe 'get_kv_id_from_create_output' {
    It 'extracts the id from the wrangler create snippet' {
        $out = @'
Creating namespace with title "SHUSH_KV"
Success!
Add the following to your configuration file in your kv_namespaces array:
{ "kv_namespaces": [ { "binding": "SHUSH_KV", "id": "ca8df347187e472882cf76b84bad0947" } ] }
'@
        get_kv_id_from_create_output -Text $out | Should -Be 'ca8df347187e472882cf76b84bad0947'
    }

    It 'returns null when no id is present' {
        get_kv_id_from_create_output -Text 'Success, probably' | Should -BeNullOrEmpty
        get_kv_id_from_create_output -Text '' | Should -BeNullOrEmpty
    }

    It 'ignores non-hex or wrong-length ids' {
        get_kv_id_from_create_output -Text '"id": "not-a-real-id"' | Should -BeNullOrEmpty
    }
}

Describe 'find_kv_namespace_id output parsing' {
    It 'survives ANSI escapes and banner noise before the JSON array' {
        $esc = [char]27
        $noisy = "$esc[33mWARNING$esc[0m unsafe fields blah`n[`n  { `"id`": `"abc123abc123abc123abc123abc123ab`", `"title`": `"SHUSH_KV`" }`n]"
        Mock invoke_wrangler { @{ success = $true; data = @{ exit_code = 0; stdout = $noisy; stderr = '' }; error = $null } } -ModuleName 'cloud_client'
        $result = find_kv_namespace_id -WorkerDir 'C:\anywhere' -Titles @('SHUSH_KV')
        $result.success | Should -BeTrue
        $result.data | Should -Be 'abc123abc123abc123abc123abc123ab'
    }

    It 'reports a miss as success with null data' {
        Mock invoke_wrangler { @{ success = $true; data = @{ exit_code = 0; stdout = '[]'; stderr = '' }; error = $null } } -ModuleName 'cloud_client'
        $result = find_kv_namespace_id -WorkerDir 'C:\anywhere' -Titles @('SHUSH_KV')
        $result.success | Should -BeTrue
        $result.data | Should -BeNullOrEmpty
    }
}

Describe 'wrangler.jsonc kv id round-trip' {
    It 'updates the namespace id and preserves the rest' {
        $source = Join-Path $PSScriptRoot '..\cloud\worker\wrangler.jsonc'
        $copy = Join-Path $TestDrive 'wrangler.jsonc'
        Copy-Item $source $copy
        (update_wrangler_kv_id -Path $copy -NamespaceId 'abc123def456').success | Should -BeTrue
        $parsed = Get-Content $copy -Raw | ConvertFrom-Json
        $parsed.kv_namespaces[0].id | Should -Be 'abc123def456'
        $parsed.kv_namespaces[0].binding | Should -Be 'SHUSH_KV'
        $parsed.name | Should -Be 'shush-cloud'
        $parsed.durable_objects.bindings[0].class_name | Should -Be 'AclDO'
        @($parsed.migrations).Count | Should -BeGreaterThan 0
    }
}

Describe 'invoke_wrangler against a fake npx' {
    BeforeAll {
        # A fake npx that ignores the injected '--yes wrangler@<ver>' prefix,
        # echoes its arguments, copies stdin byte-for-byte to a file, and
        # exits with SHUSH_FAKE_EXIT. Exercises the wrapper's stream capture,
        # UTF-8 stdin path, env injection, and exit-code contract.
        $script:fakeDir = Join-Path $TestDrive 'fake'
        New-Item -ItemType Directory -Path $script:fakeDir -Force | Out-Null
        $fakeNpx = Join-Path $script:fakeDir 'npx.cmd'
        @(
            '@echo off',
            'echo ARGS=%*',
            'echo CI=%CI%',
            'echo METRICS=%WRANGLER_SEND_METRICS%',
            'powershell -NoProfile -Command "$in = [Console]::OpenStandardInput(); $out = [IO.File]::OpenWrite(''%~dp0stdin.bin''); $in.CopyTo($out); $out.Close()"',
            'if defined SHUSH_FAKE_EXIT exit /b %SHUSH_FAKE_EXIT%',
            'exit /b 0'
        ) | Set-Content -LiteralPath $fakeNpx -Encoding Ascii
        $script:fakeNpxPath = $fakeNpx
    }

    BeforeEach {
        Mock find_npx_or_error { @{ success = $true; data = $script:fakeNpxPath; error = $null } } -ModuleName 'cloud_client'
        Remove-Item (Join-Path $script:fakeDir 'stdin.bin') -ErrorAction SilentlyContinue
        Remove-Item Env:SHUSH_FAKE_EXIT -ErrorAction SilentlyContinue
    }

    It 'captures stdout, passes arguments, and forces CI + metrics-off env' {
        $result = invoke_wrangler -WorkerDir $script:fakeDir -Arguments @('kv', 'namespace', 'list')
        $result.success | Should -BeTrue
        $result.data.exit_code | Should -Be 0
        $result.data.stdout | Should -Match 'ARGS=--yes wrangler@[0-9.]+ kv namespace list'
        $result.data.stdout | Should -Match 'CI=1'
        $result.data.stdout | Should -Match 'METRICS=false'
    }

    It 'maps a non-zero exit to WRANGLER_FAILED and keeps the streams' {
        $env:SHUSH_FAKE_EXIT = '7'
        try {
            $result = invoke_wrangler -WorkerDir $script:fakeDir -Arguments @('deploy')
            $result.success | Should -BeFalse
            $result.error.code | Should -Be 'WRANGLER_FAILED'
            $result.data.exit_code | Should -Be 7
        } finally {
            Remove-Item Env:SHUSH_FAKE_EXIT -ErrorAction SilentlyContinue
        }
    }

    It 'delivers stdin as exact UTF-8 bytes (accents and trailing newline preserved)' {
        $secret = "clé-secrète-é`n"
        $result = invoke_wrangler -WorkerDir $script:fakeDir -Arguments @('secret', 'put', 'SK_X') -StdinText $secret
        $result.success | Should -BeTrue
        $bytes = [System.IO.File]::ReadAllBytes((Join-Path $script:fakeDir 'stdin.bin'))
        $expected = [System.Text.Encoding]::UTF8.GetBytes($secret)
        # Byte-for-byte: any OEM-codepage re-encoding would corrupt the accents.
        [Convert]::ToBase64String($bytes) | Should -BeExactly ([Convert]::ToBase64String($expected))
    }

    It 'quotes arguments containing spaces' {
        $result = invoke_wrangler -WorkerDir $script:fakeDir -Arguments @('secret', 'put', 'NAME WITH SPACE')
        $result.data.stdout | Should -Match 'ARGS=.*"NAME WITH SPACE"'
    }
}
