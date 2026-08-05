$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) "modules\admin_pipe.psm1"
Import-Module $modulePath -Force

Describe "parse_admin_request" {
    It "parses a valid create request" {
        $result = parse_admin_request -Json '{"op":"create","name":"my_key","value":"v123","force":true}'
        $result.success | Should -Be $true
        $result.data.op | Should -Be 'create'
        $result.data.name | Should -Be 'my_key'
        $result.data.value | Should -Be 'v123'
        $result.data.force | Should -Be $true
    }

    It "parses ping, list, exists, delete" {
        (parse_admin_request -Json '{"op":"ping"}').success | Should -Be $true
        (parse_admin_request -Json '{"op":"list"}').success | Should -Be $true
        (parse_admin_request -Json '{"op":"exists","name":"my_key"}').success | Should -Be $true
        (parse_admin_request -Json '{"op":"delete","name":"my_key"}').success | Should -Be $true
    }

    It "rejects any value-reading op as UNSUPPORTED_OP" {
        foreach ($op in @('get', 'read', 'export', 'dump', 'run')) {
            $result = parse_admin_request -Json ('{"op":"' + $op + '","name":"my_key"}')
            $result.success | Should -Be $false
            $result.error.code | Should -Be 'UNSUPPORTED_OP'
        }
    }

    It "rejects malformed JSON, empty input, and missing op" {
        (parse_admin_request -Json 'not json').error.code | Should -Be 'INVALID_REQUEST'
        (parse_admin_request -Json '').error.code | Should -Be 'INVALID_REQUEST'
        (parse_admin_request -Json '{"name":"x"}').error.code | Should -Be 'INVALID_REQUEST'
    }

    It "requires name for create/exists/delete and validates it" {
        (parse_admin_request -Json '{"op":"exists"}').error.code | Should -Be 'INVALID_REQUEST'
        (parse_admin_request -Json '{"op":"delete","name":"Bad-Name"}').error.code | Should -Be 'INVALID_NAME'
    }

    It "requires a non-empty value for create" {
        (parse_admin_request -Json '{"op":"create","name":"my_key"}').error.code | Should -Be 'EMPTY_VALUE'
        (parse_admin_request -Json '{"op":"create","name":"my_key","value":""}').error.code | Should -Be 'EMPTY_VALUE'
    }

    It "rejects oversized requests" {
        $big = '{"op":"create","name":"my_key","value":"' + ('x' * 20000) + '"}'
        (parse_admin_request -Json $big).error.code | Should -Be 'REQUEST_TOO_LARGE'
    }

    It "defaults force to false" {
        (parse_admin_request -Json '{"op":"create","name":"my_key","value":"v"}').data.force | Should -Be $false
    }
}

Describe "get_admin_pipe_ops" {
    It "exposes exactly the write-only op set" {
        $ops = get_admin_pipe_ops
        $ops | Should -Be @('ping', 'create', 'list', 'exists', 'delete')
        $ops | Should -Not -Contain 'get'
    }
}
