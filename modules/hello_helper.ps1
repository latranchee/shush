# hello_helper.ps1
# WinRT half of the Windows Hello unlock factor.
#
# Kept in its own script because WinRT projection only exists on Windows
# PowerShell 5.1. factor_hello.psm1 dot-sources this in-process when the
# projection is available and otherwise runs it under powershell.exe 5.1,
# so PowerShell 7 users get Hello support too.
#
# Emits exactly one line of JSON on stdout: {"ok":true,"data":"<base64>"} or
# {"ok":false,"code":"...","message":"..."}. Never prints key material in any
# other form, and never writes anything to disk.

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('probe', 'create', 'sign', 'delete')]
    [string]$Operation,

    [string]$CredentialName,

    [string]$ChallengeBase64
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function write_helper_result {
    param([bool]$Ok, $Data, [string]$Code, [string]$Message)

    $payload = if ($Ok) {
        @{ ok = $true; data = $Data }
    } else {
        @{ ok = $false; code = $Code; message = $Message }
    }
    Write-Output ($payload | ConvertTo-Json -Compress -Depth 4)
}

function initialize_winrt {
    [void][Windows.Security.Credentials.KeyCredentialManager, Windows.Security.Credentials, ContentType=WindowsRuntime]
    [void][Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType=WindowsRuntime]
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
}

# WinRT returns IAsyncOperation, which PowerShell cannot await directly.
# WindowsRuntimeSystemExtensions.AsTask bridges it to a Task we can block on.
function await_winrt {
    param($Operation, [type]$ResultType)

    $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
        $_.Name -eq 'AsTask' -and
        $_.GetParameters().Count -eq 1 -and
        $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1'
    })[0]

    $task = $asTask.MakeGenericMethod($ResultType).Invoke($null, @($Operation))
    if (-not $task.Wait(120000)) {
        throw 'Timed out after 120s waiting for the Windows Hello prompt'
    }
    return $task.Result
}

function get_status_name {
    param($Status)

    try { return [string]$Status } catch { return 'Unknown' }
}

try {
    initialize_winrt
} catch {
    write_helper_result -Ok $false -Code 'WINRT_UNAVAILABLE' `
        -Message "Windows Runtime projection is unavailable in this host: $($_.Exception.Message)"
    exit 0
}

try {
    switch ($Operation) {
        'probe' {
            $supported = await_winrt -Operation ([Windows.Security.Credentials.KeyCredentialManager]::IsSupportedAsync()) -ResultType ([bool])
            write_helper_result -Ok $true -Data $supported
        }

        'create' {
            # ReplaceExisting: enrollment is the only path that reaches here,
            # and a half-created credential from an aborted attempt must not
            # wedge the user out of re-enrolling.
            $result = await_winrt -Operation ([Windows.Security.Credentials.KeyCredentialManager]::RequestCreateAsync(
                $CredentialName,
                [Windows.Security.Credentials.KeyCredentialCreationOption]::ReplaceExisting
            )) -ResultType ([Windows.Security.Credentials.KeyCredentialRetrievalResult])

            if ($result.Status -ne [Windows.Security.Credentials.KeyCredentialStatus]::Success) {
                write_helper_result -Ok $false -Code 'HELLO_CREATE_FAILED' `
                    -Message "Windows Hello refused to create the credential (status: $(get_status_name -Status $result.Status))"
                exit 0
            }
            write_helper_result -Ok $true -Data $CredentialName
        }

        'sign' {
            $result = await_winrt -Operation ([Windows.Security.Credentials.KeyCredentialManager]::OpenAsync($CredentialName)) `
                -ResultType ([Windows.Security.Credentials.KeyCredentialRetrievalResult])

            if ($result.Status -ne [Windows.Security.Credentials.KeyCredentialStatus]::Success) {
                write_helper_result -Ok $false -Code 'HELLO_OPEN_FAILED' `
                    -Message "Cannot open Hello credential '$CredentialName' (status: $(get_status_name -Status $result.Status))"
                exit 0
            }

            $challenge = [Convert]::FromBase64String($ChallengeBase64)
            $buffer = [Windows.Security.Cryptography.CryptographicBuffer]::CreateFromByteArray($challenge)

            # Prompts for the Hello gesture. The private key never leaves the
            # TPM; we only ever see the signature it produces.
            $signResult = await_winrt -Operation ($result.Credential.RequestSignAsync($buffer)) `
                -ResultType ([Windows.Security.Credentials.KeyCredentialOperationResult])

            if ($signResult.Status -ne [Windows.Security.Credentials.KeyCredentialStatus]::Success) {
                write_helper_result -Ok $false -Code 'HELLO_SIGN_FAILED' `
                    -Message "Windows Hello sign was refused or cancelled (status: $(get_status_name -Status $signResult.Status))"
                exit 0
            }

            $signature = $null
            [Windows.Security.Cryptography.CryptographicBuffer]::CopyToByteArray($signResult.Result, [ref]$signature)
            write_helper_result -Ok $true -Data ([Convert]::ToBase64String($signature))
            [Array]::Clear($signature, 0, $signature.Length)
        }

        'delete' {
            $asTaskAction = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
                $_.Name -eq 'AsTask' -and
                $_.GetParameters().Count -eq 1 -and
                $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncAction'
            })[0]
            $task = $asTaskAction.Invoke($null, @([Windows.Security.Credentials.KeyCredentialManager]::DeleteAsync($CredentialName)))
            [void]$task.Wait(30000)
            write_helper_result -Ok $true -Data $CredentialName
        }
    }
} catch {
    write_helper_result -Ok $false -Code 'HELLO_ERROR' -Message $_.Exception.Message
}
