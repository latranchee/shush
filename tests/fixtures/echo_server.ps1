# Minimal loopback echo upstream for the proxy e2e. Responds to every request
# with a JSON dump of the method, path, query, headers, and body it received,
# so the test can assert exactly what the proxy forwarded.
param(
    [Parameter(Mandatory = $true)][int]$Port
)

$ErrorActionPreference = 'Stop'

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
$listener.Start()
Write-Host "echo server on http://127.0.0.1:$Port/"

while ($listener.IsListening) {
    $context = $listener.GetContext()
    $request = $context.Request
    $response = $context.Response

    if ($request.Url.AbsolutePath -eq '/__shutdown') {
        $response.StatusCode = 200
        $response.Close()
        break
    }

    # /__sleep/<ms> stalls this upstream, so the concurrency check can hold one
    # provider busy and prove the proxy still serves everyone else. This server
    # is deliberately serial - run a second instance for the fast provider.
    if ($request.Url.AbsolutePath -match '^/__sleep/(\d+)$') {
        Start-Sleep -Milliseconds ([int]$Matches[1])
    }

    $headers = @{}
    foreach ($key in $request.Headers.AllKeys) {
        $headers[$key] = $request.Headers[$key]
    }

    $body = ''
    if ($request.HasEntityBody) {
        $reader = [System.IO.StreamReader]::new($request.InputStream, [System.Text.Encoding]::UTF8)
        $body = $reader.ReadToEnd()
        $reader.Dispose()
    }

    $payload = @{
        method = $request.HttpMethod
        path = $request.Url.AbsolutePath
        query = $request.Url.Query
        headers = $headers
        body = $body
    } | ConvertTo-Json -Depth 5

    $bytes = [System.Text.Encoding]::UTF8.GetBytes($payload)
    $response.StatusCode = 200
    $response.ContentType = 'application/json'
    $response.ContentLength64 = $bytes.Length
    $response.OutputStream.Write($bytes, 0, $bytes.Length)
    $response.Close()
}

$listener.Stop()
