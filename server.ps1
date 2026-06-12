$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:8765/")
$listener.Start()
Write-Host "Life Tracker running at http://localhost:8765" -ForegroundColor Green
Write-Host "Keep this window open. Press Ctrl+C to stop." -ForegroundColor Yellow

while ($listener.IsListening) {
    $ctx  = $listener.GetContext()
    $resp = $ctx.Response
    # Re-read file on every request so edits are reflected without restart
    $html  = Get-Content (Join-Path $PSScriptRoot "index.html") -Raw -Encoding UTF8
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($html)
    $resp.ContentType      = "text/html; charset=utf-8"
    $resp.ContentLength64  = $bytes.Length
    $resp.OutputStream.Write($bytes, 0, $bytes.Length)
    $resp.OutputStream.Close()
}
