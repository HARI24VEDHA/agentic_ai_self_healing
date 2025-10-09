# tail_firewall.ps1
# Runs as a simple forwarder: tails pfirewall.log and POSTs new lines to the agent endpoint.
# Run as Administrator or a user that can read the firewall log file.

$log = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
$uri = "http://127.0.0.1:5000/ingest"  # change if you host agent elsewhere
$pos = 0

if (Test-Path $log) {
  $pos = (Get-Item $log).Length
}

Write-Output "Starting firewall tailer. Sending to $uri"
while ($true) {
  Start-Sleep -Seconds 2
  if (-not (Test-Path $log)) { continue }
  $fi = Get-Item $log
  if ($fi.Length -le $pos) { continue }

  $fs = [System.IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
  try {
    $fs.Seek($pos, 'Begin') | Out-Null
    $sr = New-Object System.IO.StreamReader($fs)
    while (-not $sr.EndOfStream) {
      $line = $sr.ReadLine()
      if ($line.Trim() -eq "") { continue }
      $body = @{ host = $env:COMPUTERNAME; raw = $line; received_at = (Get-Date).ToString("o") } | ConvertTo-Json
      try {
        Invoke-RestMethod -Uri $uri -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5
      } catch {
        Write-Output "Forward failed: $_"
      }
    }
    $pos = $fs.Position
  } finally {
    if ($sr) { $sr.Close() }
    $fs.Close()
  }
}
