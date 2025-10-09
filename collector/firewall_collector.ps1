# firewall_collector.ps1
param(
    [string]$LogFilePath = "C:\Windows\System32\LogFiles\Firewall\pfirewall.log"
)

$AgentURL = "http://127.0.0.1:5000/ingest"
$Hostname = $env:COMPUTERNAME

# Use Get-Content -Wait to continuously monitor the file
Write-Host "Monitoring log file: $LogFilePath"
Get-Content -Path $LogFilePath -Wait | ForEach-Object {
    $LogLine = $_
    
    # Skip header lines and empty lines
    if ($LogLine -notlike "#*" -and $LogLine.Trim() -ne "") {
        
        Write-Host "Forwarded: $LogLine"
        
        # Prepare the JSON payload
        $Payload = @{
            raw = $LogLine
            host = $Hostname
        } | ConvertTo-Json

        # Send the log line to the AI Agent
        try {
            Invoke-RestMethod -Uri $AgentURL -Method Post -ContentType 'application/json' -Body $Payload | Out-Null
        } catch {
            Write-Warning "Failed to send log to agent: $($_.Exception.Message)"
        }
    }
}