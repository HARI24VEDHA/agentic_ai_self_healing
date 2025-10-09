# apply_plan.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$IPAddress
)

# Rule Name must be unique
$RuleName = "AI_BLOCK_$IPAddress"

Write-Host "Attempting to create firewall rule to block IP: $IPAddress"

# Check if the rule already exists to avoid errors
if (Get-NetFirewallRule -DisplayName $RuleName -ErrorAction SilentlyContinue) {
    Write-Host "Rule $RuleName already exists. Skipping creation."
    exit 0
}

# Create the new firewall rule
try {
    New-NetFirewallRule -DisplayName $RuleName `
        -Direction Inbound `
        -Action Block `
        -Protocol Any `
        -RemoteAddress $IPAddress `
        -Profile Any `
        -ErrorAction Stop
        
    Write-Host "SUCCESS: Created firewall rule '$RuleName' to block $IPAddress."
    exit 0
} catch {
    Write-Error "CRITICAL FAILURE: Could not create firewall rule. Ensure script is run with Administrator privileges. Error: $($_.Exception.Message)"
    exit 1
}