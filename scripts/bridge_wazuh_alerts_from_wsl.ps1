param(
    [string]$Distro = "Ubuntu",
    [string]$RemoteAlertsPath = "/var/ossec/logs/alerts/alerts.json",
    [string]$LocalAlertsPath = "",
    [switch]$NoSudo,
    [switch]$FollowExisting
)

$ErrorActionPreference = "Stop"

function Resolve-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

if (-not (Get-Command "wsl.exe" -ErrorAction SilentlyContinue)) {
    throw "wsl.exe was not found. Install WSL first."
}

$projectRoot = Resolve-ProjectRoot
if (-not $LocalAlertsPath.Trim()) {
    $LocalAlertsPath = Join-Path $projectRoot "logs\wazuh_alerts.jsonl"
}

$localDir = Split-Path -Parent $LocalAlertsPath
if ($localDir) {
    New-Item -ItemType Directory -Force -Path $localDir | Out-Null
}
if (-not (Test-Path -LiteralPath $LocalAlertsPath)) {
    New-Item -ItemType File -Force -Path $LocalAlertsPath | Out-Null
}

$tailStart = if ($FollowExisting) { "+1" } else { "0" }
$tailCommand = "tail -n $tailStart -F '$RemoteAlertsPath'"
if (-not $NoSudo) {
    $tailCommand = "sudo $tailCommand"
}

Write-Host "=== WSL Wazuh alerts bridge ==="
Write-Host "Distro: $Distro"
Write-Host "Remote: $RemoteAlertsPath"
Write-Host "Local:  $LocalAlertsPath"
Write-Host ""
Write-Host "Before starting backend/main.py in another PowerShell window, use:"
Write-Host "`$env:WAZUH_ALERT_LOG_PATH = `"$LocalAlertsPath`""
Write-Host "`$env:WAZUH_ALLOW_ALERT_LOG_BRIDGE = `"1`""
Write-Host ""
Write-Host "Streaming WSL Wazuh alerts. Press Ctrl+C to stop."

& wsl.exe -d $Distro -- bash -lc $tailCommand | Tee-Object -FilePath $LocalAlertsPath -Append
