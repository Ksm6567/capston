param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [string]$User = "",
    [int]$Port = 22,
    [string]$RemoteAlertsPath = "/var/ossec/logs/alerts/alerts.json",
    [string]$LocalAlertsPath = "",
    [switch]$NoSudo,
    [switch]$FollowExisting
)

$ErrorActionPreference = "Stop"

function Resolve-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Escape-BashSingleQuote {
    param([string]$Value)
    return $Value -replace "'", "'\''"
}

if (-not (Get-Command "ssh" -ErrorAction SilentlyContinue)) {
    throw "OpenSSH ssh.exe was not found. Install OpenSSH Client or run this from a shell that has ssh."
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

$target = if ($User.Trim()) { "$User@$HostName" } else { $HostName }
$tailStart = if ($FollowExisting) { "+1" } else { "0" }
$remotePathQuoted = "'" + (Escape-BashSingleQuote $RemoteAlertsPath) + "'"
$tailCommand = "tail -n $tailStart -F $remotePathQuoted"
if (-not $NoSudo) {
    $tailCommand = "sudo $tailCommand"
}

Write-Host "=== Wazuh alerts bridge ==="
Write-Host "Remote: ${target}:$RemoteAlertsPath"
Write-Host "Local:  $LocalAlertsPath"
Write-Host ""
Write-Host "Before starting backend/main.py in another PowerShell window, use:"
Write-Host "`$env:WAZUH_ALERT_LOG_PATH = `"$LocalAlertsPath`""
Write-Host "`$env:WAZUH_ALLOW_ALERT_LOG_BRIDGE = `"1`""
Write-Host ""
Write-Host "Streaming new Wazuh alerts. Press Ctrl+C to stop."

& ssh -p $Port $target $tailCommand | Tee-Object -FilePath $LocalAlertsPath -Append
