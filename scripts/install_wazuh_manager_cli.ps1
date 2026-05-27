param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [string]$User = "",
    [int]$Port = 22,
    [string]$RemoteDir = "~/capstone-wazuh-manager",
    [string]$WazuhVersion = "4.14",
    [switch]$InstallCapstoneRules,
    [switch]$PrintPasswords,
    [switch]$DisableRepoAfterInstall,
    [switch]$ConnectWindowsAgent,
    [string]$AgentManagerAddress = ""
)

$ErrorActionPreference = "Stop"

function Resolve-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Test-CommandAvailable {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

function Escape-BashSingleQuote {
    param([string]$Value)
    return $Value -replace "'", "'\''"
}

function Invoke-Native {
    param(
        [string]$FilePath,
        [string[]]$Arguments
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath failed with exit code $LASTEXITCODE"
    }
}

$projectRoot = Resolve-ProjectRoot
$installerPath = Join-Path $PSScriptRoot "install_wazuh_manager_cli.sh"
$rulePath = Join-Path $projectRoot "backend\rules\wazuh\optional_custom\capstone_malware_behavior_rules.xml"
$connectorPath = Join-Path $PSScriptRoot "connect_wazuh_windows_agent.ps1"

if (-not (Test-CommandAvailable "ssh")) {
    throw "OpenSSH ssh.exe was not found. Install OpenSSH Client or run this from a shell that has ssh."
}
if (-not (Test-CommandAvailable "scp")) {
    throw "OpenSSH scp.exe was not found. Install OpenSSH Client or run this from a shell that has scp."
}
if (-not (Test-Path -LiteralPath $installerPath)) {
    throw "Missing installer script: $installerPath"
}
if ($InstallCapstoneRules -and -not (Test-Path -LiteralPath $rulePath)) {
    throw "Missing Capstone rule file: $rulePath"
}

$target = if ($User.Trim()) { "$User@$HostName" } else { $HostName }
$remoteDirQuoted = "'" + (Escape-BashSingleQuote $RemoteDir) + "'"

Write-Host "=== Capstone Wazuh Manager remote CLI install ==="
Write-Host "Target: $target"
Write-Host "Remote directory: $RemoteDir"
Write-Host "Wazuh version channel: $WazuhVersion"

Invoke-Native "ssh" @("-p", "$Port", $target, "mkdir -p $remoteDirQuoted")
Invoke-Native "scp" @("-P", "$Port", $installerPath, "${target}:$RemoteDir/")

$remoteRulePath = ""
if ($InstallCapstoneRules) {
    $remoteRulePath = "$RemoteDir/capstone_malware_behavior_rules.xml"
    Invoke-Native "scp" @("-P", "$Port", $rulePath, "${target}:$remoteRulePath")
}

$envParts = [System.Collections.Generic.List[string]]::new()
$envParts.Add("WAZUH_VERSION='$(Escape-BashSingleQuote $WazuhVersion)'")
if ($InstallCapstoneRules) {
    $envParts.Add("INSTALL_CAPSTONE_RULES='1'")
    $envParts.Add("CAPSTONE_RULE_PATH='$(Escape-BashSingleQuote $remoteRulePath)'")
}
if ($PrintPasswords) {
    $envParts.Add("PRINT_PASSWORDS='1'")
}
if ($DisableRepoAfterInstall) {
    $envParts.Add("DISABLE_REPO_AFTER_INSTALL='1'")
}

$remoteCommand = "cd $remoteDirQuoted && chmod +x ./install_wazuh_manager_cli.sh && " + ($envParts -join " ") + " bash ./install_wazuh_manager_cli.sh"
Invoke-Native "ssh" @("-p", "$Port", $target, $remoteCommand)

if ($ConnectWindowsAgent) {
    if (-not (Test-Path -LiteralPath $connectorPath)) {
        throw "Missing Windows agent connector script: $connectorPath"
    }

    $managerAddress = if ($AgentManagerAddress.Trim()) { $AgentManagerAddress } else { $HostName }
    Write-Host ""
    Write-Host "Starting Windows agent connector for manager: $managerAddress"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $connectorPath -Manager $managerAddress
    if ($LASTEXITCODE -ne 0) {
        throw "Windows agent connector failed with exit code $LASTEXITCODE"
    }
}

Write-Host ""
Write-Host "Next command to bridge manager alerts into this app:"
Write-Host ".\scripts\bridge_wazuh_alerts_to_local.ps1 -HostName $HostName$(if ($User) { " -User $User" })"
