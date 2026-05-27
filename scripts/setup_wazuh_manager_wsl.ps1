param(
    [string]$Distro = "Ubuntu",
    [string]$WazuhVersion = "4.14",
    [switch]$InstallDistro,
    [switch]$InstallCapstoneRules,
    [switch]$PrintPasswords,
    [switch]$DisableRepoAfterInstall,
    [switch]$StartBridge
)

$ErrorActionPreference = "Stop"

function Resolve-ProjectRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
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

function Enable-WslWindowsFeatures {
    if (-not (Test-Administrator)) {
        throw "Administrator privileges are required to enable WSL Windows features."
    }

    $features = @(
        "Microsoft-Windows-Subsystem-Linux",
        "VirtualMachinePlatform"
    )
    $restartRequired = $false
    foreach ($feature in $features) {
        Write-Host "Checking Windows feature: $feature"
        $state = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
        if ($state -eq "Enabled") {
            Write-Host "$feature is already enabled."
            continue
        }

        Write-Host "Enabling Windows feature: $feature"
        $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
        if ($result.RestartNeeded) {
            $restartRequired = $true
        }
    }

    try {
        & wsl.exe --set-default-version 2 | Out-Host
    } catch {
        Write-Warning "Could not set WSL default version to 2 yet. This can be retried after reboot."
    }

    return $restartRequired
}

function ConvertTo-WslPath {
    param([string]$WindowsPath)
    $resolved = (Resolve-Path -LiteralPath $WindowsPath).Path
    $drive = $resolved.Substring(0, 1).ToLowerInvariant()
    $tail = $resolved.Substring(2).Replace("\", "/")
    return "/mnt/$drive$tail"
}

function Get-WslDistroNames {
    $lxssRoot = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Lxss"
    if (-not (Test-Path $lxssRoot)) {
        return @()
    }

    return @(
        Get-ChildItem $lxssRoot -ErrorAction SilentlyContinue |
            ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DistributionName } |
            Where-Object { $_ -and $_.Trim() } |
            ForEach-Object { $_.Trim() }
    )
}

$projectRoot = Resolve-ProjectRoot
$installerPath = Join-Path $PSScriptRoot "install_wazuh_manager_cli.sh"
$rulePath = Join-Path $projectRoot "backend\rules\wazuh\optional_custom\capstone_malware_behavior_rules.xml"

if (-not (Get-Command "wsl.exe" -ErrorAction SilentlyContinue)) {
    throw "wsl.exe was not found. Install WSL first."
}
if (-not (Test-Path -LiteralPath $installerPath)) {
    throw "Missing installer script: $installerPath"
}
if ($InstallCapstoneRules -and -not (Test-Path -LiteralPath $rulePath)) {
    throw "Missing Capstone rule file: $rulePath"
}

$distros = Get-WslDistroNames
if ($distros -notcontains $Distro) {
    if (-not $InstallDistro) {
        Write-Host "WSL distro '$Distro' is not installed."
        Write-Host "Installed distros: $($distros -join ', ')"
        Write-Host "Run this script again with -InstallDistro from an elevated PowerShell, or install Ubuntu manually:"
        Write-Host "wsl --install -d $Distro"
        exit 2
    }

    if (-not (Test-Administrator)) {
        Write-Host "Administrator approval is required to install WSL distro '$Distro'."
        Write-Host "Opening an elevated PowerShell window now. Approve the Windows UAC prompt."
        $args = @(
            "-NoExit",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", $PSCommandPath,
            "-Distro", $Distro,
            "-WazuhVersion", $WazuhVersion,
            "-InstallDistro"
        )
        if ($InstallCapstoneRules) { $args += "-InstallCapstoneRules" }
        if ($PrintPasswords) { $args += "-PrintPasswords" }
        if ($DisableRepoAfterInstall) { $args += "-DisableRepoAfterInstall" }
        if ($StartBridge) { $args += "-StartBridge" }
        try {
            Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -WindowStyle Normal
        } catch {
            Write-Host ""
            Write-Host "Could not open the elevated PowerShell window automatically."
            Write-Host "Open PowerShell as Administrator and run:"
            Write-Host "cd `"$projectRoot`""
            Write-Host ".\scripts\setup_wazuh_manager_wsl.ps1 -Distro $Distro -InstallDistro -InstallCapstoneRules -StartBridge"
            throw
        }
        Write-Host "The elevated setup window has been requested. Continue in that window."
        exit 0
    }

    $restartRequired = Enable-WslWindowsFeatures
    if ($restartRequired) {
        Write-Host ""
        Write-Host "WSL Windows features were enabled and Windows requires a restart."
        Write-Host "Restart Windows, then run this same setup again from the app or PowerShell."
        exit 3010
    }

    Invoke-Native "wsl.exe" @("--install", "-d", $Distro)
    Write-Host "WSL install was requested. If Windows asks for a reboot, reboot and run this script again."
    exit 0
}

$installerWslPath = ConvertTo-WslPath $installerPath
$ruleWslPath = ConvertTo-WslPath $rulePath
$envParts = @("WAZUH_VERSION='$WazuhVersion'")
if ($InstallCapstoneRules) {
    $envParts += "INSTALL_CAPSTONE_RULES='1'"
    $envParts += "CAPSTONE_RULE_PATH='$ruleWslPath'"
}
if ($PrintPasswords) {
    $envParts += "PRINT_PASSWORDS='1'"
}
if ($DisableRepoAfterInstall) {
    $envParts += "DISABLE_REPO_AFTER_INSTALL='1'"
}

$linuxCommand = "cd '$(Split-Path -Parent $installerWslPath)' && chmod +x '$installerWslPath' && $($envParts -join ' ') bash '$installerWslPath'"
Write-Host "Running Wazuh Manager installer inside WSL distro '$Distro'."
Invoke-Native "wsl.exe" @("-d", $Distro, "--", "bash", "-lc", $linuxCommand)

Write-Host ""
Write-Host "Next bridge command:"
Write-Host ".\scripts\bridge_wazuh_alerts_from_wsl.ps1 -Distro $Distro"

if ($StartBridge) {
    $bridgeScript = Join-Path $PSScriptRoot "bridge_wazuh_alerts_from_wsl.ps1"
    Write-Host ""
    Write-Host "Starting WSL alerts bridge in a new PowerShell window..."
    Start-Process -FilePath "powershell.exe" -ArgumentList @(
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", $bridgeScript,
        "-Distro", $Distro
    ) -WindowStyle Normal
}
