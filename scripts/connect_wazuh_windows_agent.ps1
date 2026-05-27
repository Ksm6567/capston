param(
    [string]$Manager,
    [string]$AgentName = $env:COMPUTERNAME,
    [string]$AgentGroup = "",
    [string]$RegistrationPassword = "",
    [string]$MsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi",
    [string]$MsiPath = "$env:TEMP\wazuh-agent-4.14.5-1.msi",
    [switch]$SkipSysmonConfig,
    [switch]$NoRestart
)

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Add-Argument {
    param(
        [System.Collections.Generic.List[string]]$List,
        [string]$Name,
        [string]$Value
    )

    if ($null -ne $Value -and $Value.Trim()) {
        $List.Add($Name)
        $List.Add($Value)
    }
}

function Find-WazuhAgentRoot {
    $candidates = @(
        "C:\Program Files (x86)\ossec-agent",
        "C:\Program Files\ossec-agent"
    )

    foreach ($path in $candidates) {
        if (Test-Path -LiteralPath $path) {
            return $path
        }
    }
    return $null
}

function Ensure-SysmonEventCollection {
    param([string]$AgentRoot)

    $configPath = Join-Path $AgentRoot "ossec.conf"
    if (-not (Test-Path -LiteralPath $configPath)) {
        Write-Warning "Wazuh config was not found: $configPath"
        return
    }

    $config = Get-Content -LiteralPath $configPath -Raw
    if ($config -match "Microsoft-Windows-Sysmon/Operational") {
        Write-Host "Sysmon EventChannel collection is already present in ossec.conf."
        return
    }

    $backupPath = "$configPath.bak.$(Get-Date -Format yyyyMMddHHmmss)"
    Copy-Item -LiteralPath $configPath -Destination $backupPath

    $block = @"

  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
"@

    if ($config -match "</ossec_config>") {
        $updated = $config -replace "</ossec_config>", "$block`r`n</ossec_config>"
    } else {
        $updated = "$config`r`n$block`r`n"
    }

    Set-Content -LiteralPath $configPath -Value $updated -Encoding UTF8
    Write-Host "Added Sysmon EventChannel collection to ossec.conf."
    Write-Host "Backup: $backupPath"
}

function Show-EndpointState {
    param([string]$Manager)

    Write-Host ""
    Write-Host "=== Endpoint state ==="
    Get-Service *wazuh*,*ossec* -ErrorAction SilentlyContinue |
        Select-Object Name, DisplayName, Status |
        Format-Table -AutoSize

    $agentRoot = Find-WazuhAgentRoot
    if ($agentRoot) {
        Write-Host "Agent root: $agentRoot"
    } else {
        Write-Host "Agent root: not found"
    }

    $sysmonService = Get-Service *sysmon* -ErrorAction SilentlyContinue
    if ($sysmonService) {
        $sysmonService | Select-Object Name, DisplayName, Status | Format-Table -AutoSize
    } else {
        Write-Host "Sysmon service: not found"
    }

    try {
        $sysmonLog = Get-WinEvent -ListLog "Microsoft-Windows-Sysmon/Operational" -ErrorAction Stop
        Write-Host "Sysmon log: enabled=$($sysmonLog.IsEnabled), records=$($sysmonLog.RecordCount)"
    } catch {
        Write-Host "Sysmon log: not found"
    }

    if ($Manager) {
        Write-Host ""
        Write-Host "=== Manager TCP checks ==="
        foreach ($port in @(1514, 1515)) {
            try {
                $test = Test-NetConnection -ComputerName $Manager -Port $port -WarningAction SilentlyContinue
                Write-Host "${Manager}:$port TcpTestSucceeded=$($test.TcpTestSucceeded)"
            } catch {
                Write-Host "${Manager}:$port check failed: $($_.Exception.Message)"
            }
        }
    }
}

if (-not $Manager.Trim()) {
    $Manager = Read-Host "Wazuh manager IP or hostname"
}

if (-not $Manager.Trim()) {
    throw "Manager address is required."
}

if (-not (Test-Administrator)) {
    Write-Host "Administrator approval is required to install/configure the Wazuh agent."
    $args = [System.Collections.Generic.List[string]]::new()
    $args.Add("-NoProfile")
    $args.Add("-ExecutionPolicy")
    $args.Add("Bypass")
    $args.Add("-File")
    $args.Add($PSCommandPath)
    Add-Argument $args "-Manager" $Manager
    Add-Argument $args "-AgentName" $AgentName
    Add-Argument $args "-AgentGroup" $AgentGroup
    Add-Argument $args "-RegistrationPassword" $RegistrationPassword
    Add-Argument $args "-MsiUrl" $MsiUrl
    Add-Argument $args "-MsiPath" $MsiPath
    if ($SkipSysmonConfig) { $args.Add("-SkipSysmonConfig") }
    if ($NoRestart) { $args.Add("-NoRestart") }
    Start-Process -FilePath "powershell.exe" -ArgumentList $args -Verb RunAs -Wait
    exit $LASTEXITCODE
}

Write-Host "=== Wazuh Windows agent connector ==="
Write-Host "Manager: $Manager"
Write-Host "Agent name: $AgentName"
if ($AgentGroup) { Write-Host "Agent group: $AgentGroup" }

if (-not (Test-Path -LiteralPath $MsiPath)) {
    Write-Host "Downloading Wazuh agent MSI..."
    Invoke-WebRequest -Uri $MsiUrl -OutFile $MsiPath
}

Write-Host "Installing/configuring Wazuh agent..."
$msiArgs = [System.Collections.Generic.List[string]]::new()
$msiArgs.Add("/i")
$msiArgs.Add($MsiPath)
$msiArgs.Add("/qn")
$msiArgs.Add("WAZUH_MANAGER=$Manager")
$msiArgs.Add("WAZUH_AGENT_NAME=$AgentName")
if ($AgentGroup) {
    $msiArgs.Add("WAZUH_AGENT_GROUP=$AgentGroup")
}
if ($RegistrationPassword) {
    $msiArgs.Add("WAZUH_REGISTRATION_PASSWORD=$RegistrationPassword")
}

$install = Start-Process -FilePath "msiexec.exe" -ArgumentList $msiArgs -Wait -PassThru
if ($install.ExitCode -notin @(0, 3010)) {
    throw "Wazuh agent installer failed with exit code $($install.ExitCode)."
}

$agentRoot = Find-WazuhAgentRoot
if (-not $agentRoot) {
    throw "Wazuh agent installation finished, but the agent directory was not found."
}

if (-not $SkipSysmonConfig) {
    Ensure-SysmonEventCollection -AgentRoot $agentRoot
}

if (-not $NoRestart) {
    Write-Host "Starting/restarting Wazuh agent service..."
    $service = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($service) {
        if ($service.Status -eq "Running") {
            Restart-Service -Name "WazuhSvc" -Force
        } else {
            Start-Service -Name "WazuhSvc"
        }
    } else {
        Write-Warning "WazuhSvc service was not found after installation."
    }
}

Show-EndpointState -Manager $Manager

Write-Host ""
Write-Host "Next checks:"
Write-Host "1. In the Wazuh dashboard, confirm this endpoint appears under Agents."
Write-Host "2. On the Wazuh manager, install backend/rules/wazuh/optional_custom/capstone_malware_behavior_rules.xml into /var/ossec/etc/rules/ and restart wazuh-manager."
Write-Host "3. If this app runs on Windows, expose the manager alerts file and set WAZUH_ALERT_LOG_PATH to that alerts.json path before starting the backend."
