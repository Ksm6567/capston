param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    [Parameter(Mandatory = $true)]
    [string]$MySqlRootPassword,
    [Parameter(Mandatory = $true)]
    [string]$DefaultAdminUsername,
    [Parameter(Mandatory = $true)]
    [string]$DefaultAdminPassword
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$PythonVersion = '3.12.9'
$PythonInstallerUrl = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion-amd64.exe"
$MySqlVersion = '8.0.44'
$MySqlZipUrl = 'https://dev.mysql.com/get/Downloads/MySQL-8.0/mysql-8.0.44-winx64.zip'
$MySqlServiceName = 'CapstoneSIEMMySQL80'
$MySqlPort = 3306

function Ensure-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Download-File {
    param(
        [string]$Url,
        [string]$Destination
    )

    Ensure-Directory (Split-Path -Parent $Destination)
    Invoke-WebRequest -Uri $Url -OutFile $Destination
}

function Wait-ForService {
    param(
        [string]$Name,
        [int]$TimeoutSeconds = 60
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        $service = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($service -and $service.Status -eq 'Running') {
            return
        }
        Start-Sleep -Seconds 2
    } while ((Get-Date) -lt $deadline)

    throw "Service '$Name' did not reach the Running state in time."
}

function Escape-SqlString {
    param([string]$Value)
    return ($Value -replace '\\', '\\') -replace "'", "''"
}

function Set-MySqlPasswordEnvironment {
    param([string]$Password)
    if ([string]::IsNullOrEmpty($Password)) {
        Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue
        return
    }
    $env:MYSQL_PWD = $Password
}

function Invoke-MySqlQuery {
    param(
        [string]$MySqlExe,
        [string]$Query,
        [string]$Password = ''
    )

    Set-MySqlPasswordEnvironment -Password $Password
    try {
        & $MySqlExe --protocol=tcp -h 127.0.0.1 -P $MySqlPort -u root --execute=$Query
        return $LASTEXITCODE
    }
    finally {
        Remove-Item Env:MYSQL_PWD -ErrorAction SilentlyContinue
    }
}

Ensure-Directory $InstallDir

$InstallerCacheDir = Join-Path $InstallDir 'installer-cache'
$RuntimeDir = Join-Path $InstallDir 'runtime'
$PythonDir = Join-Path $RuntimeDir 'python312'
$VenvDir = Join-Path $RuntimeDir 'venv'
$PythonInstallerPath = Join-Path $InstallerCacheDir "python-$PythonVersion-amd64.exe"
$MySqlRootDir = Join-Path $InstallDir 'mysql'
$MySqlZipPath = Join-Path $InstallerCacheDir "mysql-$MySqlVersion-winx64.zip"
$MySqlExtractDir = Join-Path $MySqlRootDir "mysql-$MySqlVersion-winx64"
$MySqlDataDir = Join-Path $MySqlRootDir 'data'
$MySqlLogsDir = Join-Path $MySqlRootDir 'logs'
$MySqlIniPath = Join-Path $MySqlRootDir 'my.ini'
$RequirementsPath = Join-Path $InstallDir 'installer\runtime-requirements.txt'
$PythonExe = Join-Path $PythonDir 'python.exe'
$VenvPython = Join-Path $VenvDir 'Scripts\python.exe'
$MySqlServerExe = Join-Path $MySqlExtractDir 'bin\mysqld.exe'
$MySqlClientExe = Join-Path $MySqlExtractDir 'bin\mysql.exe'

Ensure-Directory $InstallerCacheDir
Ensure-Directory $RuntimeDir
Ensure-Directory $MySqlRootDir
Ensure-Directory $MySqlLogsDir

if (-not (Test-Path -LiteralPath $PythonExe)) {
    if (-not (Test-Path -LiteralPath $PythonInstallerPath)) {
        Download-File -Url $PythonInstallerUrl -Destination $PythonInstallerPath
    }

    $pythonInstallArgs = @(
        '/quiet',
        'InstallAllUsers=0',
        'PrependPath=0',
        'Include_launcher=0',
        'Include_test=0',
        'SimpleInstall=1',
        'Include_pip=1',
        "TargetDir=$PythonDir"
    )
    $pythonInstaller = Start-Process -FilePath $PythonInstallerPath -ArgumentList $pythonInstallArgs -Wait -PassThru
    if ($pythonInstaller.ExitCode -ne 0) {
        throw "Python installer exited with code $($pythonInstaller.ExitCode)."
    }
}

if (-not (Test-Path -LiteralPath $VenvPython)) {
    & $PythonExe -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to create the Python virtual environment.'
    }
}

& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to upgrade pip.'
}

& $VenvPython -m pip install -r $RequirementsPath
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to install the Python runtime requirements.'
}

if (-not (Test-Path -LiteralPath $MySqlServerExe)) {
    if (-not (Test-Path -LiteralPath $MySqlZipPath)) {
        Download-File -Url $MySqlZipUrl -Destination $MySqlZipPath
    }

    if (Test-Path -LiteralPath $MySqlExtractDir) {
        Remove-Item -LiteralPath $MySqlExtractDir -Recurse -Force
    }

    Expand-Archive -LiteralPath $MySqlZipPath -DestinationPath $MySqlRootDir -Force
}

$normalizedBaseDir = ($MySqlExtractDir -replace '\\', '/')
$normalizedDataDir = ($MySqlDataDir -replace '\\', '/')
$normalizedLogsDir = ($MySqlLogsDir -replace '\\', '/')

$myIni = @"
[mysqld]
basedir="$normalizedBaseDir"
datadir="$normalizedDataDir"
port=$MySqlPort
default_authentication_plugin=mysql_native_password
character-set-server=utf8mb4
collation-server=utf8mb4_unicode_ci
log-error="$normalizedLogsDir/mysql-error.log"

[client]
port=$MySqlPort
"@
Set-Content -LiteralPath $MySqlIniPath -Value $myIni -Encoding ASCII

if (-not (Test-Path -LiteralPath (Join-Path $MySqlDataDir 'mysql'))) {
    Ensure-Directory $MySqlDataDir
    & $MySqlServerExe "--defaults-file=$MySqlIniPath" --initialize-insecure --console
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to initialize the MySQL data directory.'
    }
}

$service = Get-Service -Name $MySqlServiceName -ErrorAction SilentlyContinue
if (-not $service) {
    & $MySqlServerExe --install $MySqlServiceName "--defaults-file=$MySqlIniPath"
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to install the MySQL Windows service.'
    }
}

$service = Get-Service -Name $MySqlServiceName -ErrorAction SilentlyContinue
if ($service.Status -ne 'Running') {
    Start-Service -Name $MySqlServiceName
}
Wait-ForService -Name $MySqlServiceName

$escapedRootPassword = Escape-SqlString $MySqlRootPassword
$escapedAdminUsername = Escape-SqlString $DefaultAdminUsername
$escapedAdminPassword = Escape-SqlString $DefaultAdminPassword

$configured = Invoke-MySqlQuery -MySqlExe $MySqlClientExe -Query 'SELECT 1;' -Password $MySqlRootPassword
if ($configured -ne 0) {
    $bootstrapSql = @"
ALTER USER IF EXISTS 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '$escapedRootPassword';
CREATE USER IF NOT EXISTS 'root'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY '$escapedRootPassword';
GRANT ALL PRIVILEGES ON *.* TO 'root'@'127.0.0.1' WITH GRANT OPTION;
FLUSH PRIVILEGES;
"@
    $bootstrapExit = Invoke-MySqlQuery -MySqlExe $MySqlClientExe -Query $bootstrapSql
    if ($bootstrapExit -ne 0) {
        throw 'Failed to configure the MySQL root account.'
    }
}

$databaseSql = @"
CREATE DATABASE IF NOT EXISTS siem_server CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
"@
$databaseExit = Invoke-MySqlQuery -MySqlExe $MySqlClientExe -Query $databaseSql -Password $MySqlRootPassword
if ($databaseExit -ne 0) {
    throw 'Failed to create the application database.'
}

$startScriptPath = Join-Path $InstallDir 'Start-Capstone-SIEM.ps1'
$escapedPsPassword = $MySqlRootPassword.Replace("'", "''")
$escapedPsAdminUsername = $DefaultAdminUsername.Replace("'", "''")
$escapedPsAdminPassword = $DefaultAdminPassword.Replace("'", "''")
$startScript = @"
`$ErrorActionPreference = 'Stop'
`$appRoot = Split-Path -Parent `$MyInvocation.MyCommand.Path
`$env:SIEM_DB_HOST = '127.0.0.1'
`$env:SIEM_DB_PORT = '$MySqlPort'
`$env:SIEM_DB_NAME = 'siem_server'
`$env:SIEM_DB_USER = 'root'
`$env:SIEM_DB_PASSWORD = '$escapedPsPassword'
`$env:SIEM_DEFAULT_USERNAME = '$escapedPsAdminUsername'
`$env:SIEM_DEFAULT_PASSWORD = '$escapedPsAdminPassword'
Start-Process -FilePath (Join-Path `$appRoot 'runtime\venv\Scripts\pythonw.exe') -ArgumentList @((Join-Path `$appRoot 'launcher.py')) -WorkingDirectory `$appRoot
"@
Set-Content -LiteralPath $startScriptPath -Value $startScript -Encoding UTF8
