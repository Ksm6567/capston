param(
    [Parameter(Mandatory = $true)]
    [string]$InstallDir
)

$ErrorActionPreference = 'SilentlyContinue'
$MySqlServiceName = 'CapstoneSIEMMySQL80'
$MySqlServerExe = Join-Path $InstallDir 'mysql\mysql-8.0.44-winx64\bin\mysqld.exe'

$service = Get-Service -Name $MySqlServiceName -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne 'Stopped') {
        Stop-Service -Name $MySqlServiceName -Force
    }
    if (Test-Path -LiteralPath $MySqlServerExe) {
        & $MySqlServerExe --remove $MySqlServiceName | Out-Null
    }
}
