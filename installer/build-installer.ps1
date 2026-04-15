$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$installerScript = Join-Path $PSScriptRoot 'capstone-siem-installer.iss'
$isccCandidates = @(@(
    (Get-Command ISCC.exe -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
    (Join-Path $env:LOCALAPPDATA 'Programs\Inno Setup 6\ISCC.exe'),
    'C:\Program Files (x86)\Inno Setup 6\ISCC.exe',
    'C:\Program Files\Inno Setup 6\ISCC.exe'
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique)

if (-not $isccCandidates) {
    throw 'Inno Setup Compiler (ISCC.exe) was not found. Install Inno Setup 6, then run this script again.'
}

$iscc = $isccCandidates[0]
Push-Location $PSScriptRoot
try {
    & $iscc $installerScript
    if ($LASTEXITCODE -ne 0) {
        throw "ISCC exited with code $LASTEXITCODE."
    }
}
finally {
    Pop-Location
}
