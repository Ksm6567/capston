param(
    [string]$Branch = "master"
)

$ErrorActionPreference = "Stop"

$ruleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$target = Join-Path $ruleRoot "official"
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("capstone-wazuh-ruleset-" + [System.Guid]::NewGuid().ToString("N"))
$clonePath = Join-Path $tempRoot "wazuh-ruleset"

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null

try {
    Write-Host "Cloning official Wazuh ruleset from wazuh/wazuh-ruleset..."
    git clone --depth 1 --branch $Branch --filter=blob:none --sparse https://github.com/wazuh/wazuh-ruleset.git $clonePath
    if ($LASTEXITCODE -ne 0) {
        throw "git clone failed with exit code $LASTEXITCODE"
    }

    Push-Location $clonePath
    try {
        git sparse-checkout set rules decoders lists
        if ($LASTEXITCODE -ne 0) {
            throw "git sparse-checkout failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }

    if (Test-Path $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
    }
    New-Item -ItemType Directory -Path $target -Force | Out-Null

    foreach ($name in @("rules", "decoders", "lists")) {
        $sourcePath = Join-Path $clonePath $name
        if (Test-Path $sourcePath) {
            Copy-Item -LiteralPath $sourcePath -Destination $target -Recurse -Force
        }
    }

    $metadata = @{
        source = "https://github.com/wazuh/wazuh-ruleset"
        branch = $Branch
        synced_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } | ConvertTo-Json
    Set-Content -Path (Join-Path $target "source.json") -Value $metadata -Encoding UTF8

    Write-Host "Official Wazuh ruleset copied to $target"
    Write-Host "Use this as a reference copy. Runtime detection should still be performed by a Wazuh manager."
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
