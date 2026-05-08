param(
    [ValidateSet("elastic", "reversinglabs", "yara-rules", "signature-base")]
    [string]$Source = "elastic",

    [string[]]$YaraRulesCategories = @(
        "malware",
        "maldocs",
        "webshells",
        "exploit_kits",
        "packers",
        "cve_rules",
        "email"
    )
)

$ErrorActionPreference = "Stop"

$sources = @{
    "elastic" = @{
        GitUrl = "https://github.com/elastic/protections-artifacts.git"
        SparsePaths = @("yara/rules")
        InnerPath = "yara\rules"
    }
    "reversinglabs" = @{
        Url = "https://github.com/reversinglabs/reversinglabs-yara-rules/archive/refs/heads/develop.zip"
        InnerPath = "reversinglabs-yara-rules-develop\yara"
    }
    "yara-rules" = @{
        Url = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
        InnerPath = "rules-master"
        GitUrl = "https://github.com/Yara-Rules/rules.git"
    }
    "signature-base" = @{
        Url = "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip"
        InnerPath = "signature-base-master\yara"
    }
}

$ruleRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$targetRoot = Join-Path $ruleRoot "external"
$target = Join-Path $targetRoot $Source
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("capstone-yara-" + [System.Guid]::NewGuid().ToString("N"))
$zipPath = Join-Path $tempRoot "$Source.zip"

New-Item -ItemType Directory -Path $tempRoot -Force | Out-Null
New-Item -ItemType Directory -Path $targetRoot -Force | Out-Null

try {
    if ($sources[$Source].ContainsKey("GitUrl")) {
        $clonePath = Join-Path $tempRoot $Source
        Write-Host "Cloning selected $Source rule paths..."
        git clone --depth 1 --filter=blob:none --sparse $sources[$Source].GitUrl $clonePath
        if ($LASTEXITCODE -ne 0) {
            throw "git clone failed with exit code $LASTEXITCODE"
        }

        Push-Location $clonePath
        try {
            if ($Source -eq "yara-rules") {
                git sparse-checkout set @YaraRulesCategories
            }
            else {
                git sparse-checkout set @($sources[$Source].SparsePaths)
            }
            if ($LASTEXITCODE -ne 0) {
                throw "git sparse-checkout failed with exit code $LASTEXITCODE"
            }
        }
        finally {
            Pop-Location
        }

        $sourceRules = if ($sources[$Source].ContainsKey("InnerPath")) {
            Join-Path $clonePath $sources[$Source].InnerPath
        }
        else {
            $clonePath
        }
        if (-not (Test-Path $sourceRules)) {
            throw "Expected rules directory not found: $sourceRules"
        }
    }
    else {
        Write-Host "Downloading $Source rules..."
        Invoke-WebRequest -Uri $sources[$Source].Url -OutFile $zipPath

        Write-Host "Extracting rules..."
        Expand-Archive -Path $zipPath -DestinationPath $tempRoot -Force

        $sourceRules = Join-Path $tempRoot $sources[$Source].InnerPath
        if (-not (Test-Path $sourceRules)) {
            throw "Expected rules directory not found: $sourceRules"
        }
    }

    if (Test-Path $target) { Remove-Item -LiteralPath $target -Recurse -Force }
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    foreach ($item in Get-ChildItem -Path $sourceRules -Force) {
        if ($item.Name -eq ".git") {
            continue
        }
        Copy-Item -LiteralPath $item.FullName -Destination $target -Recurse -Force
    }

    Write-Host "Rules installed to $target"
    Write-Host "Set YARA_EXTERNAL_RULES_PATH to this directory before starting the backend if you are not using the default source."
}
finally {
    if (Test-Path $tempRoot) {
        Remove-Item -LiteralPath $tempRoot -Recurse -Force
    }
}
