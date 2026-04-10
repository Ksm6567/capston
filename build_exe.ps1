$ErrorActionPreference = "Stop"

$python = Join-Path $PSScriptRoot "venv\Scripts\python.exe"

if (-not (Test-Path $python)) {
    throw "Virtual environment python was not found at $python"
}

& $python -m PyInstaller `
  --noconfirm `
  --clean `
  --name capstone-siem `
  --onedir `
  --windowed `
  --add-data "frontend;frontend" `
  --add-data "backend\rules;backend\rules" `
  launcher.py
