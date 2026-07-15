# One-line installer for HF Model Provenance Scanner (Windows)
# Usage: iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/main/install.ps1'))

$ErrorActionPreference = "Stop"

Write-Host "Installing HF Model Provenance Scanner..." -ForegroundColor Cyan

# Check Python
$python = $null
if (Get-Command py -ErrorAction SilentlyContinue) { $python = "py" }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $python = "python" }
elseif (Get-Command python3 -ErrorAction SilentlyContinue) { $python = "python3" }
else {
    Write-Host "ERROR: Python 3.9+ is required. Install from https://python.org/downloads" -ForegroundColor Red
    exit 1
}

# Check version
$version = & $python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
$parts = $version.Split('.')
if ([int]$parts[0] -lt 3 -or ([int]$parts[0] -eq 3 -and [int]$parts[1] -lt 9)) {
    Write-Host "ERROR: Python 3.9+ required, found $version" -ForegroundColor Red
    exit 1
}

# Install directory
$installDir = if ($env:HF_SCANNER_DIR) { $env:HF_SCANNER_DIR } else { "$env:USERPROFILE\.hf-scanner" }

if (Test-Path $installDir) {
    Write-Host "Updating existing installation..."
    Push-Location $installDir
    git pull --quiet
    Pop-Location
} else {
    git clone --depth 1 https://github.com/poojakira/hf-model-provenance-scanner.git $installDir
}

# Install editable package and create wrapper batch file
Push-Location $installDir
& $python -m pip install -e .
Pop-Location
$pythonCmd = (Get-Command $python).Source
$wrapperContent = "@echo off`r`n`"$pythonCmd`" `"$installDir\scanner\cli.py`" %*"
Set-Content -Path "$installDir\hf-scanner.cmd" -Value $wrapperContent
# Add to user PATH if not present
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
    Write-Host "Added to user PATH (restart terminal to use 'hf-scanner' command)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "HF Scanner installed to: $installDir" -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  cd $installDir"
Write-Host "  $python -m scanner.cli --help"
Write-Host ""
Write-Host "Or restart PowerShell and use:"
Write-Host "  hf-scanner --help"
Write-Host ""
Write-Host "Quick test:" -ForegroundColor Cyan
Write-Host "  hf-scanner `"$installDir\tests\fixtures\binary`" --mode local --fail-on never"
