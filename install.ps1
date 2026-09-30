# Reviewed installer for HF Model Provenance Scanner (Windows)
# Download this script from an immutable commit, inspect it, then run it locally.
# Set HF_SCANNER_REF to another reviewed full commit SHA only when intentionally upgrading.

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

$scannerRef = if ($env:HF_SCANNER_REF) { $env:HF_SCANNER_REF } else { "9a9aa1fe37dd3366a0034ab3d6d5b35222a26fc4" }
if (-not (Test-Path "$installDir\.git")) {
    if (Test-Path $installDir) { Remove-Item -Recurse -Force $installDir }
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
    git -C $installDir init --quiet
    git -C $installDir remote add origin https://github.com/poojakira/hf-model-provenance-scanner.git
}
git -C $installDir fetch --quiet --depth 1 origin $scannerRef
git -C $installDir checkout --quiet --detach FETCH_HEAD

# Create wrapper batch file
$wrapperContent = "@echo off`r`n$python -m scanner.cli %*"
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
Write-Host "  cd $installDir; $python -m scanner.cli tests\fixtures\binary --mode local --fail-on never"
