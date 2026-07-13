# Installer for HF Model Provenance Scanner (Windows)
#
# SECURITY NOTE
# -------------
# Running a remote script through "iex ((New-Object Net.WebClient)...)" executes
# whatever the server returns, unreviewed. For a supply-chain security tool that
# is the very risk we mitigate. Prefer one of:
#
#   1. pip (pinned):
#        pip install "git+https://github.com/poojakira/hf-model-provenance-scanner.git@v0.2.0"
#
#   2. Download, REVIEW, verify signature, then run:
#        Invoke-WebRequest -UseBasicParsing `
#          'https://raw.githubusercontent.com/poojakira/hf-model-provenance-scanner/v0.2.0/install.ps1' `
#          -OutFile install.ps1
#        Get-Content install.ps1        # review it
#        Get-AuthenticodeSignature .\install.ps1   # if a signed release is used
#        .\install.ps1
#
# This script pins to a release ref and will not modify your PATH without consent.

$ErrorActionPreference = "Stop"

Write-Host "Installing HF Model Provenance Scanner..." -ForegroundColor Cyan

# Pin to a reviewable ref; override with $env:HF_SCANNER_REF
$ref = if ($env:HF_SCANNER_REF) { $env:HF_SCANNER_REF } else { "v0.2.0" }
$repoUrl = "https://github.com/poojakira/hf-model-provenance-scanner.git"

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

if (Test-Path "$installDir\.git") {
    Write-Host "Updating existing installation (ref: $ref)..."
    git -C $installDir fetch --quiet --tags origin
    git -C $installDir checkout --quiet $ref
} else {
    git clone --quiet $repoUrl $installDir
    git -C $installDir checkout --quiet $ref 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "WARNING: ref '$ref' not found; staying on default branch. Pin a tag via HF_SCANNER_REF." -ForegroundColor Yellow
    }
}

# Optional GPG commit verification
if ($env:HF_SCANNER_VERIFY_GPG -eq "1") {
    Write-Host "Verifying commit signature..."
    git -C $installDir verify-commit HEAD
    if ($LASTEXITCODE -ne 0) {
        Write-Host "ERROR: GPG signature verification failed. Aborting." -ForegroundColor Red
        exit 1
    }
}

# Create wrapper batch file
$wrapperContent = "@echo off`r`ncd /d ""$installDir"" && $python -m scanner.cli %*"
Set-Content -Path "$installDir\hf-scanner.cmd" -Value $wrapperContent

# Add to user PATH only with explicit consent (never silently)
$userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($userPath -notlike "*$installDir*") {
    $modify = $false
    if ($env:HF_SCANNER_ASSUME_YES -eq "1") {
        $modify = $true
    } elseif ([Environment]::UserInteractive) {
        $reply = Read-Host "Add hf-scanner to your user PATH? [y/N]"
        if ($reply -match '^[Yy]') { $modify = $true }
    }
    if ($modify) {
        [Environment]::SetEnvironmentVariable("PATH", "$userPath;$installDir", "User")
        Write-Host "Added to user PATH (restart terminal to use 'hf-scanner')" -ForegroundColor Yellow
    } else {
        Write-Host "PATH not modified. Add '$installDir' to PATH manually, or run:" -ForegroundColor Yellow
        Write-Host "  $installDir\hf-scanner.cmd --help"
    }
}

Write-Host ""
Write-Host "HF Scanner installed to: $installDir (ref: $ref)" -ForegroundColor Green
Write-Host ""
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  $installDir\hf-scanner.cmd --help"
