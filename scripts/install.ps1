# Exposure Checker — Windows installer
# Run from an elevated PowerShell prompt:
#   Set-ExecutionPolicy Bypass -Scope Process -Force
#   .\install.ps1
#
# What this does:
#   1. Checks Python 3.9+
#   2. Creates a venv in .\.venv
#   3. Installs the package into it
#   4. Adds a small launcher script to %LOCALAPPDATA%\Microsoft\WindowsApps
#      (which is already on PATH for most Windows 10/11 installs)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = Join-Path $repo ".venv"

Write-Host "Exposure Checker - Windows installer"
Write-Host ""

# Require Python 3.9+
try {
    $pyver = & python --version 2>&1
    if ($pyver -notmatch "Python 3\.(9|[1-9][0-9])") {
        Write-Host "Error: Python 3.9 or newer is required. Found: $pyver"
        Write-Host "Download from https://www.python.org/downloads/"
        exit 1
    }
} catch {
    Write-Host "Error: Python not found. Download from https://www.python.org/downloads/"
    exit 1
}

Write-Host "[1/3] Creating virtual environment..."
& python -m venv $venv

Write-Host "[2/3] Installing dependencies..."
& "$venv\Scripts\pip.exe" install --quiet -e $repo

Write-Host "[3/3] Creating launcher..."
$appsDir = "$env:LOCALAPPDATA\Microsoft\WindowsApps"
$launcher = @"
@echo off
"$venv\Scripts\python.exe" "$repo\exposure_checker.py" %*
"@
Set-Content -Path "$appsDir\exposure-checker.cmd" -Value $launcher

Write-Host ""
Write-Host "Done. Open a new terminal and run:"
Write-Host "  exposure-checker --full-audit"
Write-Host ""
Write-Host "Note: some checks (firewall, Defender, scheduled tasks) need an"
Write-Host "      elevated (Administrator) terminal for full results."
