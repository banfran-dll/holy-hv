#Requires -RunAsAdministrator
<#
.SYNOPSIS
    HolyHypervisor Installer / Uninstaller

.DESCRIPTION
    Installs HolyHypervisor.efi onto the EFI System Partition as a replacement
    for bootmgfw.efi (the Windows Boot Manager).
    The original bootmgfw.efi is preserved as bootmgfw_orig.efi.

    IMPORTANT: Secure Boot must be DISABLED in BIOS before rebooting.

.PARAMETER Uninstall
    Restore the original bootmgfw.efi and remove HolyHypervisor files.

.EXAMPLE
    # Install
    .\install.ps1

    # Uninstall / restore
    .\install.ps1 -Uninstall
#>
param(
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$MountPoint = "M:"
$EspBase    = "$MountPoint\EFI\Microsoft\Boot"

function Mount-ESP {
    Write-Host "[ESP] Mounting EFI System Partition as $MountPoint ..." -ForegroundColor Cyan
    try { mountvol $MountPoint /D 2>$null } catch {}  # unmount if already mounted
    Start-Sleep -Milliseconds 300
    $result = mountvol $MountPoint /S 2>&1
    Start-Sleep -Milliseconds 800
    if (-not (Test-Path "$MountPoint\EFI")) {
        Write-Host "[ERROR] ESP mount failed or EFI directory not found." -ForegroundColor Red
        Write-Host "        Try running: mountvol M: /S  manually." -ForegroundColor Yellow
        exit 1
    }
    Write-Host "        Mounted OK." -ForegroundColor Green
}

function Dismount-ESP {
    Write-Host "[ESP] Unmounting ..." -ForegroundColor Cyan
    mountvol $MountPoint /D 2>$null
    Write-Host "        Done." -ForegroundColor Green
}

# ─── UNINSTALL ────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Write-Host ""
    Write-Host " ========================================" -ForegroundColor Magenta
    Write-Host "  HolyHypervisor -- UNINSTALL" -ForegroundColor Magenta
    Write-Host " ========================================" -ForegroundColor Magenta
    Write-Host ""

    Mount-ESP

    $OrigPath = "$EspBase\bootmgfw_orig.efi"
    $BmgrPath = "$EspBase\bootmgfw.efi"

    if (-not (Test-Path $OrigPath)) {
        Write-Host "[WARN] bootmgfw_orig.efi not found - HolyHypervisor may not be installed." -ForegroundColor Yellow
        Dismount-ESP
        exit 0
    }

    Write-Host "[1/2] Restoring original bootmgfw.efi ..." -ForegroundColor Yellow
    Copy-Item $OrigPath $BmgrPath -Force
    Write-Host "      Restored." -ForegroundColor Green

    Write-Host "[2/2] Removing bootmgfw_orig.efi ..." -ForegroundColor Yellow
    Remove-Item $OrigPath -Force
    Write-Host "      Removed." -ForegroundColor Green

    Dismount-ESP

    Write-Host ""
    Write-Host " ========================================" -ForegroundColor Green
    Write-Host "  Uninstall complete. Original boot manager restored." -ForegroundColor Green
    Write-Host " ========================================" -ForegroundColor Green
    Write-Host ""
    exit 0
}

# ─── INSTALL ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host " ========================================" -ForegroundColor Cyan
Write-Host "  HolyHypervisor -- INSTALL" -ForegroundColor Cyan
Write-Host "  'Find rest in God' -- Psalms 62:5" -ForegroundColor Cyan
Write-Host " ========================================" -ForegroundColor Cyan
Write-Host ""

# Check EFI binary exists
$SourceEfi = Join-Path $PSScriptRoot "projects\x64\Release\HolyHypervisor.efi"
if (-not (Test-Path $SourceEfi)) {
    Write-Host "[ERROR] projects\x64\Release\HolyHypervisor.efi not found." -ForegroundColor Red
    Write-Host "        Please build the project in Visual Studio first." -ForegroundColor Yellow
    exit 1
}

Mount-ESP

$BmgrPath = "$EspBase\bootmgfw.efi"
$OrigPath = "$EspBase\bootmgfw_orig.efi"

# Verify Windows Boot Manager exists
if (-not (Test-Path $BmgrPath)) {
    Write-Host "[ERROR] $BmgrPath not found." -ForegroundColor Red
    Write-Host "        Is this the correct EFI System Partition?" -ForegroundColor Yellow
    Dismount-ESP
    exit 1
}

# Step 1: Backup
if (-not (Test-Path $OrigPath)) {
    Write-Host "[1/3] Backing up original bootmgfw.efi ..." -ForegroundColor Yellow
    Copy-Item $BmgrPath $OrigPath
    Write-Host "      Saved to: $OrigPath" -ForegroundColor Green
} else {
    Write-Host "[1/3] Backup already exists - skipping backup." -ForegroundColor Green
    Write-Host "      ($OrigPath)" -ForegroundColor DarkGray
}

# Step 2: Install HolyHypervisor
Write-Host "[2/3] Installing HolyHypervisor.efi as bootmgfw.efi ..." -ForegroundColor Yellow
Copy-Item $SourceEfi $BmgrPath -Force
Write-Host "      Installed." -ForegroundColor Green

# Step 3: Verify
Write-Host "[3/3] Verifying ..." -ForegroundColor Yellow
$InstalledSize = (Get-Item $BmgrPath).Length
$SourceSize    = (Get-Item $SourceEfi).Length
if ($InstalledSize -eq $SourceSize) {
    Write-Host "      File sizes match ($($InstalledSize) bytes). OK." -ForegroundColor Green
} else {
    Write-Host "      [WARN] Size mismatch! Installation may be incomplete." -ForegroundColor Yellow
}

Dismount-ESP

Write-Host ""
Write-Host " ========================================" -ForegroundColor Green
Write-Host "  Installation complete!" -ForegroundColor Green
Write-Host " ========================================" -ForegroundColor Green
Write-Host ""
Write-Host " BEFORE REBOOTING:" -ForegroundColor Yellow
Write-Host "   1. Enter BIOS/UEFI settings" -ForegroundColor Yellow
Write-Host "   2. Disable Secure Boot" -ForegroundColor Yellow
Write-Host "   3. Save and exit" -ForegroundColor Yellow
Write-Host ""
Write-Host " TO UNINSTALL later: run  .\install.ps1 -Uninstall" -ForegroundColor Cyan
Write-Host ""
