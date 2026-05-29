param(
    [string]$BuiltEfi,
    [string]$DeployedEfi,
    [string]$ExpectedMarker
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $Root
$BuildModePath = Join-Path $Root "BuildMode.h"

if ([string]::IsNullOrWhiteSpace($BuiltEfi)) {
    $BuiltEfi = Join-Path $ProjectRoot "x64\Release\HolyHypervisor.efi"
}

if ([string]::IsNullOrWhiteSpace($ExpectedMarker) -and (Test-Path -LiteralPath $BuildModePath)) {
    $buildMode = Get-Content -LiteralPath $BuildModePath -Raw
    $markerMatch = [regex]::Match($buildMode, '#define\s+HOLY_BUILD_MARKER\s+"([^"]+)"')
    if ($markerMatch.Success) {
        $ExpectedMarker = $markerMatch.Groups[1].Value
    }
}
if ([string]::IsNullOrWhiteSpace($ExpectedMarker)) {
    Fail "Expected marker not provided and BuildMode.h marker could not be read."
}

function Fail($Message) {
    Write-Host "[EFI-CHECK][FAIL] $Message" -ForegroundColor Red
    exit 1
}

function Warn($Message) {
    Write-Host "[EFI-CHECK][WARN] $Message" -ForegroundColor Yellow
}

function Pass($Message) {
    Write-Host "[EFI-CHECK][OK] $Message" -ForegroundColor Green
}

function Info($Message) {
    Write-Host "[EFI-CHECK][INFO] $Message" -ForegroundColor Cyan
}

function Test-BytesContains([byte[]]$Bytes, [byte[]]$Needle) {
    if ($Needle.Length -eq 0 -or $Bytes.Length -lt $Needle.Length) {
        return $false
    }

    for ($i = 0; $i -le $Bytes.Length - $Needle.Length; $i++) {
        $matched = $true
        for ($j = 0; $j -lt $Needle.Length; $j++) {
            if ($Bytes[$i + $j] -ne $Needle[$j]) {
                $matched = $false
                break
            }
        }
        if ($matched) {
            return $true
        }
    }

    return $false
}

function Inspect-Efi($Path, $Label, $ExpectedMarker) {
    if (!(Test-Path -LiteralPath $Path)) {
        Fail "$Label EFI not found: $Path"
    }

    $item = Get-Item -LiteralPath $Path
    $hash = Get-FileHash -Algorithm SHA256 -LiteralPath $Path
    $bytes = [System.IO.File]::ReadAllBytes($item.FullName)
    $markerBytes = [System.Text.Encoding]::ASCII.GetBytes($ExpectedMarker)
    $containsMarker = Test-BytesContains $bytes $markerBytes

    Info "$Label path: $($item.FullName)"
    Info "$Label size: $($item.Length) bytes"
    Info "$Label mtime: $($item.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    Info "$Label sha256: $($hash.Hash)"

    if ($containsMarker) {
        Pass "$Label contains marker $ExpectedMarker"
    }
    else {
        Fail "$Label does not contain marker $ExpectedMarker"
    }

    [PSCustomObject]@{
        Path = $item.FullName
        Size = $item.Length
        Hash = $hash.Hash
        ContainsMarker = $containsMarker
    }
}

$built = Inspect-Efi -Path $BuiltEfi -Label "built" -ExpectedMarker $ExpectedMarker

if (![string]::IsNullOrWhiteSpace($DeployedEfi)) {
    $deployed = Inspect-Efi -Path $DeployedEfi -Label "deployed" -ExpectedMarker $ExpectedMarker

    if ($built.Hash -eq $deployed.Hash) {
        Pass "deployed EFI hash matches built EFI"
    }
    else {
        Warn "deployed EFI hash does not match built EFI"
        Write-Host "  built   : $($built.Hash)"
        Write-Host "  deployed: $($deployed.Hash)"
        exit 2
    }
}
else {
    Warn "No deployed EFI path was provided. Built artifact marker/hash check only."
}

Pass "EFI artifact check complete"
