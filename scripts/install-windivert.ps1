<#
.SYNOPSIS
    Fetch the official signed WinDivert 2.2 binaries next to netrocket.exe.

.DESCRIPTION
    NetRocket does not bundle WinDivert: it is LGPLv3/GPLv2 and must remain a
    separate, replaceable component. This script downloads the official release,
    verifies the Authenticode signature, and copies only the two files the
    runtime needs. Run it from an elevated PowerShell in the directory that
    contains netrocket.exe.

.NOTES
    Requires: PowerShell 5.1+, an internet connection, Administrator.
#>
[CmdletBinding()]
param(
    [string]$Version = '2.2.2',
    [string]$Destination = '.',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'

$isAdmin = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    throw 'Run this script from an elevated PowerShell (WinDivert needs Administrator).'
}

$zip = Join-Path $env:TEMP "WinDivert-$Version.zip"
$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version.zip"
Write-Host "downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

# Extract into a scratch directory, then copy only what we need.
$scratch = Join-Path $env:TEMP "windivert-$Version"
if (Test-Path $scratch) { Remove-Item $scratch -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $scratch -Force

$wanted = @('WinDivert.dll', 'WinDivert64.sys')
foreach ($name in $wanted) {
    $src = Join-Path $scratch "WinDivert-$Version\x64\$name"
    if (-not (Test-Path $src)) { throw "release archive is missing x64\$name" }

    # Never install an unsigned driver binary.
    $sig = Get-AuthenticodeSignature $src
    if ($sig.Status -ne 'Valid') {
        throw "$name is not validly signed ($($sig.Status)); refusing to install it."
    }
    Write-Host ("verified signature: {0} <- {1}" -f $name, $sig.SignerCertificate.Subject)

    $dst = Join-Path $Destination $name
    if ((Test-Path $dst) -and -not $Force) {
        Write-Host "$name already present (use -Force to replace)"
    } else {
        Copy-Item $src $dst -Force
        Write-Host "installed $dst"
    }
}

Remove-Item $zip -Force -ErrorAction SilentlyContinue
Remove-Item $scratch -Recurse -Force -ErrorAction SilentlyContinue

Write-Host @"

Done. WinDivert $Version is installed next to netrocket.exe.
The driver itself is installed on first `netrocket run` (it needs Administrator).

Licence reminder: WinDivert is dual LGPLv3/GPLv2. If you redistribute these
files, include its licence text and keep the driver as a separate, replaceable
component. See docs/SECURITY.md.
"@
