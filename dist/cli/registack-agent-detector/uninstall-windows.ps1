# Registack AIR — Internal Pre-Release. © Registack.
param(
    [string]$InstallDir = $(if ($env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR) { $env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR } else { "$env:LOCALAPPDATA\Registack\agent-detector" })
)

$ErrorActionPreference = "Stop"

$pyPath = Join-Path $InstallDir "registack-agent-detector.py"
$ps1Path = Join-Path $InstallDir "registack-agent-detector.ps1"
$cmdPath = Join-Path $InstallDir "registack-agent-detector.cmd"
$pointerPath = Join-Path $InstallDir ".registack-agent-detector-config"

foreach ($target in @($pyPath, $ps1Path, $cmdPath, $pointerPath)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -Force -LiteralPath $target
    }
}

if (Test-Path -LiteralPath $InstallDir) {
    $remaining = Get-ChildItem -LiteralPath $InstallDir -Force -ErrorAction SilentlyContinue
    if (-not $remaining) {
        Remove-Item -Force -LiteralPath $InstallDir
    }
}

Write-Host "Registack AIR Agent Detector uninstall complete."
