# Registack AIR — Internal Pre-Release. © Registack.
param(
    [string]$InstallDir = $(if ($env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR) { $env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR } else { "$env:LOCALAPPDATA\Registack\agent-detector" }),
    [string]$ConfigPath = $(if ($env:REGISTACK_AGENT_DETECTOR_CONFIG) { $env:REGISTACK_AGENT_DETECTOR_CONFIG } else { "$env:LOCALAPPDATA\Registack\agent-detector\config.json" })
)

$ErrorActionPreference = "Stop"

$pyPath = Join-Path $InstallDir "registack-agent-detector.py"
$ps1Path = Join-Path $InstallDir "registack-agent-detector.ps1"
$cmdPath = Join-Path $InstallDir "registack-agent-detector.cmd"
$importPyPath = Join-Path $InstallDir "registack-air-import.py"
$importPs1Path = Join-Path $InstallDir "registack-air-import.ps1"
$importCmdPath = Join-Path $InstallDir "registack-air-import.cmd"
$linkPyPath = Join-Path $InstallDir "registack-air-link.py"
$linkPs1Path = Join-Path $InstallDir "registack-air-link.ps1"
$linkCmdPath = Join-Path $InstallDir "registack-air-link.cmd"
$pointerPath = Join-Path $InstallDir ".registack-agent-detector-config"

if (Test-Path -LiteralPath $pointerPath) {
    $pointerValue = (Get-Content -LiteralPath $pointerPath -ErrorAction SilentlyContinue | Select-Object -First 1)
    if (-not [string]::IsNullOrWhiteSpace($pointerValue)) {
        $ConfigPath = $pointerValue.Trim()
    }
}

foreach ($target in @($pyPath, $ps1Path, $cmdPath, $importPyPath, $importPs1Path, $importCmdPath, $linkPyPath, $linkPs1Path, $linkCmdPath, $pointerPath)) {
    if (Test-Path -LiteralPath $target) {
        Remove-Item -Force -LiteralPath $target
    }
}

foreach ($target in @($ConfigPath, (Join-Path (Split-Path -Parent $ConfigPath) "state.json"))) {
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
