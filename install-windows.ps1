# Registack AIR — Internal Pre-Release. © Registack.
param(
    [string]$BaseUrl = $(if ($env:REGISTACK_AGENT_DETECTOR_BASE_URL) { $env:REGISTACK_AGENT_DETECTOR_BASE_URL } else { "https://registack.eu/cli/registack-agent-detector" }),
    [string]$InstallDir = $(if ($env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR) { $env:REGISTACK_AGENT_DETECTOR_INSTALL_DIR } else { "$env:LOCALAPPDATA\Registack\agent-detector" }),
    [int]$ScanChoice = $(if ($env:REGISTACK_AGENT_DETECTOR_SCAN_CHOICE) { [int]$env:REGISTACK_AGENT_DETECTOR_SCAN_CHOICE } else { 0 }),
    [string]$ConfigPath = $(if ($env:REGISTACK_AGENT_DETECTOR_CONFIG) { $env:REGISTACK_AGENT_DETECTOR_CONFIG } else { "$env:LOCALAPPDATA\Registack\agent-detector\config.json" }),
    [switch]$NoPrompt
)

$ErrorActionPreference = "Stop"

function Resolve-PythonCommand {
    if (Get-Command py -ErrorAction SilentlyContinue) {
        return @("py", "-3")
    }
    if (Get-Command python -ErrorAction SilentlyContinue) {
        return @("python")
    }
    if (Get-Command python3 -ErrorAction SilentlyContinue) {
        return @("python3")
    }
    throw "Python 3.9+ is required but was not found."
}

$null = Resolve-PythonCommand

function Add-Candidate([System.Collections.Generic.List[string]]$List, [string]$Candidate) {
    if ([string]::IsNullOrWhiteSpace($Candidate)) {
        return
    }
    if (-not (Test-Path -LiteralPath $Candidate)) {
        return
    }
    if (-not ($List.Contains($Candidate))) {
        $List.Add($Candidate) | Out-Null
    }
}

function Get-CandidateScanDirs {
    $list = New-Object 'System.Collections.Generic.List[string]'
    Add-Candidate $list "$env:USERPROFILE\Applications"
    Add-Candidate $list "$env:LOCALAPPDATA"
    Add-Candidate $list "$env:ProgramFiles"
    Add-Candidate $list "$env:USERPROFILE\Documents"
    Add-Candidate $list "$env:USERPROFILE\Downloads"
    Add-Candidate $list "$env:USERPROFILE"
    return ,$list.ToArray()
}

$candidateScanDirs = Get-CandidateScanDirs
if ($candidateScanDirs.Count -eq 0) {
    throw "No predefined detection paths were found on this machine."
}

if ($ScanChoice -eq 0) {
    if ($NoPrompt) {
        throw "Installation requires a detection-path selection. Re-run interactively or with -ScanChoice."
    }
    Write-Host "Select default detection path:"
    for ($i = 0; $i -lt $candidateScanDirs.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $candidateScanDirs[$i])
    }
    while ($true) {
        $selected = Read-Host ("Choice [1-{0}]" -f $candidateScanDirs.Count)
        $parsed = 0
        if ([int]::TryParse($selected, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $candidateScanDirs.Count) {
            $ScanChoice = $parsed
            break
        }
        Write-Host ("Please select a number between 1 and {0}." -f $candidateScanDirs.Count)
    }
}

if ($ScanChoice -lt 1 -or $ScanChoice -gt $candidateScanDirs.Count) {
    throw "ScanChoice out of range. Valid values: 1-$($candidateScanDirs.Count)"
}

$selectedScanDir = $candidateScanDirs[$ScanChoice - 1]

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ConfigPath) | Out-Null

$pyPath = Join-Path $InstallDir "registack-agent-detector.py"
$ps1Path = Join-Path $InstallDir "registack-agent-detector.ps1"
$cmdPath = Join-Path $InstallDir "registack-agent-detector.cmd"
$pointerPath = Join-Path $InstallDir ".registack-agent-detector-config"

Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/registack-agent-detector.py" -OutFile $pyPath
Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/registack-agent-detector.ps1" -OutFile $ps1Path

$cmdBody = '@echo off' + "`r`n" +
    'powershell -ExecutionPolicy Bypass -File "%~dp0registack-agent-detector.ps1" %*'
Set-Content -Path $cmdPath -Value $cmdBody -Encoding ASCII

$configObject = @{
    default_scan_dirs = @($selectedScanDir)
}
$configObject | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigPath -Encoding UTF8
Set-Content -Path $pointerPath -Value $ConfigPath -Encoding UTF8

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
$pathEntries = if ([string]::IsNullOrWhiteSpace($userPath)) { @() } else { $userPath -split ";" }
if (-not ($pathEntries | Where-Object { $_ -eq $InstallDir })) {
    $newUserPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $InstallDir } else { "$userPath;$InstallDir" }
    [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
}

& $cmdPath --version | Out-Null

Write-Host "Registack AIR Agent Detector installed successfully at $InstallDir"
Write-Host "Selected detection path: $selectedScanDir"
Write-Host "Config: $ConfigPath"
Write-Host "Verify with: registack-agent-detector.cmd --version"
