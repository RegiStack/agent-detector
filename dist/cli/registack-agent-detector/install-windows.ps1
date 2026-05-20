# Registack AIR — Internal Pre-Release. © Registack.
param(
    [string]$BaseUrl = $(if ($env:REGISTACK_AGENT_DETECTOR_BASE_URL) { $env:REGISTACK_AGENT_DETECTOR_BASE_URL } else { "https://www.registack.eu/cli/registack-agent-detector" }),
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

function Get-ArtifactSourcePath([string]$Base, [string]$ArtifactName) {
    if ([string]::IsNullOrWhiteSpace($Base)) {
        throw "BaseUrl must not be empty."
    }
    if ($Base -match '^(https?)://') {
        return $null
    }
    if ($Base -match '^file://') {
        $uri = [System.Uri]$Base
        $localPath = $uri.LocalPath
        if ([string]::IsNullOrWhiteSpace($localPath)) {
            throw "Unable to resolve local path from file URL: $Base"
        }
        return Join-Path $localPath $ArtifactName
    }
    if (Test-Path -LiteralPath $Base) {
        return Join-Path $Base $ArtifactName
    }
    throw "Unsupported BaseUrl or local path: $Base"
}

function Fetch-Artifact([string]$Base, [string]$ArtifactName, [string]$DestinationPath) {
    $sourcePath = Get-ArtifactSourcePath -Base $Base -ArtifactName $ArtifactName
    if ($null -eq $sourcePath) {
        Invoke-WebRequest -UseBasicParsing -Uri "$Base/$ArtifactName" -OutFile $DestinationPath
        return
    }
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        throw "Missing artifact: $sourcePath"
    }
    Copy-Item -Force -LiteralPath $sourcePath -Destination $DestinationPath
}

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
    if ($env:SystemDrive) {
        Add-Candidate $list ($env:SystemDrive + "\")
    }
    Add-Candidate $list "$env:USERPROFILE\Applications"
    Add-Candidate $list "$env:USERPROFILE\.registack"
    Add-Candidate $list "$env:USERPROFILE\.codex"
    Add-Candidate $list "$env:USERPROFILE\.cursor"
    Add-Candidate $list "$env:USERPROFILE\.openclaw"
    Add-Candidate $list "$env:LOCALAPPDATA"
    Add-Candidate $list "$env:ProgramFiles"
    Add-Candidate $list "$env:USERPROFILE\Documents"
    Add-Candidate $list "$env:USERPROFILE\Downloads"
    Add-Candidate $list "$env:USERPROFILE"
    return ,$list.ToArray()
}

function Select-ScanDirWithPicker {
    Add-Type -AssemblyName System.Windows.Forms
    $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
    $dialog.Description = "Select default detection path for Registack AIR Agent Detector"
    $dialog.ShowNewFolderButton = $false
    if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
        throw "No folder selected."
    }
    if (-not (Test-Path -LiteralPath $dialog.SelectedPath)) {
        throw "Selected folder does not exist."
    }
    return $dialog.SelectedPath
}

$candidateScanDirs = Get-CandidateScanDirs
if ($candidateScanDirs.Count -eq 0) {
    throw "No predefined detection paths were found on this machine."
}

$pickerChoice = $candidateScanDirs.Count + 1

if ($ScanChoice -eq 0) {
    if ($NoPrompt) {
        throw "Installation requires a detection-path selection. Re-run interactively or with -ScanChoice."
    }
    Write-Host "Select default detection path:"
    for ($i = 0; $i -lt $candidateScanDirs.Count; $i++) {
        Write-Host ("  [{0}] {1}" -f ($i + 1), $candidateScanDirs[$i])
    }
    Write-Host ("  [{0}] {1}" -f $pickerChoice, "Choose folder in File Explorer...")
    while ($true) {
        $selected = Read-Host ("Choice [1-{0}]" -f $pickerChoice)
        $parsed = 0
        if ([int]::TryParse($selected, [ref]$parsed) -and $parsed -ge 1 -and $parsed -le $pickerChoice) {
            $ScanChoice = $parsed
            break
        }
        Write-Host ("Please select a number between 1 and {0}." -f $pickerChoice)
    }
}

if ($ScanChoice -lt 1 -or $ScanChoice -gt $pickerChoice) {
    throw "ScanChoice out of range. Valid values: 1-$pickerChoice"
}

if ($ScanChoice -eq $pickerChoice) {
    $selectedScanDir = Select-ScanDirWithPicker
} else {
    $selectedScanDir = $candidateScanDirs[$ScanChoice - 1]
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $ConfigPath) | Out-Null

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

Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-agent-detector.py" -DestinationPath $pyPath
Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-agent-detector.ps1" -DestinationPath $ps1Path
Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-air-import.py" -DestinationPath $importPyPath
Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-air-import.ps1" -DestinationPath $importPs1Path
Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-air-link.py" -DestinationPath $linkPyPath
Fetch-Artifact -Base $BaseUrl -ArtifactName "registack-air-link.ps1" -DestinationPath $linkPs1Path

$cmdBody = '@echo off' + "`r`n" +
    'powershell -ExecutionPolicy Bypass -File "%~dp0registack-agent-detector.ps1" %*'
Set-Content -Path $cmdPath -Value $cmdBody -Encoding ASCII

$importCmdBody = '@echo off' + "`r`n" +
    'powershell -ExecutionPolicy Bypass -File "%~dp0registack-air-import.ps1" %*'
Set-Content -Path $importCmdPath -Value $importCmdBody -Encoding ASCII

$linkCmdBody = '@echo off' + "`r`n" +
    'powershell -ExecutionPolicy Bypass -File "%~dp0registack-air-link.ps1" %*'
Set-Content -Path $linkCmdPath -Value $linkCmdBody -Encoding ASCII

$configObject = @{
    scan_profile = "persistent_selected_path"
    selected_primary_scan_dir = $selectedScanDir
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
& $importCmdPath --version | Out-Null
& $linkCmdPath --version | Out-Null

Write-Host "Registack AIR Agent Detector installed successfully at $InstallDir"
Write-Host "Registack AIR Importer installed successfully at $InstallDir"
Write-Host "Registack AIR Link installed successfully at $InstallDir"
Write-Host "Primary detection path: $selectedScanDir"
Write-Host "Default scan profile: persistent selected path"
Write-Host "Config: $ConfigPath"
Write-Host "Verify with: registack-agent-detector.cmd --version"
Write-Host "Importer verify: registack-air-import.cmd --version"
Write-Host "AIR link verify: registack-air-link.cmd --version"
