# Registack AIR — Internal Pre-Release. © Registack.
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$RemainingArgs
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
    throw "Python 3.9+ is required but was not found. Install Python and try again."
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptRoot "registack-air-link.py"
if (-not (Test-Path -LiteralPath $pythonScript)) {
    throw "Python AIR link script not found next to wrapper: $pythonScript"
}

$pythonCommand = Resolve-PythonCommand
$pythonExecutable = $pythonCommand[0]
$pythonPrefixArgs = @()
if ($pythonCommand.Count -gt 1) {
    $pythonPrefixArgs = $pythonCommand[1..($pythonCommand.Count - 1)]
}

& $pythonExecutable @pythonPrefixArgs $pythonScript @RemainingArgs
exit $LASTEXITCODE
