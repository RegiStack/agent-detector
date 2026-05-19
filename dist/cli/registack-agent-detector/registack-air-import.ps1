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

function Normalize-ImporterArgs {
    param([string[]]$ArgsIn)

    $output = New-Object System.Collections.Generic.List[string]
    $i = 0
    while ($i -lt $ArgsIn.Count) {
        $current = $ArgsIn[$i]
        $output.Add($current)
        if ($current -eq "--input" -and ($i + 1) -lt $ArgsIn.Count) {
            $nextArg = $ArgsIn[$i + 1]
            if ($nextArg -eq "-") {
                $output.Add($nextArg)
            } else {
                try {
                    $resolved = (Resolve-Path -LiteralPath $nextArg -ErrorAction Stop).Path
                    $output.Add($resolved)
                } catch {
                    $output.Add($nextArg)
                }
            }
            $i += 2
            continue
        }
        $i += 1
    }
    return ,$output.ToArray()
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$pythonScript = Join-Path $scriptRoot "registack-air-import.py"
if (-not (Test-Path -LiteralPath $pythonScript)) {
    throw "Python AIR importer script not found next to wrapper: $pythonScript"
}

$pythonCommand = Resolve-PythonCommand
$normalizedArgs = Normalize-ImporterArgs -ArgsIn $RemainingArgs

$pythonExecutable = $pythonCommand[0]
$pythonPrefixArgs = @()
if ($pythonCommand.Count -gt 1) {
    $pythonPrefixArgs = $pythonCommand[1..($pythonCommand.Count - 1)]
}

& $pythonExecutable @pythonPrefixArgs $pythonScript @normalizedArgs
exit $LASTEXITCODE
