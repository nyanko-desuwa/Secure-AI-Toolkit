# Cross-platform launcher for scripts/validate_repository.py
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
if (-not $Root) { $Root = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent }
$Script = Join-Path $PSScriptRoot "validate_repository.py"

function Find-Python {
    foreach ($cmd in @("py", "python3", "python")) {
        $found = Get-Command $cmd -ErrorAction SilentlyContinue
        if ($found) {
            if ($cmd -eq "py") { return @("py", "-3") }
            return @($cmd)
        }
    }
    throw "Python 3 is required"
}

$py = Find-Python
& $py[0] @($py[1..($py.Length-1)]) $Script @args
exit $LASTEXITCODE
