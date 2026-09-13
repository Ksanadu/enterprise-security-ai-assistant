# Runs every quality gate for the project.
# Usage:  pwsh -File scripts/check.ps1
#
#   backend  : ruff, mypy, pytest (with a coverage floor)
#   frontend : tsc, eslint, vitest (with coverage thresholds)
#   repo     : secret / ignore-rule check
#
# Coverage is part of the gate, not an optional extra: a suite that cannot see its
# own blind spots needs the numbers measured on every change, or the same class of
# defect returns the next time somebody widens a regex or deletes a test.

$ErrorActionPreference = 'Continue'
$root = Split-Path -Parent $PSScriptRoot
$failed = @()

function Invoke-Step {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$Command
    )

    Write-Host ''
    Write-Host "=== $Name ===" -ForegroundColor Cyan
    Push-Location $WorkingDirectory
    try {
        Invoke-Expression $Command
        if ($LASTEXITCODE -ne 0) { $script:failed += $Name }
    }
    finally {
        Pop-Location
    }
}

$venvPython = Join-Path $root 'backend\.venv\Scripts\python.exe'
if (-not (Test-Path $venvPython)) {
    Write-Host "Backend virtualenv not found at $venvPython" -ForegroundColor Red
    Write-Host 'Create it first:  cd backend; python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt'
    exit 1
}

Invoke-Step 'backend: ruff'      (Join-Path $root 'backend')  "& '$venvPython' -m ruff check app tests"
Invoke-Step 'backend: mypy'      (Join-Path $root 'backend')  "& '$venvPython' -m mypy app"
Invoke-Step 'backend: pytest'    (Join-Path $root 'backend')  "& '$venvPython' -m pytest -q --cov=app --cov-report=term-missing"
Invoke-Step 'frontend: typecheck' (Join-Path $root 'frontend') 'npx tsc -b'
Invoke-Step 'frontend: eslint'   (Join-Path $root 'frontend') 'npm run lint'
Invoke-Step 'frontend: vitest'   (Join-Path $root 'frontend') 'npm run test:coverage'
Invoke-Step 'repo: secrets'      $root                        "& (Join-Path '$PSScriptRoot' 'check-no-secrets.ps1')"

Write-Host ''
if ($failed.Count -gt 0) {
    Write-Host ('FAILED: ' + ($failed -join ', ')) -ForegroundColor Red
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
