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
$ran = @()

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
        $script:ran += $Name
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
# `--junit-xml` is written on failure as well as success, so a red run leaves a
# machine-readable record of *which* test failed and why. That matters because a
# runner's job log needs repository admin rights to read through the API: without
# this, a CI-only failure is diagnosable only by guessing or by pushing debug
# commits. The path is relative to the working directory above, so it lands in
# backend/ and is uploaded as an artifact by .github/workflows/ci.yml.
Invoke-Step 'backend: pytest'    (Join-Path $root 'backend')  "& '$venvPython' -m pytest -q --cov=app --cov-report=term-missing --junit-xml=gate-junit.xml"
Invoke-Step 'frontend: typecheck' (Join-Path $root 'frontend') 'npx tsc -b'
Invoke-Step 'frontend: eslint'   (Join-Path $root 'frontend') 'npm run lint'
Invoke-Step 'frontend: vitest'   (Join-Path $root 'frontend') 'npm run test:coverage'
Invoke-Step 'repo: secrets'      $root                        "& (Join-Path '$PSScriptRoot' 'check-no-secrets.ps1')"

Write-Host ''
foreach ($name in $ran) {
    $mark = if ($failed -contains $name) { 'FAIL' } else { 'ok  ' }
    Write-Host ("  {0} {1}" -f $mark, $name)
}

if ($failed.Count -gt 0) {
    Write-Host ('FAILED: ' + ($failed -join ', ')) -ForegroundColor Red
    # In CI, name the failing gate as an annotation. Without this, a red run says
    # only "Process completed with exit code 1", which is exactly as useful as no
    # pipeline at all - the annotations are also readable from the commit page and
    # from the Checks API without downloading a log.
    if ($env:GITHUB_ACTIONS -eq 'true') {
        foreach ($name in $failed) {
            Write-Host "::error title=gate failed::$name failed; open the 'Run the gate' step for its output"
        }
    }
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
