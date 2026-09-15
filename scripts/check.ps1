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
            Write-Host "::error title=gate failed::$name failed"
        }

        # Naming the gate is not enough. A job's log and its artifacts both need
        # repository admin rights to read through the API, so "backend: pytest
        # failed" is the whole story an outside observer can get - and R11 spent an
        # hour inferring a cause that one line of JUnit could have stated. The
        # report is parsed here and the failing tests are emitted as annotations,
        # which *are* readable without a token.
        $report = Join-Path $root 'backend\gate-junit.xml'
        if ($failed -contains 'backend: pytest' -and (Test-Path $report)) {
            [xml]$junit = Get-Content -Raw -LiteralPath $report
            $reported = 0
            foreach ($case in $junit.testsuites.testsuite.testcase) {
                # Interpolated, not added: XmlElement has no `+` operator.
                $problem = "$($case.failure)$($case.error)"
                if ([string]::IsNullOrWhiteSpace($problem)) { continue }
                if ($reported -ge 8) {
                    Write-Host '::error title=further failures::more tests failed; see backend/gate-junit.xml'
                    break
                }
                # A multi-line message collapses to its first line: an annotation
                # is a single line, and the first line of a JUnit `message`
                # attribute is the assertion itself ("AssertionError: ..."). The
                # element's text is a fallback for a report that carries no
                # message; splitting the element itself yields only its type name.
                $detail = "$($case.failure.message)$($case.error.message)"
                if ([string]::IsNullOrWhiteSpace($detail)) {
                    $detail = "$($case.failure.'#text')$($case.error.'#text')"
                }
                $first = (($detail -split "`n") | Where-Object { $_.Trim() } | Select-Object -First 1)
                $where = if ($case.classname) { "$($case.classname)::$($case.name)" } else { $case.name }
                # Built as a variable, not formatted inline: a bare `::` inside a
                # nested quoted expression is where PowerShell 5.1's parser gives
                # up, and the failure is a confusing "missing expression".
                $annotation = '::error title=test failed::{0} :: {1}' -f $where, $first.Trim()
                Write-Host $annotation
                $reported++
            }
            if ($reported -eq 0) {
                Write-Host '::error title=no test report::pytest failed but gate-junit.xml records no failing case'
            }
        }
    }
    exit 1
}
Write-Host 'All checks passed.' -ForegroundColor Green
exit 0
