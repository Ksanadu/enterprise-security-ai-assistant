# Starts the application locally without Docker.
#
#   pwsh -File scripts/run-local.ps1            start backend + frontend, keep running
#   pwsh -File scripts/run-local.ps1 -Check     start, smoke-test, shut down, exit code
#
# This is the non-container equivalent of `docker compose up`: one browser origin
# (the frontend) that serves the SPA and proxies /api to the backend, which is the
# same single-origin topology the nginx image provides.
#
# Ports default to 5173 (frontend) and 8000 (backend) and can be overridden with
# -FrontendPort / -BackendPort.

[CmdletBinding()]
param(
    [switch]$Check,
    [int]$FrontendPort = 5173,
    [int]$BackendPort = 8000,
    [int]$TimeoutSeconds = 90
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot

$python = Join-Path $root 'backend\.venv\Scripts\python.exe'
if (-not (Test-Path $python)) {
    Write-Host "Backend virtualenv not found: $python" -ForegroundColor Red
    Write-Host 'Create it first:  cd backend; python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt'
    exit 1
}

if (-not (Test-Path (Join-Path $root 'frontend\node_modules'))) {
    Write-Host "frontend\node_modules is missing. Run:  cd frontend; npm ci" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path (Join-Path $root '.env'))) {
    Write-Host 'No .env found; copying .env.example so the app has a configuration.' -ForegroundColor Yellow
    Copy-Item (Join-Path $root '.env.example') (Join-Path $root '.env')
}

$started = @()
$logDir = Join-Path $root 'logs'
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

function Start-AppProcess {
    param(
        [string]$Name,
        [string]$WorkingDirectory,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$LogStem
    )

    Write-Host "  starting $Name ..." -ForegroundColor DarkGray

    # Child output goes to files rather than the console. Two reasons: the
    # smoke-test verdict stays readable, and a native process writing to stderr
    # otherwise surfaces as a NativeCommandError that muddies this script's own
    # exit code.
    $stdout = Join-Path $logDir "$LogStem.out.log"
    $stderr = Join-Path $logDir "$LogStem.err.log"

    $process = Start-Process -FilePath $FilePath -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory -PassThru -NoNewWindow `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $script:started += $process
    return $process
}

function Show-LogTail {
    param([string]$LogStem, [int]$Lines = 15)

    foreach ($suffix in @('err', 'out')) {
        $path = Join-Path $logDir "$LogStem.$suffix.log"
        if (-not (Test-Path $path)) { continue }
        $tail = Get-Content -Path $path -Tail $Lines -ErrorAction SilentlyContinue
        if (-not $tail) { continue }
        Write-Host "  last $Lines line(s) of $path" -ForegroundColor DarkGray
        foreach ($line in $tail) { Write-Host "    $line" -ForegroundColor DarkGray }
    }
}

function Stop-All {
    foreach ($process in $script:started) {
        if ($null -eq $process) { continue }
        # /T also terminates the child tree: npm.cmd spawns node, and killing the
        # wrapper alone would leave the dev server holding the port.
        & taskkill.exe /T /F /PID $process.Id 2>&1 | Out-Null
    }
    $script:started = @()
}

function Wait-ForUrl {
    param([string]$Url, [string]$Label)

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                Write-Host "  $Label ready: $Url" -ForegroundColor DarkGray
                return $true
            }
        }
        catch {
            Start-Sleep -Milliseconds 700
        }
    }
    Write-Host "  $Label did NOT become ready within $TimeoutSeconds s ($Url)" -ForegroundColor Red
    return $false
}

$frontendUrl = "http://127.0.0.1:$FrontendPort"
$backendUrl = "http://127.0.0.1:$BackendPort"
$failures = @()

try {
    Write-Host ''
    Write-Host 'Starting Enterprise Security AI Assistant (local mode)' -ForegroundColor Cyan

    Start-AppProcess -Name 'backend (uvicorn)' -WorkingDirectory (Join-Path $root 'backend') `
        -FilePath $python -LogStem 'backend' `
        -Arguments @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', "$BackendPort") | Out-Null

    if (-not (Wait-ForUrl -Url "$backendUrl/api/v1/health" -Label 'backend')) {
        $failures += 'backend health'
        Show-LogTail -LogStem 'backend'
    }

    Start-AppProcess -Name 'frontend (vite)' -WorkingDirectory (Join-Path $root 'frontend') `
        -FilePath 'npm.cmd' -LogStem 'frontend' `
        -Arguments @('run', 'dev', '--', '--port', "$FrontendPort", '--strictPort') | Out-Null

    if (-not (Wait-ForUrl -Url "$frontendUrl/" -Label 'frontend')) {
        $failures += 'frontend'
        Show-LogTail -LogStem 'frontend'
    }

    if ($failures.Count -eq 0 -and -not $Check) {
        Write-Host ''
        Write-Host "  Application:  $frontendUrl" -ForegroundColor Green
        Write-Host "  API health:   $backendUrl/api/v1/health" -ForegroundColor Green
        Write-Host "  API docs:     $backendUrl/docs" -ForegroundColor Green
        Write-Host "  Logs:         $logDir" -ForegroundColor Green
        Write-Host ''
        Write-Host 'Press Ctrl+C to stop both processes.' -ForegroundColor Yellow
        while ($true) { Start-Sleep -Seconds 3600 }
    }

    if ($Check) {
        Write-Host ''
        Write-Host 'Smoke test' -ForegroundColor Cyan

        # NOTE: these must not be named $check / $checks. PowerShell variable
        # names are case-insensitive, so $check would be the same variable as the
        # [switch]$Check parameter, and assigning a hashtable to it fails with a
        # confusing "Cannot create object of type SwitchParameter" error.
        $probes = @(
            @{ Label = 'backend health';      Url = "$backendUrl/api/v1/health" },
            @{ Label = 'SPA document';        Url = "$frontendUrl/" },
            @{ Label = 'proxied API health';  Url = "$frontendUrl/api/v1/health" }
        )

        foreach ($probe in $probes) {
            try {
                $response = Invoke-WebRequest -Uri $probe.Url -UseBasicParsing -TimeoutSec 10
                if ($response.StatusCode -eq 200) {
                    Write-Host ("  [pass] {0,-20} {1}" -f $probe.Label, $probe.Url) -ForegroundColor Green
                }
                else {
                    Write-Host ("  [FAIL] {0,-20} HTTP {1}" -f $probe.Label, $response.StatusCode) -ForegroundColor Red
                    $failures += $probe.Label
                }
            }
            catch {
                Write-Host ("  [FAIL] {0,-20} {1}" -f $probe.Label, $_.Exception.Message) -ForegroundColor Red
                $failures += $probe.Label
            }
        }

        # The unauthenticated surface must not leak anything beyond liveness, and
        # a protected route must refuse an anonymous caller.
        try {
            $response = Invoke-WebRequest -Uri "$backendUrl/api/v1/tickets" -UseBasicParsing -TimeoutSec 10
            Write-Host ("  [FAIL] anonymous tickets returned HTTP {0}" -f $response.StatusCode) -ForegroundColor Red
            $failures += 'anonymous access to /tickets'
        }
        catch {
            # PowerShell 5.1 exposes StatusCode as an enum and 7.x as an int, so
            # cast rather than reading the backing field.
            $code = -1
            if ($null -ne $_.Exception.Response) {
                $code = [int]$_.Exception.Response.StatusCode
            }
            if ($code -eq 401) {
                Write-Host '  [pass] anonymous /api/v1/tickets rejected with 401' -ForegroundColor Green
            }
            else {
                Write-Host ("  [FAIL] anonymous /api/v1/tickets returned HTTP {0}, expected 401" -f $code) -ForegroundColor Red
                $failures += 'anonymous access status'
            }
        }
    }
}
finally {
    Stop-All
}

Write-Host ''
if ($failures.Count -gt 0) {
    Write-Host ('FAILED: ' + ($failures -join ', ')) -ForegroundColor Red
    Show-LogTail -LogStem 'backend'
    Show-LogTail -LogStem 'frontend'
    exit 1
}
Write-Host 'Local run smoke test passed.' -ForegroundColor Green
exit 0
