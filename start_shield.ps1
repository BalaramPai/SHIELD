
$ErrorActionPreference = "Stop"

$Root = $PSScriptRoot
$Python = Join-Path $Root ".venv\Scripts\python.exe"
$Venv = Join-Path $Root ".venv\Scripts\Activate.ps1"
$Web = Join-Path $Root "apps\web"
$Vite = Join-Path $Web "node_modules\.bin\vite.cmd"
$Logs = Join-Path $Root "logs\launcher"
$State = Join-Path $Root ".shield-runtime"

New-Item -ItemType Directory -Force -Path $Logs, $State | Out-Null

if (-not (Test-Path $Python)) { throw "SHIELD .venv was not found." }
if (-not (Test-Path $Vite)) { throw "Frontend dependencies missing. Run npm install in apps\web." }

# Prevent accidental duplicate launcher sessions.
$Existing = Join-Path $State "launcher.lock"
if (Test-Path $Existing) {
    $OldPid = Get-Content $Existing -ErrorAction SilentlyContinue
    if ($OldPid -and (Get-Process -Id ([int]$OldPid) -ErrorAction SilentlyContinue)) {
        throw "SHIELD launcher may already be running (PID $OldPid). Use stop_shield.ps1 first."
    }
    Remove-Item $Existing -Force -ErrorAction SilentlyContinue
}
Set-Content $Existing $PID

function Test-Port {
    param([int]$Port)
    return [bool](Test-NetConnection 127.0.0.1 -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue)
}

function Wait-Port {
    param([int]$Port, [int]$Seconds = 120)
    $End = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $End) {
        if (Test-Port $Port) { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

function Start-Background {
    param(
        [string]$Name,
        [string]$File,
        [string[]]$Arguments,
        [string]$WorkingDirectory
    )

    $Out = Join-Path $Logs "$Name.out.log"
    $Err = Join-Path $Logs "$Name.err.log"
    $PidFile = Join-Path $State "$Name.pid"

    $Process = Start-Process `
        -FilePath $File `
        -ArgumentList $Arguments `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $Out `
        -RedirectStandardError $Err `
        -PassThru `
        -WindowStyle Hidden

    Set-Content $PidFile $Process.Id
    Write-Host "Started $Name (PID $($Process.Id))"
}

try {
    Write-Host "`nStarting SHIELD..." -ForegroundColor Cyan

    # Docker infrastructure.
    docker compose up -d
    if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed. Check Docker Desktop." }

    Write-Host "Waiting for Elasticsearch..."
    if (-not (Wait-Port 9200 180)) { throw "Elasticsearch did not become ready. Check Docker logs." }

    Write-Host "Waiting for Kibana..."
    if (-not (Wait-Port 5601 180)) { throw "Kibana did not become ready. Check Docker logs." }

    # Start Python services without opening terminals.
    # Run API without reload so its process is easier to manage.
    Start-Background "sensor" $Python @("scripts/development/run_sensor.py") $Root
    Start-Background "detector" $Python @("scripts/development/run_detector.py") $Root
    Start-Background "api" $Python @("-m", "uvicorn", "apps.api.main:app", "--host", "127.0.0.1", "--port", "8000") $Root

    Write-Host "Waiting for API..."
    if (-not (Wait-Port 8000 90)) {
        throw "API did not start. Inspect logs/launcher/api.err.log"
    }

    # Run the dashboard setup once after Kibana is reachable.
    Write-Host "Configuring Kibana dashboards..."
    & $Python (Join-Path $Root "scripts\development\create_dashboard.py") `
        *> (Join-Path $Logs "dashboard-setup.log")
    if ($LASTEXITCODE -ne 0) {
        Write-Warning "Dashboard setup returned an error. See logs/launcher/dashboard-setup.log"
    }

    # Start the web UI.
    Start-Background "frontend" $Vite @("--host", "127.0.0.1") $Web

    Write-Host "Waiting for frontend..."
    if (-not (Wait-Port 5173 60)) {
        throw "Frontend did not start. Inspect logs/launcher/frontend.err.log"
    }

    # Verify API health, not merely that its port is open.
    try {
        $Health = Invoke-RestMethod "http://127.0.0.1:8000/health" -TimeoutSec 10
        Write-Host "API: $($Health.status); Elasticsearch: $($Health.elasticsearch)"
    } catch {
        Write-Warning "API port is open but health check failed."
    }

    Start-Process "http://localhost:5173"

    Write-Host "`nSHIELD startup completed." -ForegroundColor Green
    Write-Host "Web UI:   http://localhost:5173"
    Write-Host "API docs: http://localhost:8000/docs"
    Write-Host "Kibana:   http://localhost:5601"
    Write-Host "Logs:     $Logs"
    Write-Host "Demo burst has NOT been started."
    Write-Host "Keep this launcher window open. Use stop_shield.ps1 to shut down SHIELD."
}
catch {
    Write-Host "`nSHIELD startup failed: $_" -ForegroundColor Red
    Write-Host "Inspect logs in $Logs"
    Remove-Item $Existing -Force -ErrorAction SilentlyContinue
    throw
}
