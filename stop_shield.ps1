$ErrorActionPreference = "Continue"

$Root = (Resolve-Path $PSScriptRoot).Path.TrimEnd("\")
$State = Join-Path $Root ".shield-runtime"

Write-Host "`nStopping SHIELD application..." -ForegroundColor Cyan

# Read saved PIDs so we can verify which services were launched.
$SavedPids = @{}
foreach ($Name in @("frontend", "api", "detector", "sensor")) {
    $PidFile = Join-Path $State "$Name.pid"
    if (Test-Path $PidFile) {
        $RawPid = Get-Content $PidFile -Raw -ErrorAction SilentlyContinue
        $ParsedPid = 0
        if ([int]::TryParse(([string]$RawPid).Trim(), [ref]$ParsedPid)) {
            $SavedPids[$Name] = $ParsedPid
        }
    }
}

# Discover processes whose command lines reference this exact SHIELD project.
$Processes = Get-CimInstance Win32_Process -ErrorAction SilentlyContinue
$RootPattern = [regex]::Escape($Root)

$Targets = foreach ($Process in $Processes) {
    if (-not $Process.CommandLine) { continue }

    $Cmd = $Process.CommandLine
    $InsideProject = $Cmd -match $RootPattern

    if (-not $InsideProject) { continue }

    $Service = $null

    if ($Process.Name -eq "node.exe" -and $Cmd -match "vite") {
        $Service = "frontend"
    }
    elseif ($Process.Name -match "^python(w)?\.exe$") {
        if ($Cmd -match "scripts[\\/]+development[\\/]+run_sensor\.py|apps\.sensor\.run") {
            $Service = "sensor"
        }
        elseif ($Cmd -match "scripts[\\/]+development[\\/]+run_detector\.py|apps\.detector\.engine") {
            $Service = "detector"
        }
        elseif ($Cmd -match "uvicorn|scripts[\\/]+development[\\/]+run_api\.py|apps\.api\.main") {
            $Service = "api"
        }
    }

    if ($Service) {
        [PSCustomObject]@{
            Name = $Service
            PID = [int]$Process.ProcessId
            ParentPID = [int]$Process.ParentProcessId
        }
    }
}

# Stop only processes positively identified as SHIELD application services.
foreach ($Target in $Targets) {
    $Current = Get-CimInstance Win32_Process -Filter "ProcessId = $($Target.PID)" -ErrorAction SilentlyContinue
    if (-not $Current) { continue }

    try {
        Stop-Process -Id $Target.PID -Force -ErrorAction Stop
        Write-Host "Stopped $($Target.Name) (PID $($Target.PID))" -ForegroundColor Green
    }
    catch {
        Write-Warning "Could not stop $($Target.Name) (PID $($Target.PID)): $($_.Exception.Message)"
    }
}

# Remove stale PID files after attempting shutdown.
foreach ($Name in @("frontend", "api", "detector", "sensor")) {
    $PidFile = Join-Path $State "$Name.pid"
    if (Test-Path $PidFile) {
        Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
    }
}

# Do not kill the PowerShell session or launcher shell.
# Remove the lock file only; Docker remains untouched.
$Lock = Join-Path $State "launcher.lock"
if (Test-Path $Lock) {
    Remove-Item $Lock -Force -ErrorAction SilentlyContinue
}

Start-Sleep -Seconds 1

Write-Host "`nChecking SHIELD application ports..." -ForegroundColor Cyan
$Ports = @(5173, 8000)

foreach ($Port in $Ports) {
    $Listeners = Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue
    if ($Listeners) {
        Write-Warning "Port $Port is still listening (PID(s): $((@($Listeners | Select-Object -ExpandProperty OwningProcess -Unique)) -join ', ')). Check before stopping anything else."
    }
    else {
        Write-Host "Port $Port is free." -ForegroundColor Green
    }
}

Write-Host "`nSHIELD application shutdown attempted. Docker containers and Elasticsearch data were not changed." -ForegroundColor Cyan
