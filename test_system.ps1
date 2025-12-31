$ErrorActionPreference = "Continue"

Write-Host "Starting API..."
$apiProcess = Start-Process python -ArgumentList "-m src.api.main" -PassThru -NoNewWindow
if ($apiProcess.Id) {
    Write-Host "API started with PID: $($apiProcess.Id)"
} else {
    Write-Error "Failed to start API"
    exit 1
}

# Wait for API to start
Start-Sleep -Seconds 10

Write-Host "Testing API endpoints..."
try {
    $r = Invoke-WebRequest "http://localhost:8000/" -Method Get -ErrorAction Stop
    Write-Host "Root: $($r.StatusCode) $($r.StatusDescription)"
} catch {
    Write-Host "Root check failed: $_"
}

try {
    $r = Invoke-WebRequest "http://localhost:8000/health" -Method Get -ErrorAction Stop
    Write-Host "Health: $($r.StatusCode) $($r.StatusDescription)"
} catch {
    Write-Host "Health check failed: $_"
}

try {
    $r = Invoke-WebRequest "http://localhost:8000/stats" -Method Get -ErrorAction Stop
    Write-Host "Stats: $($r.StatusCode) $($r.StatusDescription)"
} catch {
    Write-Host "Stats check failed: $_"
}

Write-Host "Starting Dashboard..."
# Serving static files
$dashProcess = Start-Process python -ArgumentList "-m http.server 3000 --directory src/api/static" -PassThru -NoNewWindow
if ($dashProcess.Id) {
    Write-Host "Dashboard started with PID: $($dashProcess.Id)"
}

Write-Host "Starting Scheduler..."
# Using module execution instead of 'arachne' command for safety
$schedProcess = Start-Process python -ArgumentList "-m src.cli.main system start --workers 2" -PassThru -NoNewWindow
if ($schedProcess.Id) {
    Write-Host "Scheduler started with PID: $($schedProcess.Id)"
}

Write-Host "Running services for 10 seconds..."
Start-Sleep -Seconds 10

Write-Host "Stopping processes..."
Stop-Process -Id $apiProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $dashProcess.Id -Force -ErrorAction SilentlyContinue
Stop-Process -Id $schedProcess.Id -Force -ErrorAction SilentlyContinue

Write-Host "Running Integration Tests..."
# Verify pytest exists or use python -m pytest
python -m pytest tests/integration/ -v
