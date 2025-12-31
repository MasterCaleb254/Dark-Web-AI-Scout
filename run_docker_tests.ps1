$ErrorActionPreference = "Continue"

Write-Host "Waiting for Docker services to be ready..."
$retries = 60  # Increased retries since build is slow
$sleeptime = 10

for ($i = 0; $i -lt $retries; $i++) {
    $status = docker-compose -f docker/docker-compose.prod.yml --env-file prod.env ps -q arachne-api
    if ($status) {
        # Check if actually running
        $running = docker inspect -f '{{.State.Running}}' $status
        if ($running -eq 'true') {
            Write-Host "Arachne API is running."
            break
        }
    }
    Write-Host "Waiting for service startup... ($($i+1)/$retries)"
    Start-Sleep -Seconds $sleeptime
}

if ($i -eq $retries) {
    Write-Error "Timed out waiting for services."
    exit 1
}

Write-Host "Installing test dependencies in container..."
# Temporarily install pytest in the running container
docker-compose -f docker/docker-compose.prod.yml --env-file prod.env exec -T arachne-api pip install pytest pytest-asyncio httpx

Write-Host "Running Integration Tests inside container..."
docker-compose -f docker/docker-compose.prod.yml --env-file prod.env exec -T arachne-api pytest tests/integration -v

Write-Host "Done."
