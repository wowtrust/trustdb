<#
.SYNOPSIS
  Start/stop local TiKV+PD for TrustDB TiKV integration tests (Podman or Docker Compose).

.DESCRIPTION
  Default on Windows uses Podman only: pod + named volumes, same layout as docker-compose.tikv.yml.
  PD client: 127.0.0.1:2379, TiKV: 127.0.0.1:20160 (see compose file).

  Commands: up, down, reset, test, logs, ps, help

  Environment:
    TRUSTDB_TIKV_COMPOSE_FILE     Path to compose file (podman|docker-api only; native ignores)
    TRUSTDB_TIKV_PD_ENDPOINTS     PD for go test (default 127.0.0.1:2379)
    TRUSTDB_TIKV_KEYSPACE         Optional TiKV keyspace for tests
    TRUSTDB_TIKV_PD_IMAGE         PD image (native default: pingcap/pd:v7.5.0)
    TRUSTDB_TIKV_TIKV_IMAGE       TiKV image (native default: pingcap/tikv:v7.5.0)
    TRUSTDB_TIKV_COMPOSE_VIA      auto | native | podman | docker-api (default auto)
                                  auto on this script = native (Podman only, no Docker CLI)
    TRUSTDB_TIKV_DOCKER_HOST      docker-api only: Docker API URL (default npipe:////./pipe/docker_engine)
#>
param(
    [Parameter(Position = 0)]
    [ValidateSet("up", "down", "reset", "test", "logs", "ps", "help")]
    [string]$Command = "help"
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
# Podman writes pull progress to stderr; PS 7+ would otherwise surface it as error records when $ErrorActionPreference is Stop.
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -ErrorAction SilentlyContinue) {
    $PSNativeCommandUseErrorActionPreference = $false
}

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

$script:TiKVPod = "trustdb-tikv-dev-pod"
$script:TiKVVolPd = "trustdb-tikv-dev-pd-vol"
$script:TiKVVolTikv = "trustdb-tikv-dev-tikv-vol"
$script:TiKVContPd = "trustdb-tikv-dev-pd"
$script:TiKVContTikv = "trustdb-tikv-dev-tikv"

function Get-TiKVImgPd {
    if (-not [string]::IsNullOrWhiteSpace($env:TRUSTDB_TIKV_PD_IMAGE)) { return $env:TRUSTDB_TIKV_PD_IMAGE.Trim() }
    return "pingcap/pd:v7.5.0"
}

function Get-TiKVImgTikv {
    if (-not [string]::IsNullOrWhiteSpace($env:TRUSTDB_TIKV_TIKV_IMAGE)) { return $env:TRUSTDB_TIKV_TIKV_IMAGE.Trim() }
    return "pingcap/tikv:v7.5.0"
}

function Get-ComposeFile {
    $f = $env:TRUSTDB_TIKV_COMPOSE_FILE
    if ([string]::IsNullOrWhiteSpace($f)) {
        return Join-Path $RepoRoot "docker-compose.tikv.yml"
    }
    if ([System.IO.Path]::IsPathRooted($f)) {
        return $f
    }
    return Join-Path $RepoRoot $f
}

function Get-ComposeArgs {
    $composeFile = Get-ComposeFile
    if (-not (Test-Path -LiteralPath $composeFile)) {
        throw "Compose file not found: $composeFile"
    }
    return @("-f", $composeFile, "--project-name", "trustdb-tikv-dev")
}

function Get-StackVia {
    $via = $env:TRUSTDB_TIKV_COMPOSE_VIA
    if ([string]::IsNullOrWhiteSpace($via)) {
        return "auto"
    }
    return $via.Trim().ToLowerInvariant()
}

function Test-PodmanAvailable {
    return [bool](Get-Command podman -ErrorAction SilentlyContinue)
}

function Test-PodExists {
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman pod inspect $script:TiKVPod 2>&1
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-ContainerExists {
    param([string]$Name)
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman container inspect $Name 2>&1
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-ContainerRunning {
    param([string]$Name)
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $s = (& podman container inspect $Name --format "{{.State.Running}}" 2>&1 | Out-String).Trim()
        return ($s -eq "true")
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Test-PodmanVolumeExists {
    param([string]$VolumeName)
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman volume exists $VolumeName 2>&1
        $ec = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
    if ($ec -eq 0) {
        return $true
    }
    if ($ec -eq 1) {
        return $false
    }
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman volume inspect $VolumeName 2>&1
        return ($LASTEXITCODE -eq 0)
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Ensure-PodmanVolume {
    param([string]$VolumeName)
    if (Test-PodmanVolumeExists $VolumeName) {
        return
    }
    Write-Host "[tikv-dev] podman volume create $VolumeName"
    & podman volume create $VolumeName
    if ($LASTEXITCODE -ne 0) {
        throw "podman volume create failed: $VolumeName"
    }
}

function Invoke-NativeRunPd {
    if (Test-ContainerExists $script:TiKVContPd) {
        if (-not (Test-ContainerRunning $script:TiKVContPd)) {
            Write-Host "[tikv-dev] podman start $script:TiKVContPd"
            & podman start $script:TiKVContPd
            if ($LASTEXITCODE -ne 0) {
                throw "podman start PD failed"
            }
        }
        return
    }
    $img = Get-TiKVImgPd
    Write-Host "[tikv-dev] podman run PD ($img)"
    $runArgs = @(
        "run", "-d", "--pod", $script:TiKVPod, "--name", $script:TiKVContPd,
        "-v", "$($script:TiKVVolPd):/data",
        $img,
        "--name=pd",
        "--data-dir=/data/pd",
        "--client-urls=http://0.0.0.0:2379",
        "--peer-urls=http://0.0.0.0:2380",
        "--advertise-client-urls=http://127.0.0.1:2379",
        "--advertise-peer-urls=http://127.0.0.1:2380",
        "--initial-cluster=pd=http://127.0.0.1:2380"
    )
    & podman @runArgs
    if ($LASTEXITCODE -ne 0) {
        throw "podman run PD failed"
    }
}

function Invoke-NativeRunTikv {
    if (Test-ContainerExists $script:TiKVContTikv) {
        if (-not (Test-ContainerRunning $script:TiKVContTikv)) {
            Write-Host "[tikv-dev] podman start $script:TiKVContTikv"
            & podman start $script:TiKVContTikv
            if ($LASTEXITCODE -ne 0) {
                throw "podman start TiKV failed"
            }
        }
        return
    }
    $img = Get-TiKVImgTikv
    Write-Host "[tikv-dev] podman run TiKV ($img)"
    $runArgs = @(
        "run", "-d", "--pod", $script:TiKVPod, "--name", $script:TiKVContTikv,
        "-v", "$($script:TiKVVolTikv):/data/tikv",
        $img,
        "--addr=0.0.0.0:20160",
        "--advertise-addr=127.0.0.1:20160",
        "--status-addr=0.0.0.0:20180",
        "--pd=127.0.0.1:2379",
        "--data-dir=/data/tikv"
    )
    & podman @runArgs
    if ($LASTEXITCODE -ne 0) {
        throw "podman run TiKV failed"
    }
}

function Invoke-NativeUp {
    if (-not (Test-PodmanAvailable)) {
        throw "podman not found in PATH"
    }
    Ensure-PodmanVolume $script:TiKVVolPd
    Ensure-PodmanVolume $script:TiKVVolTikv

    if ((Test-PodExists) -and (Test-ContainerRunning $script:TiKVContPd) -and (Test-ContainerRunning $script:TiKVContTikv)) {
        Write-Host "[tikv-dev] native stack already running"
        return
    }

    if (Test-PodExists) {
        Write-Host "[tikv-dev] podman pod start $($script:TiKVPod)"
        & podman pod start $script:TiKVPod
        if ($LASTEXITCODE -ne 0) {
            throw "podman pod start failed"
        }
        if (-not (Test-ContainerExists $script:TiKVContPd)) {
            throw "Pod exists but PD container is missing; run: .\scripts\tikv-dev.ps1 reset"
        }
        Invoke-NativeRunPd
        Wait-PdHealthy
        Invoke-NativeRunTikv
        return
    }

    Write-Host "[tikv-dev] podman pod create $($script:TiKVPod) (publish 2379,2380,20160,20180)"
    & podman pod create --name $script:TiKVPod -p 2379:2379 -p 2380:2380 -p 20160:20160 -p 20180:20180
    if ($LASTEXITCODE -ne 0) {
        throw "podman pod create failed"
    }
    Invoke-NativeRunPd
    Wait-PdHealthy
    Invoke-NativeRunTikv
}

function Invoke-NativeDown {
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman pod rm -f $script:TiKVPod 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Invoke-NativeReset {
    Invoke-NativeDown
    $prev = $ErrorActionPreference
    try {
        $ErrorActionPreference = "SilentlyContinue"
        $null = & podman volume rm -f $script:TiKVVolPd $script:TiKVVolTikv 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Invoke-NativeLogs {
    param([string[]]$LogArgs = @("-f", "--tail", "200"))
    if (-not (Test-PodExists)) {
        throw "Stack is not up (no pod). Run: .\scripts\tikv-dev.ps1 up"
    }
    $all = @("pod", "logs") + $LogArgs + $script:TiKVPod
    Write-Host "[tikv-dev] podman $($all -join ' ')"
    & podman @all
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[tikv-dev] pod logs failed; following TiKV container only" -ForegroundColor Yellow
        & podman logs -f --tail 200 $script:TiKVContTikv
        if ($LASTEXITCODE -ne 0) {
            throw "podman logs failed"
        }
    }
}

function Invoke-NativePs {
    Write-Host "[tikv-dev] podman ps -a --filter pod=$($script:TiKVPod)"
    & podman ps -a --filter "pod=$($script:TiKVPod)"
}

function Invoke-NativeFromComposeArgs {
    # Do not name this parameter $Args — it conflicts with PowerShell's automatic $args and breaks splatting.
    param([string[]]$StackArgs)
    if ($StackArgs.Count -ge 2 -and $StackArgs[0] -eq "down" -and $StackArgs[1] -eq "-v") {
        Invoke-NativeReset
    } elseif ($StackArgs[0] -eq "down") {
        Invoke-NativeDown
    } elseif ($StackArgs[0] -eq "up") {
        Invoke-NativeUp
    } elseif ($StackArgs[0] -eq "logs") {
        if ($StackArgs.Count -gt 1) {
            Invoke-NativeLogs -LogArgs $StackArgs[1..($StackArgs.Count - 1)]
        } else {
            Invoke-NativeLogs
        }
    } elseif ($StackArgs[0] -eq "ps") {
        Invoke-NativePs
    } else {
        throw "Native stack: unsupported arguments: $($StackArgs -join ' ')"
    }
}

function Invoke-PodmanComposeInternal {
    param([string[]]$StackArgs)
    if (-not (Test-PodmanAvailable)) {
        throw "podman not found in PATH"
    }
    $all = @("compose") + (Get-ComposeArgs) + $StackArgs
    Write-Host "[tikv-dev] podman $($all -join ' ')"
    & podman @all
    if ($LASTEXITCODE -ne 0) {
        throw "podman compose failed with exit code $LASTEXITCODE"
    }
}

function Invoke-DockerComposePodmanPipe {
    param([string[]]$StackArgs)
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        throw "docker CLI not found in PATH (set TRUSTDB_TIKV_COMPOSE_VIA=native to avoid Docker)"
    }
    $pipe = $env:TRUSTDB_TIKV_DOCKER_HOST
    if ([string]::IsNullOrWhiteSpace($pipe)) {
        $pipe = "npipe:////./pipe/docker_engine"
    }
    $savedDockerHost = [Environment]::GetEnvironmentVariable("DOCKER_HOST", "Process")
    try {
        $env:DOCKER_HOST = $pipe
        $all = @("compose") + (Get-ComposeArgs) + $StackArgs
        Write-Host "[tikv-dev] docker $($all -join ' ') (DOCKER_HOST=$pipe)"
        & docker @all
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose failed with exit code $LASTEXITCODE"
        }
    } finally {
        if ($null -eq $savedDockerHost -or $savedDockerHost -eq "") {
            Remove-Item Env:DOCKER_HOST -ErrorAction SilentlyContinue
        } else {
            $env:DOCKER_HOST = $savedDockerHost
        }
    }
}

function Invoke-Stack {
    param([string[]]$StackArgs)
    $via = Get-StackVia
    switch ($via) {
        "native" {
            Invoke-NativeFromComposeArgs $StackArgs
        }
        "podman" {
            Invoke-PodmanComposeInternal $StackArgs
        }
        "docker-api" {
            Invoke-DockerComposePodmanPipe $StackArgs
        }
        "auto" {
            Invoke-NativeFromComposeArgs $StackArgs
        }
        default {
            throw "Invalid TRUSTDB_TIKV_COMPOSE_VIA: $env:TRUSTDB_TIKV_COMPOSE_VIA (use auto|native|podman|docker-api)"
        }
    }
}

function Assert-ComposePrereqs {
    Get-ComposeArgs | Out-Null
}

function Wait-PdHealthy {
    param([int]$TimeoutSec = 120)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $url = "http://127.0.0.1:2379/pd/api/v1/health"
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) {
                Write-Host "[tikv-dev] PD health OK"
                return
            }
        } catch {
            # retry
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for PD at $url"
}

function Wait-TikvStatus {
    param([int]$TimeoutSec = 180)
    $deadline = (Get-Date).AddSeconds($TimeoutSec)
    $url = "http://127.0.0.1:20180/status"
    while ((Get-Date) -lt $deadline) {
        try {
            $r = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 3
            if ($r.StatusCode -eq 200) {
                Write-Host "[tikv-dev] TiKV status OK"
                return
            }
        } catch {
            # retry
        }
        Start-Sleep -Seconds 2
    }
    throw "Timed out waiting for TiKV status at $url"
}

function Get-PdEndpoints {
    $ep = $env:TRUSTDB_TIKV_PD_ENDPOINTS
    if ([string]::IsNullOrWhiteSpace($ep)) {
        return "127.0.0.1:2379"
    }
    return $ep.Trim()
}

function Invoke-TiKVGoTest {
    $env:TRUSTDB_TIKV_PD_ENDPOINTS = Get-PdEndpoints
    if (-not [string]::IsNullOrWhiteSpace($env:TRUSTDB_TIKV_KEYSPACE)) {
        Write-Host "[tikv-dev] TRUSTDB_TIKV_KEYSPACE=$($env:TRUSTDB_TIKV_KEYSPACE)"
    } else {
        Remove-Item Env:TRUSTDB_TIKV_KEYSPACE -ErrorAction SilentlyContinue
    }
    Write-Host "[tikv-dev] TRUSTDB_TIKV_PD_ENDPOINTS=$($env:TRUSTDB_TIKV_PD_ENDPOINTS)"
    Write-Host "[tikv-dev] go test -count=1 -tags=integration ./internal/proofstore/tikv"
    & go test -count=1 -tags=integration ./internal/proofstore/tikv
    if ($LASTEXITCODE -ne 0) {
        throw "go test failed with exit code $LASTEXITCODE"
    }
}

function Assert-StackPrereqs {
    $via = Get-StackVia
    switch ($via) {
        "native" {
            if (-not (Test-PodmanAvailable)) {
                throw "podman not found in PATH"
            }
        }
        "podman" {
            if (-not (Test-PodmanAvailable)) {
                throw "podman not found in PATH"
            }
            Assert-ComposePrereqs
        }
        "docker-api" {
            Assert-ComposePrereqs
        }
        "auto" {
            if (-not (Test-PodmanAvailable)) {
                throw "podman not found in PATH (auto uses native Podman on this script)"
            }
        }
        default {
            throw "Invalid TRUSTDB_TIKV_COMPOSE_VIA"
        }
    }
}

switch ($Command) {
    "up" {
        Assert-StackPrereqs
        Invoke-Stack @("up", "-d")
        Wait-PdHealthy
        Wait-TikvStatus
        Write-Host "[tikv-dev] stack is up. Run: .\scripts\tikv-dev.ps1 test"
    }
    "down" {
        Assert-StackPrereqs
        Invoke-Stack @("down")
    }
    "reset" {
        Assert-StackPrereqs
        Invoke-Stack @("down", "-v")
        Write-Host "[tikv-dev] volumes removed"
    }
    "test" {
        Invoke-TiKVGoTest
    }
    "logs" {
        Assert-StackPrereqs
        Invoke-Stack @("logs", "-f", "--tail", "200")
    }
    "ps" {
        Assert-StackPrereqs
        Invoke-Stack @("ps")
    }
    default {
        @"
TrustDB local TiKV helper (Podman-first on Windows)

Usage:
  .\scripts\tikv-dev.ps1 <command>

Commands:
  up           Start PD+TiKV (Podman pod + containers) and wait for health from host
  down         Stop stack (keep volumes)
  reset        Stop and delete volumes (clean cluster)
  test         Run: go test -count=1 -tags=integration ./internal/proofstore/tikv
  logs         Follow logs (pod logs, or TiKV container fallback)
  ps           podman ps for this pod

Env:
  TRUSTDB_TIKV_COMPOSE_VIA        auto | native | podman | docker-api (default auto = native here)
  TRUSTDB_TIKV_COMPOSE_FILE       Override compose file (podman|docker-api only)
  TRUSTDB_TIKV_PD_ENDPOINTS       Default 127.0.0.1:2379
  TRUSTDB_TIKV_KEYSPACE           Optional keyspace for tests
  TRUSTDB_TIKV_PD_IMAGE           Override PD image (native + compose interpolation)
  TRUSTDB_TIKV_TIKV_IMAGE         Override TiKV image (native + compose interpolation)
  TRUSTDB_TIKV_DOCKER_HOST        docker-api: API URL (default npipe:////./pipe/docker_engine)

See scripts/tikv-dev.env.example: copy values into repo-root .env for docker compose image pins.

Use TRUSTDB_TIKV_COMPOSE_VIA=podman to force podman compose (custom compose file).
Use TRUSTDB_TIKV_COMPOSE_VIA=docker-api only if you have docker CLI and want Compose against a Docker API.
"@ | Write-Host
    }
}
