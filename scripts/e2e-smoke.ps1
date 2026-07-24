param(
    [string]$WorkDir = "",
    [int]$Port = 18080,
    [string]$TrustDBExe = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
if ([string]::IsNullOrWhiteSpace($WorkDir)) {
    $WorkDir = Join-Path $script:RepoRoot ".localtest\e2e-smoke"
}
$WorkDir = [System.IO.Path]::GetFullPath($WorkDir)

function Write-Step([string]$Message) {
    Write-Host "[trustdb-smoke] $Message"
}

function ConvertTo-ArgumentLine([string[]]$TrustArgs) {
    ($TrustArgs | ForEach-Object {
        if ($_ -match '[\s"]') {
            '"' + ($_.Replace('"', '\"')) + '"'
        } else {
            $_
        }
    }) -join " "
}

function Invoke-TrustDBJson([string[]]$TrustArgs) {
    $stderr = Join-Path $script:WorkDirForCommand ("trustdb-" + [System.Guid]::NewGuid().ToString("N") + ".stderr.log")
    $oldErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = "Continue"
        $stdout = & $script:TrustDB @TrustArgs 2> $stderr
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $oldErrorActionPreference
    }
    $errText = ""
    if (Test-Path $stderr) {
        $errText = Get-Content -LiteralPath $stderr -Raw -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $stderr -Force -ErrorAction SilentlyContinue
    }
    if ($exitCode -ne 0) {
        throw "trustdb $($TrustArgs -join ' ') failed with exit code $exitCode`n$errText"
    }
    $text = ($stdout | Out-String).Trim()
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }
    return $text | ConvertFrom-Json
}

function Wait-Json([string]$Uri, [scriptblock]$Predicate, [int]$TimeoutSeconds = 30) {
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = ""
    while ((Get-Date) -lt $deadline) {
        try {
            $value = Invoke-RestMethod -Method Get -Uri $Uri -TimeoutSec 3
            if (& $Predicate $value) {
                return $value
            }
            $last = "predicate returned false"
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Milliseconds 250
    }
    throw "timed out waiting for $Uri ($last)"
}

function Start-TrustDBServer(
    [int]$ServerPort,
    [string]$WalDir,
    [string]$ProofDir,
    [string]$PebbleDir,
    [string]$ServerKey,
    [string]$ClientPub,
    [string]$LogPrefix
) {
    New-Item -ItemType Directory -Force -Path $WalDir, $ProofDir, $PebbleDir | Out-Null
    $stdout = Join-Path $script:WorkDirForCommand "$LogPrefix.stdout.log"
    $stderr = Join-Path $script:WorkDirForCommand "$LogPrefix.stderr.log"
    $args = @(
        "--log-format", "json",
        "--log-output", "stderr",
        "serve",
        "--listen", "127.0.0.1:$ServerPort",
        "--wal", $WalDir,
        "--proof-dir", $ProofDir,
        "--metastore", "pebble",
        "--metastore-path", $PebbleDir,
        "--server-private-key", $ServerKey,
        "--client-public-key", $ClientPub,
        "--batch-max-records", "1",
        "--batch-max-delay", "50ms",
        "--wal-fsync-mode", "group",
        "--wal-group-commit-interval", "5ms",
        "--anchor-sink", "noop"
    )
    $process = Start-Process `
        -FilePath $script:TrustDB `
        -ArgumentList (ConvertTo-ArgumentLine $args) `
        -WorkingDirectory $script:RepoRoot `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru
    $process | Add-Member -NotePropertyName StdoutLog -NotePropertyValue $stdout
    $process | Add-Member -NotePropertyName StderrLog -NotePropertyValue $stderr
    Wait-Json "http://127.0.0.1:$ServerPort/healthz" { param($j) $j.ok -eq $true } 20 | Out-Null
    return $process
}

function Stop-TrustDBServer($Process) {
    if ($null -eq $Process) {
        return
    }
    try {
        $live = Get-Process -Id $Process.Id -ErrorAction SilentlyContinue
        if ($null -ne $live) {
            Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
            Wait-Process -Id $Process.Id -Timeout 10 -ErrorAction SilentlyContinue
        }
    } catch {
        Write-Warning "failed to stop trustdb server pid=$($Process.Id): $($_.Exception.Message)"
    }
}

function New-SmokeClaim([string]$InputPath, [string]$ClaimPath, [string]$ClientKey) {
    Invoke-TrustDBJson @(
        "--log-format", "json",
        "--log-output", "stderr",
        "claim-file",
        "--file", $InputPath,
        "--private-key", $ClientKey,
        "--tenant", "smoke-tenant",
        "--client", "smoke-client",
        "--key-id", "smoke-key",
        "--out", $ClaimPath
    )
}

function Submit-Claim([string]$BaseURL, [string]$ClaimPath) {
    Invoke-RestMethod -Method Post -Uri "$BaseURL/v1/claims" -ContentType "application/cbor" -InFile $ClaimPath -TimeoutSec 10
}

if (Test-Path -LiteralPath $WorkDir) {
    Remove-Item -LiteralPath $WorkDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$script:WorkDirForCommand = $WorkDir

try {
    if ([string]::IsNullOrWhiteSpace($TrustDBExe)) {
        $script:TrustDB = Join-Path $WorkDir "trustdb-smoke.exe"
        Write-Step "building trustdb CLI"
        Push-Location $script:RepoRoot
        try {
            & go build -o $script:TrustDB .\cmd\trustdb
            if ($LASTEXITCODE -ne 0) {
                throw "go build failed with exit code $LASTEXITCODE"
            }
        } finally {
            Pop-Location
        }
    } else {
        $script:TrustDB = [System.IO.Path]::GetFullPath($TrustDBExe)
    }

    $keysDir = Join-Path $WorkDir "keys"
    $inputDir = Join-Path $WorkDir "input"
    $claimsDir = Join-Path $WorkDir "claims"
    $walDir = Join-Path $WorkDir "wal"
    $proofDir = Join-Path $WorkDir "proofs"
    $pebbleDir = Join-Path $WorkDir "pebble"
    $restoreProofDir = Join-Path $WorkDir "restore-proofs"
    $restorePebbleDir = Join-Path $WorkDir "restore-pebble"
    New-Item -ItemType Directory -Force -Path $keysDir, $inputDir, $claimsDir | Out-Null

    Write-Step "generating client/server keys"
    # The Windows smoke test uses the explicit disposable plaintext fixture.
    # Authenticated software envelopes fail closed on Windows until their DACL
    # behavior is runtime-qualified; production deployments must use an
    # approved external provider rather than this test-only escape hatch.
    Invoke-TrustDBJson @("--log-format", "json", "--log-output", "stderr", "keygen", "--out", $keysDir, "--prefix", "client", "--protection", "plaintext-dev-v1") | Out-Null
    Invoke-TrustDBJson @("--log-format", "json", "--log-output", "stderr", "keygen", "--out", $keysDir, "--prefix", "server", "--protection", "plaintext-dev-v1") | Out-Null
    $clientKey = Join-Path $keysDir "client.key"
    $clientPub = Join-Path $keysDir "client.pub"
    $serverKey = Join-Path $keysDir "server.key"
    $serverPub = Join-Path $keysDir "server.pub"

    Write-Step "starting primary server on port $Port"
    $server = Start-TrustDBServer $Port $walDir $proofDir $pebbleDir $serverKey $clientPub "server-primary"
    $base = "http://127.0.0.1:$Port"

    $records = @()
    for ($i = 1; $i -le 3; $i++) {
        $input = Join-Path $inputDir "payload-$i.txt"
        Set-Content -LiteralPath $input -Value "TrustDB smoke payload $i $(Get-Date -Format o)" -Encoding UTF8
        $claim = Join-Path $claimsDir "payload-$i.tdclaim"
        $created = New-SmokeClaim $input $claim $clientKey
        $submitted = Submit-Claim $base $claim
        if ($submitted.record_id -ne $created.record_id) {
            throw "record_id mismatch for payload ${i}: claim=$($created.record_id) submit=$($submitted.record_id)"
        }
        $records += [pscustomobject]@{
            File = $input
            Claim = $claim
            RecordID = $submitted.record_id
        }
    }

    Write-Step "waiting for L3/L4/L5 artifacts"
    $first = $records[0]
    $proof = Wait-Json "$base/v1/proofs/$($first.RecordID)" {
        param($j)
        -not [string]::IsNullOrWhiteSpace($j.proof_bundle.committed_receipt.batch_id)
    } 30
    $batchID = $proof.proof_bundle.committed_receipt.batch_id
    $global = Wait-Json "$base/v1/global-log/inclusion/$batchID" {
        param($j)
        $j.tree_size -gt 0 -and $j.sth.tree_size -gt 0
    } 30
    $treeSize = [uint64]$global.sth.tree_size
    $anchor = Wait-Json "$base/v1/anchors/sth/$treeSize" {
        param($j)
        $j.status -eq "published" -and $null -ne $j.result
    } 30

    Write-Step "checking record pagination and filters"
    $page1 = Wait-Json "$base/v1/records?limit=2&direction=desc" {
        param($j)
        @($j.records).Count -eq 2 -and -not [string]::IsNullOrWhiteSpace($j.next_cursor)
    } 10
    $cursor = [System.Uri]::EscapeDataString([string]$page1.next_cursor)
    $page2 = Wait-Json "$base/v1/records?limit=2&direction=desc&cursor=$cursor" {
        param($j)
        @($j.records).Count -ge 1
    } 10
    $recordIndex = Wait-Json "$base/v1/records/$($first.RecordID)" {
        param($j)
        $j.record_id -eq $first.RecordID -and $j.batch_id -eq $batchID
    } 10
    $batchFilter = [System.Uri]::EscapeDataString([string]$batchID)
    Wait-Json "$base/v1/records?batch_id=$batchFilter&limit=10" {
        param($j)
        @($j.records | Where-Object { $_.record_id -eq $first.RecordID }).Count -eq 1
    } 10 | Out-Null
    $hashFilter = (Get-FileHash -Algorithm SHA256 -LiteralPath $first.File).Hash.ToLowerInvariant()
    Wait-Json "$base/v1/records?content_hash=$hashFilter&limit=10" {
        param($j)
        @($j.records | Where-Object { $_.record_id -eq $first.RecordID }).Count -eq 1
    } 10 | Out-Null
    $queryFilter = [System.Uri]::EscapeDataString("payload-1")
    Wait-Json "$base/v1/records?q=$queryFilter&limit=10" {
        param($j)
        @($j.records | Where-Object { $_.record_id -eq $first.RecordID }).Count -eq 1
    } 10 | Out-Null

    Write-Step "running remote verify up to available proof level"
    $verify = Invoke-TrustDBJson @(
        "--log-format", "json",
        "--log-output", "stderr",
        "verify",
        "--file", $first.File,
        "--server", $base,
        "--record", $first.RecordID,
        "--client-public-key", $clientPub,
        "--server-public-key", $serverPub
    )
    if ($verify.record_id -ne $first.RecordID -or $verify.proof_level -ne "L5") {
        throw "unexpected verify result: record=$($verify.record_id) level=$($verify.proof_level)"
    }

    Write-Step "stopping primary server before Pebble backup"
    Stop-TrustDBServer $server
    $server = $null

    $backupPath = Join-Path $WorkDir "trustdb-smoke.tdbackup"
    Write-Step "creating and verifying portable backup"
    $createdBackup = Invoke-TrustDBJson @(
        "--log-format", "json",
        "--log-output", "stderr",
        "backup", "create",
        "--metastore", "pebble",
        "--metastore-path", $pebbleDir,
        "--out", $backupPath,
        "--compression", "gzip"
    )
    Invoke-TrustDBJson @("--log-format", "json", "--log-output", "stderr", "backup", "verify", "--file", $backupPath) | Out-Null

    Write-Step "restoring backup into a fresh Pebble store"
    Invoke-TrustDBJson @(
        "--log-format", "json",
        "--log-output", "stderr",
        "backup", "restore",
        "--file", $backupPath,
        "--metastore", "pebble",
        "--metastore-path", $restorePebbleDir
    ) | Out-Null

    $restorePort = $Port + 1
    $restoreWalDir = Join-Path $WorkDir "restore-wal"
    Write-Step "starting restored server on port $restorePort"
    $restoreServer = Start-TrustDBServer $restorePort $restoreWalDir $restoreProofDir $restorePebbleDir $serverKey $clientPub "server-restored"
    $restoreBase = "http://127.0.0.1:$restorePort"
    Wait-Json "$restoreBase/v1/records/$($first.RecordID)" {
        param($j)
        $j.record_id -eq $first.RecordID -and $j.batch_id -eq $batchID
    } 20 | Out-Null
    Wait-Json "$restoreBase/v1/proofs/$($first.RecordID)" {
        param($j)
        $j.proof_bundle.record_id -eq $first.RecordID
    } 20 | Out-Null
    Stop-TrustDBServer $restoreServer
    $restoreServer = $null

    Write-Step "success"
    [pscustomobject]@{
        ok = $true
        work_dir = $WorkDir
        records = $records.RecordID
        first_batch_id = $batchID
        first_sth_tree_size = $treeSize
        anchor_sink = $anchor.result.sink_name
        record_page_1_count = @($page1.records).Count
        record_page_2_count = @($page2.records).Count
        backup = $backupPath
        backup_entries = $createdBackup.entries
    } | ConvertTo-Json -Depth 8
} finally {
    if ($null -ne $server) {
        Stop-TrustDBServer $server
    }
    if ($null -ne $restoreServer) {
        Stop-TrustDBServer $restoreServer
    }
}
