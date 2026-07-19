$ErrorActionPreference = "Stop"

foreach ($name in @(
    "VERSION",
    "NUMERIC_VERSION",
    "BUILD_DATE",
    "TARGET_ARCH",
    "WIX_ARCH",
    "SIGNTOOL_ARCH",
    "GITHUB_SHA",
    "GITHUB_WORKSPACE",
    "RUNNER_TEMP"
  )) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) {
    throw "$name is required"
  }
}

Set-Location (Join-Path $env:GITHUB_WORKSPACE "clients\desktop")
$ldflags = "-s -w -X main.desktopVersion=$env:VERSION -X main.desktopCommit=$env:GITHUB_SHA -X main.desktopDate=$env:BUILD_DATE"
$wailsArgs = @(
  "github.com/wailsapp/wails/v2/cmd/wails@v2.12.0",
  "build",
  "-clean",
  "-platform", "windows/$env:TARGET_ARCH",
  "-nopackage",
  "-trimpath",
  "-ldflags", $ldflags
)
go run @wailsArgs
if ($LASTEXITCODE -ne 0) {
  throw "Wails build failed"
}

$builtExe = Join-Path $PWD "build\bin\trustdb.exe"
if (-not (Test-Path $builtExe)) {
  throw "Wails did not produce $builtExe"
}

$outputDir = Join-Path $PWD "release-output"
$certDir = Join-Path $env:RUNNER_TEMP "trustdb-cert"
New-Item -ItemType Directory -Force -Path $outputDir, $certDir | Out-Null
$package = "trustdb-desktop-$env:VERSION-windows-$env:TARGET_ARCH"
$rawExe = Join-Path $outputDir "$package.exe"
Copy-Item $builtExe $rawExe

$passwordText = [Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")
$pfxPath = Join-Path $certDir "signing.pfx"
$privateKeyPath = Join-Path $certDir "signing-key.pem"
$pemCertPath = Join-Path $certDir "signing-cert.pem"
$cerPath = Join-Path $outputDir "$package.cer"
$fingerprintPath = Join-Path $outputDir "$package-certificate.txt"

Write-Host "Creating an isolated self-signed code-signing certificate"
$openssl = Get-Command openssl.exe -ErrorAction Stop
& $openssl.Source req -x509 -newkey rsa:3072 -sha256 -days 397 -nodes `
  -keyout $privateKeyPath `
  -out $pemCertPath `
  -subj "/CN=TrustDB Community Self-Signed $env:VERSION/O=TrustDB Community" `
  -addext "basicConstraints=critical,CA:FALSE" `
  -addext "keyUsage=critical,digitalSignature" `
  -addext "extendedKeyUsage=codeSigning"
if ($LASTEXITCODE -ne 0) {
  throw "OpenSSL certificate generation failed"
}
& $openssl.Source pkcs12 -export `
  -out $pfxPath `
  -inkey $privateKeyPath `
  -in $pemCertPath `
  -name "TrustDB Community Self-Signed $env:VERSION" `
  -passout "pass:$passwordText"
if ($LASTEXITCODE -ne 0) {
  throw "OpenSSL PKCS#12 export failed"
}
& $openssl.Source x509 -in $pemCertPath -outform DER -out $cerPath
if ($LASTEXITCODE -ne 0) {
  throw "OpenSSL DER certificate export failed"
}

$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
  [System.IO.File]::ReadAllBytes($cerPath)
)

(Get-FileHash -Path $cerPath -Algorithm SHA256).Hash.ToLowerInvariant() |
  Set-Content -NoNewline $fingerprintPath
Write-Host "Certificate ready: $($cert.Thumbprint)"

try {
  $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  $signTool = Get-ChildItem $sdkRoot -Directory |
    Sort-Object Name -Descending |
    ForEach-Object {
      Get-Item (Join-Path $_.FullName "$env:SIGNTOOL_ARCH\signtool.exe") -ErrorAction SilentlyContinue
    } |
    Select-Object -First 1
  if ($null -eq $signTool) {
    throw "signtool.exe for $env:SIGNTOOL_ARCH was not found"
  }
  Write-Host "Using signtool: $($signTool.FullName)"

  function Sign-TrustDBFile([string] $Path) {
    Write-Host "Signing $Path"
    & $signTool.FullName sign /fd SHA256 /f $pfxPath /p $passwordText $Path
    if ($LASTEXITCODE -ne 0) {
      throw "signtool failed for $Path"
    }

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($null -eq $signature.SignerCertificate) {
      throw "signed file has no embedded signer certificate: $Path"
    }
    if ($signature.SignerCertificate.Thumbprint -ne $cert.Thumbprint) {
      throw "signed file has an unexpected signer certificate: $Path"
    }
    if ($signature.Status -eq "HashMismatch" -or $signature.Status -eq "NotSigned" -or
      $signature.Status -eq "NotSupported") {
      throw "signature integrity verification failed for ${Path}: $($signature.Status)"
    }
    if ($signature.Status -eq "UnknownError" -and $signature.StatusMessage -notmatch "not trusted") {
      throw "unexpected signature verification error for ${Path}: $($signature.StatusMessage)"
    }
    if ($signature.Status -ne "Valid" -and $signature.Status -ne "NotTrusted" -and
      $signature.Status -ne "UnknownError") {
      throw "unexpected signature status for ${Path}: $($signature.Status)"
    }
    Write-Host "Signature integrity verified ($($signature.Status)): $Path"
  }

  Sign-TrustDBFile $rawExe

  $zipStage = Join-Path $env:RUNNER_TEMP $package
  New-Item -ItemType Directory -Force -Path $zipStage | Out-Null
  Copy-Item $rawExe (Join-Path $zipStage "trustdb-desktop.exe")
  Copy-Item $cerPath (Join-Path $zipStage "TrustDB-self-signed.cer")
  Copy-Item $fingerprintPath (Join-Path $zipStage "CERTIFICATE_SHA256.txt")
  Copy-Item (Join-Path $env:GITHUB_WORKSPACE "packaging\SELF_SIGNED_CLIENTS.md") $zipStage
  Compress-Archive -Path $zipStage -DestinationPath (Join-Path $outputDir "$package.zip") -CompressionLevel Optimal

  Write-Host "Building NSIS installer"
  $setupExe = Join-Path $outputDir "$package-setup.exe"
  $makensis = "${env:ProgramFiles(x86)}\NSIS\makensis.exe"
  if (-not (Test-Path $makensis)) {
    throw "makensis.exe was not found"
  }
  $sourceDefine = $rawExe
  $certDefine = $cerPath
  $guideDefine = Join-Path $env:GITHUB_WORKSPACE "packaging\SELF_SIGNED_CLIENTS.md"
  $outputDefine = $setupExe
  $nsisArgs = @(
    "/DVERSION=$env:VERSION",
    "/DSOURCE_EXE=$sourceDefine",
    "/DCERT_SOURCE=$certDefine",
    "/DSIGNING_GUIDE=$guideDefine",
    "/DOUTFILE=$outputDefine",
    (Join-Path $env:GITHUB_WORKSPACE "packaging\windows\installer.nsi")
  )
  & $makensis @nsisArgs
  if ($LASTEXITCODE -ne 0) {
    throw "NSIS packaging failed"
  }
  Sign-TrustDBFile $setupExe

  Write-Host "Building WiX installer"
  $msi = Join-Path $outputDir "$package.msi"
  $wix = Join-Path $env:USERPROFILE ".dotnet\tools\wix.exe"
  $wixArgs = @(
    "build",
    (Join-Path $env:GITHUB_WORKSPACE "packaging\windows\installer.wxs"),
    "-arch", $env:WIX_ARCH,
    "-d", "ProductVersion=$env:NUMERIC_VERSION",
    "-d", "DisplayVersion=$env:VERSION",
    "-d", "SourceExe=$rawExe",
    "-d", "CertSource=$cerPath",
    "-d", "SigningGuide=$(Join-Path $env:GITHUB_WORKSPACE 'packaging\SELF_SIGNED_CLIENTS.md')",
    "-out", $msi
  )
  & $wix @wixArgs
  if ($LASTEXITCODE -ne 0) {
    throw "WiX packaging failed"
  }
  Sign-TrustDBFile $msi
}
finally {
  $cert.Dispose()
  Remove-Item $pfxPath, $privateKeyPath, $pemCertPath -ErrorAction SilentlyContinue
}
