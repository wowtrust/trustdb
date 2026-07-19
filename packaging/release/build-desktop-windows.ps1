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
$cerPath = Join-Path $outputDir "$package.cer"
$fingerprintPath = Join-Path $outputDir "$package-certificate.txt"

Write-Host "Creating an isolated self-signed code-signing certificate"
$rsa = [System.Security.Cryptography.RSA]::Create(3072)
$generatedCert = $null
$cert = $null
try {
  $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
    "CN=TrustDB Community Self-Signed $env:VERSION, O=TrustDB Community"
  )
  $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    $subject,
    $rsa,
    [System.Security.Cryptography.HashAlgorithmName]::SHA256,
    [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
  )
  $ekuOids = [System.Security.Cryptography.OidCollection]::new()
  [void]$ekuOids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3"))
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($ekuOids, $false)
  )
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
      [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
      $true
    )
  )
  $request.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
  )

  $generatedCert = $request.CreateSelfSigned((Get-Date).AddMinutes(-5), (Get-Date).AddDays(397))
  $pfxBytes = $generatedCert.Export(
    [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
    $passwordText
  )
  $cerBytes = $generatedCert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
  [System.IO.File]::WriteAllBytes($pfxPath, $pfxBytes)
  [System.IO.File]::WriteAllBytes($cerPath, $cerBytes)
  $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $pfxBytes,
    $passwordText,
    ([System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor
      [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)
  )
}
finally {
  if ($null -ne $generatedCert) {
    $generatedCert.Dispose()
  }
  $rsa.Dispose()
}

(Get-FileHash -Path $cerPath -Algorithm SHA256).Hash.ToLowerInvariant() |
  Set-Content -NoNewline $fingerprintPath
$rootStore = [System.Security.Cryptography.X509Certificates.X509Store]::new(
  [System.Security.Cryptography.X509Certificates.StoreName]::Root,
  [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
  $rootStore.Add($cert)
}
finally {
  $rootStore.Close()
}
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
    & $signTool.FullName verify /pa /v $Path
    if ($LASTEXITCODE -ne 0) {
      throw "signature verification failed for $Path"
    }
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
  $sourceDefine = $rawExe.Replace("\", "/")
  $certDefine = $cerPath.Replace("\", "/")
  $guideDefine = (Join-Path $env:GITHUB_WORKSPACE "packaging\SELF_SIGNED_CLIENTS.md").Replace("\", "/")
  $outputDefine = $setupExe.Replace("\", "/")
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
  $rootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
  try {
    $rootStore.Remove($cert)
  }
  finally {
    $rootStore.Close()
  }
  $cert.Dispose()
  Remove-Item $pfxPath -ErrorAction SilentlyContinue
}
