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

$certArgs = @{
  Type = "CodeSigningCert"
  Subject = "CN=TrustDB Community Self-Signed $env:VERSION, O=TrustDB Community"
  CertStoreLocation = "Cert:\CurrentUser\My"
  KeyAlgorithm = "RSA"
  KeyLength = 3072
  HashAlgorithm = "SHA256"
  KeyExportPolicy = "Exportable"
  NotAfter = (Get-Date).AddDays(397)
}
$cert = New-SelfSignedCertificate @certArgs
$passwordText = [Guid]::NewGuid().ToString("N") + [Guid]::NewGuid().ToString("N")
$password = ConvertTo-SecureString $passwordText -AsPlainText -Force
$pfxPath = Join-Path $certDir "signing.pfx"
$cerPath = Join-Path $outputDir "$package.cer"
Export-PfxCertificate -Cert $cert -FilePath $pfxPath -Password $password | Out-Null
Export-Certificate -Cert $cert -FilePath $cerPath -Type CERT | Out-Null
$cert.Thumbprint | Set-Content -NoNewline (Join-Path $outputDir "$package-certificate.txt")
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\CurrentUser\Root" | Out-Null

try {
  $sdkRoot = "${env:ProgramFiles(x86)}\Windows Kits\10\bin"
  $signTool = Get-ChildItem $sdkRoot -Recurse -Filter signtool.exe |
    Where-Object { $_.FullName -match "\\$env:SIGNTOOL_ARCH\\signtool\.exe$" } |
    Sort-Object FullName -Descending |
    Select-Object -First 1
  if ($null -eq $signTool) {
    throw "signtool.exe for $env:SIGNTOOL_ARCH was not found"
  }

  function Sign-TrustDBFile([string] $Path) {
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
  Copy-Item (Join-Path $outputDir "$package-certificate.txt") (Join-Path $zipStage "CERTIFICATE_SHA256.txt")
  Copy-Item (Join-Path $env:GITHUB_WORKSPACE "packaging\SELF_SIGNED_CLIENTS.md") $zipStage
  Compress-Archive -Path $zipStage -DestinationPath (Join-Path $outputDir "$package.zip") -CompressionLevel Optimal

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
  Remove-Item "Cert:\CurrentUser\Root\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
  Remove-Item "Cert:\CurrentUser\My\$($cert.Thumbprint)" -ErrorAction SilentlyContinue
  Remove-Item $pfxPath -ErrorAction SilentlyContinue
}
