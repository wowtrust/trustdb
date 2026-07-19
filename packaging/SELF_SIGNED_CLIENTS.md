# TrustDB Desktop self-signed builds

TrustDB Desktop `1.0.0-beta` is signed with a release-specific, self-signed code-signing certificate. The certificate and its public fingerprint are included beside each installer so the downloaded binary can be checked independently.

Self-signing protects against an installer being changed after this release was built, but it does not create trust with Apple or Microsoft. macOS Gatekeeper and Windows SmartScreen may therefore show an unknown-developer warning. Only install an asset downloaded from the project release page after comparing it with `SHA256SUMS`.

## macOS

Inspect the application signature before opening it:

```bash
codesign --verify --deep --strict --verbose=2 "TrustDB Desktop.app"
codesign -dvvv "TrustDB Desktop.app"
```

If Gatekeeper blocks the first launch, open **System Settings → Privacy & Security**, confirm that the application is the TrustDB build you downloaded, then choose **Open Anyway**. Do not disable Gatekeeper globally.

## Windows

Open the file's **Properties → Digital Signatures** tab, select the TrustDB signature, and compare the certificate with the `.cer` file shipped in the same archive. PowerShell can display the signature with:

```powershell
Get-AuthenticodeSignature .\trustdb-desktop.exe | Format-List
```

The certificate is intentionally not installed into the system trust store by the installer. Import it only if your own deployment policy requires that, after independently checking its fingerprint.
