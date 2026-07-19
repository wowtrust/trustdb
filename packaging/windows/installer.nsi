!include "MUI2.nsh"

!ifndef VERSION
  !error "VERSION is required"
!endif
!ifndef SOURCE_EXE
  !error "SOURCE_EXE is required"
!endif
!ifndef CERT_SOURCE
  !error "CERT_SOURCE is required"
!endif
!ifndef SIGNING_GUIDE
  !error "SIGNING_GUIDE is required"
!endif
!ifndef OUTFILE
  !error "OUTFILE is required"
!endif

Unicode true
Name "TrustDB Desktop ${VERSION}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\TrustDB"
InstallDirRegKey HKCU "Software\TrustDB" "InstallDir"
RequestExecutionLevel user
SetCompressor /SOLID lzma

VIProductVersion "1.0.0.0"
VIAddVersionKey "ProductName" "TrustDB Desktop"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "CompanyName" "TrustDB Community"
VIAddVersionKey "FileDescription" "TrustDB Desktop self-signed installer"
VIAddVersionKey "LegalCopyright" "TrustDB contributors"

!define MUI_ABORTWARNING
!define MUI_FINISHPAGE_RUN "$INSTDIR\trustdb-desktop.exe"
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

Section "TrustDB Desktop" SecMain
  SetOutPath "$INSTDIR"
  File /oname=trustdb-desktop.exe "${SOURCE_EXE}"
  File /oname=TrustDB-self-signed.cer "${CERT_SOURCE}"
  File /oname=SELF_SIGNED_CLIENTS.md "${SIGNING_GUIDE}"
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  WriteRegStr HKCU "Software\TrustDB" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrustDB" "DisplayName" "TrustDB Desktop"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrustDB" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrustDB" "Publisher" "TrustDB Community"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrustDB" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  CreateDirectory "$SMPROGRAMS\TrustDB"
  CreateShortcut "$SMPROGRAMS\TrustDB\TrustDB Desktop.lnk" "$INSTDIR\trustdb-desktop.exe"
  CreateShortcut "$SMPROGRAMS\TrustDB\Uninstall TrustDB.lnk" "$INSTDIR\Uninstall.exe"
SectionEnd

Section "Uninstall"
  Delete "$SMPROGRAMS\TrustDB\TrustDB Desktop.lnk"
  Delete "$SMPROGRAMS\TrustDB\Uninstall TrustDB.lnk"
  RMDir "$SMPROGRAMS\TrustDB"
  Delete "$INSTDIR\trustdb-desktop.exe"
  Delete "$INSTDIR\TrustDB-self-signed.cer"
  Delete "$INSTDIR\SELF_SIGNED_CLIENTS.md"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\TrustDB"
  DeleteRegKey HKCU "Software\TrustDB"
SectionEnd
