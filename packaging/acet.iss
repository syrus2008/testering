; Inno Setup script — ACET installer (spec §45, §47; ACC-001/025).
; Workspaces live in %LOCALAPPDATA%\ACET and are NEVER removed by uninstall (INV-015).
; Repair = re-run the installer: application files are replaced, workspaces untouched.
#define AppVersion GetEnv("ACET_VERSION")
[Setup]
AppId={{6B7C4E5E-ACE7-4C11-9D0A-ACE7ACE7ACE7}
AppName=ACET
AppVersion={#AppVersion}
DefaultDirName={autopf}\ACET
DefaultGroupName=ACET
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=ACET-Setup-{#AppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\acet-ui.exe
SignedUninstaller=no

[Files]
Source: "..\dist\ACET\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\ACET"; Filename: "{app}\acet-ui.exe"
Name: "{group}\ACET Doctor"; Filename: "{app}\acet.exe"; Parameters: "doctor --full"

[Run]
Filename: "{app}\acet.exe"; Parameters: "doctor --json"; Flags: runhidden nowait postinstall skipifsilent; Description: "Run ACET self-check"

; No [UninstallDelete] entry targets {localappdata}\ACET: research data must be removed
; explicitly by the user (spec §47).
