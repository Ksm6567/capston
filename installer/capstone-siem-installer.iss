#define AppName "Capstone SIEM"
#define AppVersion "1.0.0"
#define AppPublisher "Capstone"
#define AppExeName "Launch-Capstone-SIEM.cmd"

[Setup]
AppId={{7E540C77-40A0-4B95-8D31-5EF4D4A0D2F9}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Capstone SIEM
DefaultGroupName={#AppName}
OutputDir=output
OutputBaseFilename=capstone-siem-setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExeName}

[Files]
Source: "..\backend\*"; DestDir: "{app}\backend"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\frontend\*"; DestDir: "{app}\frontend"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\launcher.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\installer\runtime-requirements.txt"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "..\installer\Install-Capstone-SIEM.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "..\installer\Uninstall-Capstone-SIEM.ps1"; DestDir: "{app}\installer"; Flags: ignoreversion
Source: "..\installer\Launch-Capstone-SIEM.cmd"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"

[Run]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\Install-Capstone-SIEM.ps1"" -InstallDir ""{app}"" -MySqlRootPassword ""{code:GetMySqlRootPassword}"" -DefaultAdminUsername ""{code:GetDefaultAdminUsername}"" -DefaultAdminPassword ""{code:GetDefaultAdminPassword}"""; StatusMsg: "Installing Python, runtime requirements, and MySQL 8.0.44..."; Flags: waituntilterminated

[UninstallRun]
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\installer\Uninstall-Capstone-SIEM.ps1"" -InstallDir ""{app}"""; Flags: runhidden waituntilterminated

[Code]
var
  CredentialsPage: TInputQueryWizardPage;

function ContainsForbiddenQuote(const Value: String): Boolean;
begin
  Result := Pos('"', Value) > 0;
end;

function GetMySqlRootPassword(Value: String): String;
begin
  Result := CredentialsPage.Values[0];
end;

function GetDefaultAdminUsername(Value: String): String;
begin
  Result := CredentialsPage.Values[1];
end;

function GetDefaultAdminPassword(Value: String): String;
begin
  Result := CredentialsPage.Values[2];
end;

function NextButtonClick(CurPageID: Integer): Boolean;
begin
  Result := True;
  if CurPageID = CredentialsPage.ID then
  begin
    if Trim(CredentialsPage.Values[0]) = '' then
    begin
      MsgBox('Enter a MySQL root password for the local MySQL 8.0.44 installation.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    if Trim(CredentialsPage.Values[1]) = '' then
    begin
      MsgBox('Enter a default dashboard admin username.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    if Trim(CredentialsPage.Values[2]) = '' then
    begin
      MsgBox('Enter a default dashboard admin password.', mbError, MB_OK);
      Result := False;
      exit;
    end;

    if ContainsForbiddenQuote(CredentialsPage.Values[0]) or
       ContainsForbiddenQuote(CredentialsPage.Values[1]) or
       ContainsForbiddenQuote(CredentialsPage.Values[2]) then
    begin
      MsgBox('Double quote characters (") are not allowed in the installer credential fields.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure InitializeWizard;
begin
  CredentialsPage := CreateInputQueryPage(
    wpSelectDir,
    'Runtime Setup',
    'Configure the local runtime that the installer will provision.',
    'The installer will set up Python 3.12.9, install the Python requirements, install MySQL 8.0.44 locally, and configure the default dashboard administrator.'
  );
  CredentialsPage.Add('MySQL root password:', True);
  CredentialsPage.Add('Default dashboard admin username:', False);
  CredentialsPage.Add('Default dashboard admin password:', True);
  CredentialsPage.Values[1] := 'admin';
  CredentialsPage.Values[2] := 'admin1234';
end;
