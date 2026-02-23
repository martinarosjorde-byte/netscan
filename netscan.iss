[Setup]
AppName=NetScan
AppVersion=1.2.0
DefaultDirName={autopf}\NetScan
DefaultGroupName=NetScan
OutputDir=.
OutputBaseFilename=NetScan-Installer
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

[Dirs]
Name: "{commonappdata}\NetScan"
Name: "{app}\fingerprints"

[Files]
Source: "dist\netscan\*"; DestDir: "{app}"; Flags: recursesubdirs createallsubdirs
Source: "fingerprints\fingerprints.json"; DestDir: "{app}\fingerprints"; Flags: onlyifdoesntexist
Source: "fingerprints\fingerprints.json"; DestDir: "{commonappdata}\NetScan"; Flags: onlyifdoesntexist

[Icons]
Name: "{group}\NetScan"; Filename: "{app}\netscan.exe"
Name: "{commondesktop}\NetScan"; Filename: "{app}\netscan.exe"

[Run]
Filename: "{app}\netscan.exe"; Description: "Launch NetScan"; Flags: nowait postinstall skipifsilent

[Registry]
Root: HKLM; Subkey: "SYSTEM\CurrentControlSet\Control\Session Manager\Environment"; \
    ValueType: expandsz; ValueName: "Path"; ValueData: "{olddata};{app}"; \
    Check: NeedsAddPath(ExpandConstant('{app}'))

[Code]

function NeedsAddPath(Dir: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKLM,
    'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
    'Path', OrigPath)
  then
    Result := True
  else
    Result := Pos(';' + Dir + ';', ';' + OrigPath + ';') = 0;
end;


procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OrigPath: string;
begin
  if CurUninstallStep = usUninstall then
  begin
    if RegQueryStringValue(HKLM,
      'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
      'Path', OrigPath) then
    begin
      StringChangeEx(OrigPath, ';' + ExpandConstant('{app}'), '', True);
      StringChangeEx(OrigPath, ExpandConstant('{app}') + ';', '', True);
      StringChangeEx(OrigPath, ExpandConstant('{app}'), '', True);

      RegWriteStringValue(HKLM,
        'SYSTEM\CurrentControlSet\Control\Session Manager\Environment',
        'Path', OrigPath);
    end;
  end;
end;