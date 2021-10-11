unit uPlugins;

interface

uses
  Windows, Messages;

type

  {==================================}
  {== TPluginInfo Type Declaration ==}
  {==================================}

  PPluginInfo = ^TPluginInfo;
  TPluginInfo = record
    Author      : PChar;
    Description : PChar;
  end;

  PPluginModule = ^TPluginModule;
  TPluginModule = record
    hPlugin : THandle;     // Хендл плагина
    pInfo   : TPluginInfo; // Информация о плагине
  end;

  TGetPluginInfo = procedure(Info: PPluginInfo); stdcall;
  TPluginExecute = procedure(hWnd: HWND; szFName: PChar); stdcall;

  procedure Execute(APlugin: PPluginModule; hWnd: HWND; szFName: PChar);

var
  Plugins     : array of TPluginModule;
  PlugCount   : Integer = 0;

  PluginsMenu : HMENU;

implementation

uses uShare;

//------------------------------------------------------------------------------

function LoadPlugin(const AFileName: string): Boolean;
var
  hLib          : Cardinal;
  GetPluginInfo : TGetPluginInfo;
  Ind           : Integer;
begin
  Result := False;
  hLib := LoadLibrary(PChar(AFileName));

  if hLib <> 0 then
  begin
    @GetPluginInfo := GetProcAddress(hLib, 'GetPluginInfo');

    if Assigned(GetPluginInfo) then
    begin
      Ind := Length(Plugins);
      SetLength(Plugins, Ind + 1);

      with Plugins[Ind] do
      begin
        GetPluginInfo(@pInfo);
        hPlugin := hLib;
        
        AppendMenu(PluginsMenu, MF_BYPOSITION, hLib, pInfo.Description);
      end;

      Result := True;
    end;
  end;
end;

//------------------------------------------------------------------------------

procedure UnloadPlugins;
var
  I : Integer;
begin
  for I := 0 to Length(Plugins) - 1 do
  begin
    FreeLibrary(Plugins[I].hPlugin);
  end;
  SetLength(Plugins, 0);
end;

//------------------------------------------------------------------------------

procedure SearchForPlugIns(const AFolder: string);
const
  faDirectory = $00000010;
  faAnyFile   = $0000003F;
var
  Data       : TWin32FindData;
  FindHandle : Cardinal;
begin
  FindHandle := FindFirstFile(PChar(AFolder + '*.DLL'), Data);

  if FindHandle <> INVALID_HANDLE_VALUE then
  begin
    repeat

      if Data.cFileName[0] <> '.' then
      begin
        LoadPlugin(AFolder + Data.cFileName);
      end;

    until not FindNextFile(FindHandle, Data);

    FindClose(FindHandle);
  end;
end;

//------------------------------------------------------------------------------

procedure Execute(APlugin: PPluginModule; hWnd: HWND; szFName: PChar);
var
  PluginExecute: TPluginExecute;
begin
  @PluginExecute := GetProcAddress(APlugin^.hPlugin, 'PluginExecute');

  if Assigned(PluginExecute) then
  begin
    PluginExecute(hWnd, szFName);
  end;
end;

//------------------------------------------------------------------------------

initialization
    PluginsMenu := CreatePopupMenu;
    SearchForPlugIns(GetStartDir + 'Plug-Ins\');

finalization
    DestroyMenu(PluginsMenu);
    UnloadPlugins;

//------------------------------------------------------------------------------

end.
