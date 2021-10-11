////////////////////////////////////////////////////////////////////////////////
//
//  ****************************************************************************
//  * Unit Name : PE_Sniffer
//  * Purpose   : Утилита для отображения краткой информации о PE File
//  * Author    : Dik0n
//  * Copyright : © 2009 - 2011
//  * Home Page : http://my-soft.ucoz.ru
//  * E-Mail    : dima_yar@mail.ru
//  * Version   : 0.1
//  ****************************************************************************
//
//
//  ****************************************************************************
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.
//  ****************************************************************************

program PE_Sniffer;

uses
  Windows,
  Messages, 
  CommCtrl,
  ShlObj,
  ActiveX,
  ShellAPI {CommDlg},
  uShare in 'uShare.pas',
  uPlugIns in 'uPlugIns.pas',
  PE_File in 'PE_File.pas';

{$R Dlg___.res}

type
  PIMAGE_DOS_HEADER     = ^IMAGE_DOS_HEADER;
  PIMAGE_NT_HEADERS     = ^IMAGE_NT_HEADERS;
  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;

  TOpenFilename = packed record
    lStructSize: DWORD;
    hWndOwner: HWND;
    hInstance: HINST;
    lpstrFilter: PAnsiChar;
    lpstrCustomFilter: PAnsiChar;
    nMaxCustFilter: DWORD;
    nFilterIndex: DWORD;
    lpstrFile: PAnsiChar;
    nMaxFile: DWORD;
    lpstrFileTitle: PAnsiChar;
    nMaxFileTitle: DWORD;
    lpstrInitialDir: PAnsiChar;
    lpstrTitle: PAnsiChar;
    Flags: DWORD;
    nFileOffset: Word;
    nFileExtension: Word;
    lpstrDefExt: PAnsiChar;
    lCustData: LPARAM;
    lpfnHook: function(Wnd: HWND; Msg: UINT; wParam: WPARAM; lParam: LPARAM): UINT stdcall;
    lpTemplateName: PAnsiChar;
    pvReserved: Pointer;
    dwReserved: DWORD;
    FlagsEx: DWORD;
  end;

  function GetOpenFileName(var OpenFile: TOpenFilename): BOOL; stdcall;
    external 'comdlg32.dll' name 'GetOpenFileNameA';

var
  EP_Section  : string;
  szFileName  : string;
  
  FileOffset  : DWORD;
  Handle      : HWND;
  h_Dlg       : HWND;
  hStatusBar  : HWND;

  PE          : TPEFile;

const
  H_SIZE                       = $08;

  MenuItemID                   = 99; 

  IDC_BUTTON_OPEN              = 1;
  IDC_BUTTON_HEADER            = 3;
  IDC_BUTTON_DIRECTORY         = 4;
  IDC_BUTTON_SECTIONS          = 5;
  IDC_BUTTON_SCANNER           = 6;
  IDC_BUTTON_PLUGINS           = 7;

{Ресурсы диалогов}
  RES_DIALOG_GENERAL           = 101;
  RES_DIALOG_HEADER            = 102;
  RES_DIALOG_DIRECTORY         = 103;
  RES_DIALOG_SECTIONS          = 104;
  RES_DIALOG_ABOUT             = 105;

  CTRL_EDIT_FILE               = 10;
  CTRL_EDIT_INFORMATION        = 20;
  CTRL_EDIT_LINKERINFO         = 21;
  CTRL_EDIT_ENTRYPOINT         = 22;
  CTRL_EDIT_FILEIOFFSET        = 23;
  CTRL_EDIT_SUBSYSTEM          = 24;
  CTRL_EDIT_FIRSTBYTES         = 25;
  CTRL_EDIT_EPSECTION          = 26;

  CTRL_MENU_NEWSCAN            = 1;
  CTRL_MENU_CLOSE              = 2;
  CTRL_MENU_SAVELIST           = 3;
  CTRL_MENU_CLEARLIST          = 4;
  CTRL_MENU_LOAD               = 5;
  CTRL_MENU_STOP               = 6;
  CTRL_MENU_EXPLORER           = 7;

  CTRL_LABEL_TOTALSIGNATURES   = 201;
  CTRL_LABEL_LASTUPDATE        = 202;

  SignsFile    = 'Signs.txt';
  sProjName    = 'PE Sniffer';
  sUnknown     = 'Unknown!';

  CR           = #10#13;

//------------------------------------------------------------------------------
//  Проверка версии операционной системы.
//  Функция возвращает положительный результат в случае Windows >= 2000
//------------------------------------------------------------------------------

function IsNTMachine: Boolean;
var
  OSVersionInfo: TOSVersionInfo;
begin
  Result := False;
  ZeroMemory(@OSVersionInfo, SizeOf(TOSVersionInfo));
  OSVersionInfo.dwOSVersionInfoSize := SizeOf(TOSVersionInfo);
  if GetVersionEx(OSVersionInfo) then
    if OSVersionInfo.dwPlatformId = VER_PLATFORM_WIN32_NT then
      Result := OSVersionInfo.dwMajorVersion > 4;
end;

//------------------------------------------------------------------------------

function ShortCutToFileName(const FileName: string): string;
const
  CLSCTX_INPROC_SERVER     = 1;
  CLSCTX_LOCAL_SERVER      = 4;
var
  ShellObject : IUnknown;
  ShellLink   : IShellLink;
  PersistFile : IPersistFile;
  szFName     : array[0..255] of Char;
  FindData    : TWIN32FINDDATA;

  function CreateComObject(const ClassID: TGUID): IUnknown;
  begin
    CoCreateInstance(ClassID, nil, CLSCTX_INPROC_SERVER or
      CLSCTX_LOCAL_SERVER, IUnknown, Result);
  end;

begin
  ShellObject := CreateComObject(CLSID_ShellLink);
  ShellLink := ShellObject as IShellLink;
  PersistFile := ShellObject as IPersistFile;
  with ShellLink do
  begin
    PersistFile.Load(PWChar(WideString(FileName)), 0);
    GetPath(szFName, 255, FindData, SLGP_UNCPRIORITY);
    Result := szFName;
  end;
end;

//------------------------------------------------------------------------------

function IsSoftIceLoaded: Boolean;
const
  lpName : array[Boolean] of PChar = ('\\.\SICE', '\\.\NTICE');
var
  hFile  : THandle;
begin
  Result:= False;
  hFile:= CreateFile(lpName[IsNTMachine], GENERIC_READ or GENERIC_WRITE,
    FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, 0);
  if (hFile <> INVALID_HANDLE_VALUE) then
  begin
    CloseHandle(hFile);
    Result:= True;
  end;
end;

//------------------------------------------------------------------------------

procedure ProcessMessages;
var
  Msg: TMsg;
begin
  while PeekMessage(Msg, 0, 0, 0, PM_REMOVE) do
  begin
    if Msg.Message <> WM_QUIT then
    begin
      TranslateMessage(Msg);
      DispatchMessage(Msg);
    end;
  end;
end;

//------------------------------------------------------------------------------
// Получение информации о колличестве сигналтур
//  и последнего обновления базы данных...
//------------------------------------------------------------------------------

function GetSignInfo(const FileName: string): Boolean;
var
  hFile    : Cardinal;
  FileTime : TFileTime;
  SysTime  : TSystemTime;
  f        : TextFile;
  Count    : Integer;
begin
  Result := True;

  if not FileExists(FileName) then
  begin
    Result := False;
    Exit;
  end;

  AssignFile(f, FileName);
  Reset(f);

  Count := 0;
  while not eof(f) do
  begin
    Readln(f);
    Inc(Count);
  end;
  CloseFile(f);
  SetDlgItemText(Handle, CTRL_LABEL_TOTALSIGNATURES, PChar(Format('%d',[Count])));

  hFile := CreateFile(PChar(FileName), GENERIC_READ,
                      FILE_SHARE_READ, nil, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL, 0);

  if hFile <> INVALID_HANDLE_VALUE then
  begin
    GetFileTime(hFile, nil, nil, @FileTime);
    FileTimeToSystemTime(FileTime, SysTime);

    SetDlgItemText(Handle, CTRL_LABEL_LASTUPDATE, PChar(Format('%.2d/%.2d/%d',
      [SysTime.wDay, SysTime.wMonth, SysTime.wYear])));
  end;
end;

//------------------------------------------------------------------------------
// Загрузка настроек приложения
//------------------------------------------------------------------------------

procedure LoadSettings;
begin

end;

//------------------------------------------------------------------------------
// Сохранение настроек приложения
//------------------------------------------------------------------------------

procedure SaveSettings;
begin

end;

//------------------------------------------------------------------------------
// Добавляем в системное меню свой пункт
//------------------------------------------------------------------------------

procedure AddSysMenu();
begin
  AppendMenu(GetSystemMenu(Handle, False), MF_SEPARATOR, 0, '');
  AppendMenu(GetSystemMenu(Handle, False), MF_BYPOSITION, MenuItemID, '&About');
end;

//------------------------------------------------------------------------------

procedure NotValidMZFile();
begin
  EP_Section := '';
  FileOffset := 0;

  SetDlgItemText(Handle, CTRL_EDIT_LINKERINFO, '');
  SetDlgItemText(Handle, CTRL_EDIT_ENTRYPOINT, '');
  SetDlgItemText(Handle, CTRL_EDIT_FILEIOFFSET, '');
  SetDlgItemText(Handle, CTRL_EDIT_SUBSYSTEM, '');
  SetDlgItemText(Handle, CTRL_EDIT_FIRSTBYTES, '');
  SetDlgItemText(Handle, CTRL_EDIT_EPSECTION, '');

  SetDlgItemText(Handle, CTRL_EDIT_INFORMATION, 'Not a valid MZ file');
end;

//------------------------------------------------------------------------------
// Добавляем новую строку в список секций
//------------------------------------------------------------------------------

procedure AddListViewNode(ListViewHandle: THandle;
  const Name, VirtualSize, VirtualOffset, RawSize, RawOffset, Flags: string);
var
  lvItem: TLVItem;
  nvItemIndex: Integer;

  procedure InsertItem(const szText: string; SubItem: Integer);
  begin
    lvItem.mask := LVIF_TEXT;
    lvItem.iSubItem := SubItem;
    lvItem.pszText := PChar(szText);
    lvItem.cchTextMax := Length(szText) + 1;
    ListView_SetItem(ListViewHandle, lvItem);
  end;

begin
  // Подготавливаем структуру для добавления информации в список
  nvItemIndex := ListView_GetItemCount(ListViewHandle);
  ZeroMemory(@lvItem, SizeOf(TLVItem));
  lvItem.iItem := nvItemIndex;
  lvItem.mask := LVIF_TEXT or LVIF_IMAGE;
  lvItem.pszText := PChar(Name);
  lvItem.cchTextMax := Length(Name) + 1;
  lvItem.iImage := 1;
  ListView_InsertItem(ListViewHandle, lvItem);

  InsertItem(VirtualSize,   1);
  InsertItem(VirtualOffset, 2);
  InsertItem(RawSize,       3);
  InsertItem(RawOffset,     4);
  InsertItem(Flags,         5);
end;

//------------------------------------------------------------------------------

function FindSign(fs, EntryPoint: Cardinal): string;
const
  SignLen = 1024;
var
  I         : Integer;
  s, stemp  : string;
  f         : TextFile;
  a,temp    : array[0..SignLen - 1] of Char;
  Err       : Boolean;
  BytesRead : dword;
begin
  Err := False;

  if FileExists(GetStartDir + SignsFile) then
  begin
    AssignFile(f, GetStartDir + SignsFile);
    Reset(f);

    SetFilePointer(fs, EntryPoint, nil, FILE_BEGIN);
    ReadFile(fs, a, SignLen, BytesRead, nil);
    stemp := Str2Hex(a, BytesRead);

    while not eof(f) do
    begin
      Readln(f, temp);
      s := copy(temp, pos('=', temp) + 1, MaxInt);

      for I := 0 to length(s) - 1 do
      begin
        if s[I] <> ':' then
          if s[I] <> stemp[I] then Err := True;
        if Err then break;
      end;

      if not Err then
      begin
        Result := copy(temp, pos('[', temp) + 1, pos('=', temp) - 2);
        break;
      end;

      Err := False;
      s := '';
      temp := '';
    end;

    CloseFile(f);
  end;

  if Result = '' then Result := sUnknown;
end;

//------------------------------------------------------------------------------

procedure SetDisplayInfo(const FileName: string);
var
  s,sInfo    : string;
  SubSysStr  : string;
  I          : Integer;
//  FileOffset : dword;
  hFile      : dword;
  Buf        : array[1..4] of Char;
  BytesRead  : Cardinal;
begin
  hFile := CreateFile(PChar(FileName), GENERIC_READ,
                      FILE_SHARE_READ or FILE_SHARE_WRITE, nil,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

  if hFile = INVALID_HANDLE_VALUE then
  begin
    Exit;
  end;

  szFileName := FileName;
  sInfo := '';
  FileOffset := PE.Header.OptionalHeader.AddressOfEntryPoint;
  for I := 0 to PE.SectionCount - 1 do
  begin
    with PE.Sections[I], PE.Header.OptionalHeader do
    begin
      if (AddressOfEntryPoint >= VirtualAddress) and
         (AddressOfEntryPoint <= VirtualAddress + Misc.VirtualSize) then
      begin
        FileOffset := AddressOfEntryPoint - VirtualAddress + PointerToRawData;
        EP_Section := PChar(@Name);

        sInfo := FindSign(hFile, FileOffset);

        if sInfo <> sUnknown then break;
      end;
    end;
  end;

  if sInfo = '' then sInfo := FindSign(hFile, FileOffset);

  SetFilePointer(hFile, FileOffset, nil, FILE_BEGIN);
  ReadFile(hFile, Buf, 4, BytesRead, nil);

  CloseHandle(hFile);

  s :=     Str2Hex(Buf[1], 0) + ',';
  s := s + Str2Hex(Buf[2], 0) + ',';
  s := s + Str2Hex(Buf[3], 0) + ',';
  s := s + Str2Hex(Buf[4], 0);

  with PE.Header.OptionalHeader, PE.Header.FileHeader do
  begin
    case Subsystem of
      0: SubSysStr := 'Unknown';
      1: SubSysStr := 'Native';
      2: SubSysStr := 'Win32 GUI';
      3: SubSysStr := 'Win32 Console';
    else
      SubSysStr := 'Unknown';
    end;
    SetDlgItemText(Handle, CTRL_EDIT_LINKERINFO, PChar(Format('%d.%d', [MajorLinkerVersion, MinorLinkerVersion])));
    SetDlgItemText(Handle, CTRL_EDIT_INFORMATION, PChar(sInfo));
    SetDlgItemText(Handle, CTRL_EDIT_FIRSTBYTES, PChar(s));
    SetDlgItemText(Handle, CTRL_EDIT_FILEIOFFSET, PChar(Int2Hex(FileOffset, H_SIZE)));
    SetDlgItemText(Handle, CTRL_EDIT_SUBSYSTEM, PChar(SubSysStr));
    SetDlgItemText(Handle, CTRL_EDIT_ENTRYPOINT, PChar(Int2Hex(AddressOfEntryPoint, H_SIZE)));
    SetDlgItemText(Handle, CTRL_EDIT_EPSECTION, PChar(EP_Section));
  end;
end;

//------------------------------------------------------------------------------

procedure InitDialog();
var
  s: string;
begin
  PE := TPEFile.Create;

  AddSysMenu;
  DragAcceptFiles(Handle, True);
  CheckDlgButton(Handle, 33, BST_CHECKED);
  EnableWindow(GetDlgItem(Handle, 34), False);

//  SetWindowText(Handle, 'PE [Info...]');

  hStatusBar := CreateStatusWindow(SBARS_SIZEGRIP or WS_CHILD or WS_VISIBLE,
                                   'Ready...', Handle, 500);

  SetStatusPanel(hStatusBar, 2, [200, -1]);

  if IsSoftIceLoaded then
    SetStatusText(hStatusBar, 1, 'SoftIce is loaded')
  else
    SetStatusText(hStatusBar, 1, 'SoftIce is not loaded');

  if not GetSignInfo(GetStartDir + SignsFile) then
    MessageBox(Handle, PChar(Format('Unable to open datafile (%s)',
      [SignsFile])), sProjName, MB_ICONHAND);

  if ParamCount > 0 then
  begin
    s := ParamStr(1);
    if Pos('.lnk', s) > 0 then s := ShortCutToFileName(s);

    SetDlgItemText(Handle, CTRL_EDIT_FILE, PChar(s));
    if PE.LoadFromFile(s) then
      SetDisplayInfo(s)
    else
      NotValidMZFile;
  end;
end;

//------------------------------------------------------------------------------

procedure ShowOpenDialog();
const
  Filter: PChar = 'Executable Files (.exe; .dll; .ocx; .scr; .cpl; .sys)'#0 +
                  '*.exe;*.dll;*.ocx;*.scr;*.cpl;*.sys'#0 +
                  'All Files (*.*)'#0 + '*.*'#0;
var
  OpenFilename : TOpenFilename;
  Buf          : array[0..MAX_PATH] of Char;
begin
  FillChar(OpenFileName, SizeOf(OpenFileName), 0);

  with OpenFilename do
  begin
    Buf[0] := #0;

    lStructSize := SizeOf(OpenFileName);
    hInstance   := SysInit.hInstance;
    hWndOwner   := Handle;
    lpstrFilter := Filter;
    lpstrFile   := Buf;
    nMaxFile    := MAX_PATH;
    Flags       := $800 or $1000 or $04;
  end;

  if GetOpenFileName(OpenFilename) then
  begin
    SetDlgItemText(Handle, CTRL_EDIT_FILE, Buf);
    if PE.LoadFromFile(Buf) then
      SetDisplayInfo(Buf)
    else
      NotValidMZFile;
  end;
end;

//------------------------------------------------------------------------------

procedure ShutDown;
begin
  PE.Free;
  PostQuitMessage(0);
  ExitProcess(HInstance);
  Halt;
end;

procedure InitDialogSections(hWnd: THandle);
var
  lvColumn : TLVColumn;
  lvHandle : THandle;
  I        : Integer;
begin
  FillChar(lvColumn, SizeOf(TLVColumn), 0);
  lvHandle := GetDlgItem(hWnd, 100);

  lvColumn.mask := LVCF_FMT or LVCF_WIDTH or LVCF_TEXT or LVCF_SUBITEM;
  lvColumn.fmt := LVCFMT_LEFT;

  lvColumn.cx := 76;

  lvColumn.pszText := 'Flags';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  lvColumn.pszText := 'Raw Offset';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  lvColumn.pszText := 'Raw Size';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  lvColumn.pszText := 'Virtual Offset';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  lvColumn.pszText := 'Virtual Size';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  lvColumn.pszText := 'Name';
  lvColumn.cchTextMax := Length(lvColumn.pszText) + 1;
  ListView_InsertColumn(lvHandle, 0, lvColumn);

  ListView_SetExtendedListViewStyle(lvHandle, LVS_EX_FULLROWSELECT);

  for I := 0 to PE.SectionCount - 1 do
  begin
    with PE.Sections[I] do
    begin
      AddListViewNode(lvHandle, string(@Name),
                      Int2Hex(Misc.VirtualSize, H_SIZE),
                      Int2Hex(VirtualAddress, H_SIZE),
                      Int2Hex(SizeOfRawData, H_SIZE),
                      Int2Hex(PointerToRawData, H_SIZE),
                      Int2Hex(Characteristics, H_SIZE));
    end;
  end;
end;

//------------------------------------------------------------------------------

function WindowProcDir(hWnd, Msg, wParam, lParam: LongInt): LongInt; stdcall; //обработчик сообщений
var
  I: Integer;
begin
  Result := 0;

  case Msg of
    WM_INITDIALOG:
    begin
      h_Dlg := hWnd;

//      CenterWindow(hWnd);
      SetFocus(GetDlgItem(hWnd, ID_CANCEL));
      ShowWindow(hWnd, SW_SHOW);

      with PE.Header.OptionalHeader do
      begin
        for I := 0 to 15 do
        begin
          SetDlgItemText(hWnd, I + 100, PChar(Int2Hex(DataDirectory[I].VirtualAddress, H_SIZE)));
          SetDlgItemText(hWnd, I + 200, PChar(Int2Hex(DataDirectory[I].Size, H_SIZE)));
        end;

      end;
    end;
    WM_COMMAND:
      case wParam of

        ID_CANCEL:
        begin
          EndDialog(hWnd, IDCANCEL);
        end;
      end;
  end;
end;

//------------------------------------------------------------------------------

function WindowProcHead(hWnd, Msg, wParam, lParam: LongInt): LongInt; stdcall; //обработчик сообщений
begin
  Result := 0;

  case Msg of
    WM_INITDIALOG:
    begin
      h_Dlg := hWnd;

//      CenterWindow(hWnd);
      ShowWindow(hWnd, SW_SHOW);

      with PE.Header.OptionalHeader, PE.Header.FileHeader do
      begin
        SetDlgItemText(hWnd, 100, PChar(Int2Hex(AddressOfEntryPoint, H_SIZE)));
        SetDlgItemText(hWnd, 101, PChar(Int2Hex(ImageBase, H_SIZE)));
        SetDlgItemText(hWnd, 102, PChar(Int2Hex(SizeOfImage, H_SIZE)));
        SetDlgItemText(hWnd, 103, PChar(Int2Hex(BaseOfCode, H_SIZE)));
        SetDlgItemText(hWnd, 104, PChar(Int2Hex(BaseOfData, H_SIZE)));
        SetDlgItemText(hWnd, 105, PChar(Int2Hex(SectionAlignment, H_SIZE)));
        SetDlgItemText(hWnd, 106, PChar(Int2Hex(FileAlignment, H_SIZE)));
        SetDlgItemText(hWnd, 107, PChar(Int2Hex(Magic, H_SIZE)));
        SetDlgItemText(hWnd, 112, PChar(Int2Hex(Subsystem, H_SIZE)));
        SetDlgItemText(hWnd, 113, PChar(Int2Hex(NumberOfSections, H_SIZE)));
        SetDlgItemText(hWnd, 114, PChar(Int2Hex(TimeDateStamp, H_SIZE)));
        SetDlgItemText(hWnd, 115, PChar(Int2Hex(SizeOfHeaders, H_SIZE)));
        SetDlgItemText(hWnd, 116, PChar(Int2Hex(Characteristics, H_SIZE)));
        SetDlgItemText(hWnd, 117, PChar(Int2Hex(CheckSum, H_SIZE)));
        SetDlgItemText(hWnd, 118, PChar(Int2Hex(SizeOfOptionalHeader, H_SIZE)));
        SetDlgItemText(hWnd, 119, PChar(Int2Hex(NumberOfRvaAndSizes, H_SIZE)));

        SetDlgItemText(hWnd, 1000,
          PChar(Format(' Section: [%s], EP: 0x%s',
            [EP_Section, Int2Hex(FileOffset, H_SIZE)])));
      end;

    end;
    WM_COMMAND:
      case wParam of

        ID_CANCEL:
        begin
          EndDialog(hWnd, IDCANCEL);
        end;
      end;
  end;
end;

//------------------------------------------------------------------------------

function WindowProcSections(hWnd, Msg, wParam, lParam: LongInt): LongInt; stdcall; //обработчик сообщений
begin
  Result := 0;

  case Msg of
    WM_INITDIALOG:
    begin
      h_Dlg := hWnd;
      InitDialogSections(hWnd);
    end;
    WM_COMMAND:
      case wParam of
        ID_CANCEL:
        begin
          EndDialog(hWnd, IDCANCEL);
        end;
      end;
  end;
end;

//------------------------------------------------------------------------------

function WindowProcAbout(hWnd, Msg, wParam, lParam: LongInt): LongInt; stdcall; //обработчик сообщений
begin
  Result := 0;

  case Msg of
    WM_INITDIALOG:
    begin
      h_Dlg := hWnd;
    end; {
    WM_CTLCOLORSTATIC:
    begin
      SetBkMode(wParam, TRANSPARENT);
      SetTextColor(wParam, COLOR_GRAYTEXT);
      Result := 0;
    end; }
    WM_COMMAND:
      case wParam of

        ID_CANCEL:
        begin
          EndDialog(hWnd, IDCANCEL);
        end;
      end;
  end;
end;

//------------------------------------------------------------------------------

function WindowProc(hWnd, Msg, wParam, lParam: LongInt): LongInt; stdcall; //обработчик сообщений
var
  Buf    : array[0..MAX_PATH] of Char;
  lpRect : TRect;
  I      : Integer;
  s      : string;
begin
  Result := 0;

  case Msg of
    WM_INITDIALOG:
    begin
      Handle := hWnd;

      ShowWindow(hWnd, SW_SHOW);

      InitDialog;
    end;

    WM_COMMAND:
    begin
      case wParam of

        ID_CANCEL:
        begin
          EndDialog(hWnd, IDCANCEL);
          ShutDown;
        end;
//        IDC_BUTTON_ABOUT     : About;
        IDC_BUTTON_OPEN      : ShowOpenDialog;
        IDC_BUTTON_HEADER    : DialogBox(hInstance, PChar(RES_DIALOG_HEADER), Handle, @WindowProcHead);
        IDC_BUTTON_DIRECTORY : DialogBox(hInstance, PChar(RES_DIALOG_DIRECTORY), Handle, @WindowProcDir);
        IDC_BUTTON_SECTIONS  : DialogBox(hInstance, PChar(RES_DIALOG_SECTIONS), Handle, @WindowProcSections);
        IDC_BUTTON_PLUGINS   :
        begin
          GetWindowRect(GetDlgItem(Handle, IDC_BUTTON_PLUGINS), lpRect);
          TrackPopupMenu(PluginsMenu, 0, lpRect.Right, lpRect.Top, 0, Handle, nil);
        end;
      end;

      if Length(Plugins) > 0 then
        for I := 0 to Length(Plugins) - 1 do
        begin
          if wParam = Integer(Plugins[I].hPlugin) then
            Execute(@Plugins[I], Handle, PChar(szFileName));
        end;

    end;

     WM_SYSCOMMAND: if wParam = MenuItemID then
       DialogBox(hInstance, PChar(RES_DIALOG_ABOUT), Handle, @WindowProcAbout);

     WM_DROPFILES:
     begin
       DragQueryFile(wParam, 0, Buf, MAX_PATH);
       
       s := Buf;
       if Pos('.lnk', s) > 0 then s := ShortCutToFileName(s);

       SetDlgItemText(Handle, CTRL_EDIT_FILE, PChar(s));
       if PE.LoadFromFile(s) then
         SetDisplayInfo(s)
       else
         NotValidMZFile;
     end;
  end;
end;

//------------------------------------------------------------------------------

procedure Run;
var
  Msg: TMsg;
begin
  while GetMessage(Msg, 0, 0, 0) do
  begin
    TranslateMessage(Msg);
    DispatchMessage(Msg);
  end;
end;

//------------------------------------------------------------------------------

begin
  CoInitialize(nil);
  InitCommonControls;
  DialogBoxParam(hInstance, PChar(RES_DIALOG_GENERAL), 0, @WindowProc, 0);
  CoUninitialize;
end.

//------------------------------------------------------------------------------