unit uShare;

interface

uses
  Windows, Messages, CommCtrl, ShlObj, ShellAPI;

  procedure SetStatusPanel(hStatusWnd: HWND; Idx: Integer; nWidths: array of Integer);
  procedure SetStatusText(hStatusWnd: HWND; Index: Integer; Value: PChar);
  procedure CenterWindow(hWindow: THandle);

  function TaskBarAddIcon(hWindow: THandle; ID: Cardinal; ICON: hIcon;
    CallbackMessage: Cardinal; Tip: PChar): Boolean;

  function Format( fmt: PChar; params: array of const ): PChar;
  function Int2Hex( Value : DWORD; Digits : Integer ) : string;
  function Str2Hex(Arr: array of Char; Size: Integer): string;
  function FileExists(const FileName: string) : Boolean;
  function HexToInt( const Value : string) : Integer;
  function BrowserFolder(AOwner : THandle) : string;
  function GetStartDir : string;
  function FileNameWithoutExt(const AFileName: string): string;

const
  H_SIZE               = $08;

implementation

//------------------------------------------------------------------------------

procedure SetStatusPanel(hStatusWnd: HWND; Idx: Integer; nWidths: array of Integer);
begin
  SendMessage(hStatusWnd, SB_SETPARTS, Idx, Integer(@nWidths[0]));
end;

//------------------------------------------------------------------------------

procedure SetStatusText(hStatusWnd: HWND; Index: Integer; Value: PChar);
begin
  SendMessage(hStatusWnd, SB_SETTEXT, Index, Integer(Value));
end;

//------------------------------------------------------------------------------
// Центрирует окно с дискриптором hWindow
//------------------------------------------------------------------------------

procedure CenterWindow(hWindow: THandle);
var
  Rect              : TRect;
  iWidth, iHeight   : Integer;
begin
  GetWindowRect(hWindow, Rect);
  iWidth := Rect.right - Rect.left;
  iHeight := Rect.bottom - Rect.top;
  Rect.left := (GetSystemMetrics(SM_CXSCREEN) - iWidth) shr 1;
  Rect.top := (GetSystemMetrics(SM_CYSCREEN) - iHeight) shr 1;
  MoveWindow(hWindow, Rect.left, Rect.top, iWidth, iHeight, False);
end;

//------------------------------------------------------------------------------
// Добавление иконки на TaskBar
//------------------------------------------------------------------------------

function TaskBarAddIcon(hWindow: THandle; ID: Cardinal; ICON: hIcon;
  CallbackMessage: Cardinal; Tip: PChar): Boolean;
var
  NID : TNotifyIconData;
begin
  FillChar(NID, SizeOf(TNotifyIconData), 0);
  with NID do
    begin
      cbSize := SizeOf(TNotifyIconData);
      Wnd := hWindow;
      uID := ID;
      uFlags := NIF_MESSAGE or NIF_ICON or NIF_TIP;
      uCallbackMessage := CallbackMessage;
      hIcon := Icon;
      lstrcpyn(szTip, Tip, SizeOf(szTip));
    end;
  Result := Shell_NotifyIcon(NIM_ADD, @NID);
end;

//------------------------------------------------------------------------------
// Аналог функции из "SysUtils.pas"
//------------------------------------------------------------------------------

function Format( fmt: PChar; params: array of const ): PChar;
var
  Buffer: array[ 0..2047 ] of Char;
  ElsArray, El: PDWORD;
  I : Integer;
  P : PDWORD;
begin
  ElsArray := nil;
  if High( params ) >= 0 then
    GetMem( ElsArray, (High( params ) + 1) * sizeof( Pointer ) );
  El := ElsArray;
  for I := 0 to High( params ) do
  begin
    P := @params[ I ];
    P := Pointer( P^ );
    El^ := DWORD( P );
    Inc( El );
  end;
  wvsprintf( @Buffer[0], fmt, PChar( ElsArray ) );
  Result := @Buffer[0];
  if ElsArray <> nil then
     FreeMem( ElsArray );
end;

//------------------------------------------------------------------------------
// Аналог функции IntToHex из "SysUtils.pas"
//------------------------------------------------------------------------------

function Int2Hex( Value : DWORD; Digits : Integer ) : string;
var Buf: array[ 0..8 ] of Char;
    Dest : PChar;

    function HexDigit( B : Byte ) : Char;
    const
      HexDigitChr: array[ 0..15 ] of Char = ( '0','1','2','3','4','5','6','7',
                                              '8','9','A','B','C','D','E','F' );
    begin
      Result := HexDigitChr[ B and $F ];
    end;

begin
  Dest := @Buf[ 8 ];
  Dest^ := #0;
  repeat
    Dec( Dest );
    Dest^ := '0';
    if Value <> 0 then
    begin
      Dest^ := HexDigit( Value and $F );
      Value := Value shr 4;
    end;
    Dec( Digits );
  until (Value = 0) and (Digits <= 0);
  Result := Dest;
end;

//------------------------------------------------------------------------------
// Переводит массив символов в HEX строку
//------------------------------------------------------------------------------

function Str2Hex(Arr: array of Char; Size: Integer): string;
var
  I: Integer;
begin
  for I := 0 to Size do
  begin
    Result := Result + Int2Hex(Byte(Arr[I]), 2);
  end;
end;

//------------------------------------------------------------------------------
// Проверяет соществует ли файл
//------------------------------------------------------------------------------

function FileExists(const FileName: string) : Boolean;
var
  Code: Integer;
begin
  Code := GetFileAttributes(PChar(FileName));
  Result := (Code <> -1) and (FILE_ATTRIBUTE_DIRECTORY and Code = 0);
end;

//------------------------------------------------------------------------------

function HexToInt( const Value : string) : Integer;
var
  I : Integer;
begin
  Result := 0;
  I := 1;
  if Value = '' then Exit;
  if Value[ 1 ] = '$' then Inc( I );
  while I <= Length( Value ) do
  begin
    if Value[ I ] in [ '0'..'9' ] then
       Result := (Result shl 4) or (Ord(Value[I]) - Ord('0'))
    else
    if Value[ I ] in [ 'A'..'F' ] then
       Result := (Result shl 4) or (Ord(Value[I]) - Ord('A') + 10)
    else
    if Value[ I ] in [ 'a'..'f' ] then
       Result := (Result shl 4) or (Ord(Value[I]) - Ord('a') + 10)
    else
      break;
    Inc( I );
  end;
end;

//------------------------------------------------------------------------------

function BrowserFolder(AOwner : THandle) : string;
var
  Bi   : TBrowseInfo;
  Buf  : array[0..MAX_PATH] of Char;
  PIDL : PItemIDList;
begin
  FillChar(Bi, sizeof(Bi), #0);
//  SHGetSpecialFolderLocation(AOwner, CSIDL_DESKTOP, PIDL);
  bi.hwndOwner := AOwner;
  bi.pszDisplayName := Buf;

  bi.ulFlags := BIF_RETURNONLYFSDIRS;
  bi.lpszTitle := 'Выбор прапки';
//  bi.pidlRoot := PIDL;
  PIDL := SHBrowseForFolder(BI);
  SHGetPathFromIDList(PIDL, Buf);
  GlobalFreePtr(PIDL);
  Result := Buf;
end;

//------------------------------------------------------------------------------
// Возвращает директорию из которой запущенно приложение
//------------------------------------------------------------------------------

function GetStartDir : string;
var
  Buffer : array[0..260] of Char;
  I      : Integer;
begin
  I := GetModuleFileName( 0, Buffer, SizeOf( Buffer ) );
  for I := I downto 0 do
    if Buffer[ I ] = '\' then
    begin
      Buffer[ I + 1 ] := #0;
      break;
    end;
  Result := Buffer;
end;

//------------------------------------------------------------------------------

function FileNameWithoutExt(const AFileName: string): string;
var
  I: Integer;
begin
  Result := AFileName;
  I := Length(AFileName);

  for I := I downto 1 do
    if AFileName[i] = '.' then
    begin
      Result := Copy(AFileName, 0, I - 1);
      break;
    end;
end;

//------------------------------------------------------------------------------

end.
