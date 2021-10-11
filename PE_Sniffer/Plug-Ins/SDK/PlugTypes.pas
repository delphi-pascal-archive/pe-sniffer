unit PlugTypes;

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

  function Format( fmt: PChar; params: array of const ): PChar;
  procedure SetOwnerFormCenter(phWnd, hWnd: HWND);

implementation

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

procedure SetOwnerFormCenter(phWnd, hWnd: HWND);
var
  pwRect: TRect;
  wRect : TRect;
begin
  GetWindowRect(phWnd, pwRect);
  GetWindowRect(hWnd, wRect);

  SetWindowPos(hWnd,
               phWnd,
               (((pwRect.Right - pwRect.Left) - (wRect.Right - wRect.Left)) shr 1) + pwRect.Left,
               (((pwRect.Bottom - pwRect.Top) - (wRect.Bottom - wRect.Top)) shr 1) + pwRect.Top,
               0,
               0,
               SW_NORMAL);
end;

//------------------------------------------------------------------------------

end.
