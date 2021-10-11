library Plugin;

uses
  Windows, Messages, CommCtrl, PlugTypes;

{$R Dialog_180.res}

var
  Handle : HWND;

//------------------------------------------------------------------------------

function DialogProc(hWnd: HWND; uMsg: UINT; wParam: WPARAM;
  lParam: LPARAM): LongInt; stdcall;
begin
  Result := 0;

   case uMsg of
     WM_INITDIALOG:
     begin
       Handle := hWnd;
       ShowWindow(hWnd, SW_SHOW);

       SetDlgItemText(hWnd, 1123, PChar(lParam));

       SendDlgItemMessage(hWnd, 1122, PBM_SETRANGE, 0, MakeLong(0, 100));
       SendDlgItemMessage(hWnd, 1122, PBM_SETPOS, 50, 0);

//       SetOwnerFormCenter(HwdParent, Hwd);
     end;
     WM_COMMAND:
       case wParam of
         IDOK:
         begin

         end;
//         EnableWindow(GetDlgItem(hwndDlg, 1435), false);

         ID_CANCEL:
         begin
           EndDialog(hWnd, IDCANCEL);
         end;
//         1542: CheckDlgButton(hWnd, 1512, 1);
       end;
   end;
end;

//------------------------------------------------------------------------------

procedure PluginExecute(hWnd: HWND; szFName: PChar); stdcall;
begin
  DialogBoxParam(HInstance, '#180', hWnd, @DialogProc, Integer(szFName));
end;

//------------------------------------------------------------------------------

procedure GetPluginInfo(Info: PPluginInfo); stdcall;   
begin
  Info^.Author := 'Dim@-X';
  Info^.Description := 'Sample plugin';
end;

//------------------------------------------------------------------------------

exports
  GetPluginInfo,
  PluginExecute;

//------------------------------------------------------------------------------

begin
end.
