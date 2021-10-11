unit PE_File;

interface

uses
  Windows;

type
  PIMAGE_DOS_HEADER     = ^IMAGE_DOS_HEADER;
  PIMAGE_NT_HEADERS     = ^IMAGE_NT_HEADERS;
  PIMAGE_SECTION_HEADER = ^IMAGE_SECTION_HEADER;

  {===============================}
  {== TPEFile Class Declaration ==}
  {===============================}

  TPEFile = class
  private
    FHeader     : IMAGE_NT_HEADERS;
    FSections   : array of IMAGE_SECTION_HEADER;
//    FEPSection  : string;
//    FFileOffset : dword;

    function GetFileHeader: PImageFileHeader;
    function GetOptionalHeader: PImageOptionalHeader;
    function GetSection(Index: Integer): IMAGE_SECTION_HEADER;
    function GetSectionCount: Integer;
  public
    constructor Create;
    destructor Destroy; override;

    procedure ClearValues;
    function LoadFromFile(const FileName: String): Boolean;

    property Header: IMAGE_NT_HEADERS read FHeader;
    property FileHeader: PImageFileHeader read GetFileHeader;
    property OptionalHeader: PImageOptionalHeader read GetOptionalHeader;
    property Sections[Index: Integer]: IMAGE_SECTION_HEADER read GetSection;
    property SectionCount: Integer read GetSectionCount;
//    property EPSection: string read FEPSection;
//    property FileOffset: dword read FFileOffset;
  end;


implementation

{ TPEFile }

constructor TPEFile.Create;
begin
  FillChar(FHeader, SizeOf(IMAGE_NT_HEADERS), 0);
end;

destructor TPEFile.Destroy;
begin

  inherited;
end;

function TPEFile.GetFileHeader: PImageFileHeader;
begin
  Result := @FHeader.FileHeader;
end;

function TPEFile.GetOptionalHeader: PImageOptionalHeader;
begin
  Result := @FHeader.OptionalHeader;
end;

function TPEFile.GetSection(Index: Integer): IMAGE_SECTION_HEADER;
begin
  Result := FSections[Index];
end;

function TPEFile.GetSectionCount: Integer;
begin
  Result := FHeader.FileHeader.NumberOfSections;
end;

procedure TPEFile.ClearValues;
begin
  FillChar(FHeader, SizeOf(IMAGE_NT_HEADERS), 0);
  FSections := nil;
end;

function TPEFile.LoadFromFile(const FileName: String): Boolean;
var
  DosHead      : IMAGE_DOS_HEADER;
  hFile        : dword;
  hMapping     : dword;
//  EntryPoint   : dword;
  Memory, Ptr  : Pointer;
  I            : Integer;
begin
  Result := False;
  ClearValues;

  hFile := CreateFile(PChar(FileName), GENERIC_READ,
                      FILE_SHARE_READ or FILE_SHARE_WRITE, nil,
                      OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

  if hFile <> INVALID_HANDLE_VALUE then
  begin
    hMapping := CreateFileMapping(hFile, nil, PAGE_READONLY, 0, 0, nil);

    if hMapping <> 0 then
    begin
      Memory := MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);

      if Assigned(Memory) then
      begin
        Ptr := Memory;
        DosHead := PIMAGE_DOS_HEADER(Ptr)^;

        if DosHead.e_magic = IMAGE_DOS_SIGNATURE then
        begin
          Inc(dword(Ptr), DosHead._lfanew);
          FHeader := PIMAGE_NT_HEADERS(Ptr)^;

          if FHeader.Signature = IMAGE_NT_SIGNATURE then
          begin
            Inc(dword(Ptr), SizeOf(IMAGE_NT_HEADERS));

//            EntryPoint := FHeader.OptionalHeader.AddressOfEntryPoint;
//            FFileOffset := EntryPoint;

            SetLength(FSections, FHeader.FileHeader.NumberOfSections);
            for I := 0 to FHeader.FileHeader.NumberOfSections - 1 do
            begin
              FSections[I] := PIMAGE_SECTION_HEADER(Ptr)^;
              Inc(dword(Ptr), SizeOf(IMAGE_SECTION_HEADER));
            end;
            Result := True;
          end;
        end;
        UnMapViewOfFile(Memory);
      end;
      CloseHandle(hMapping);
    end;
  end;
  CloseHandle(hFile);
end;

end.
