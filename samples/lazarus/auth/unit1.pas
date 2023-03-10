unit Unit1;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  HlpIHashInfo, HlpConverters, HlpHashFactory, fpjwt, base64;

type
  TForm1 = class(TForm)
    Button1: TButton;
    edJWT: TEdit;
    edSecretJWt: TEdit;
    edAssinatura: TEdit;
    Label1: TLabel;
    Label2: TLabel;
    Label3: TLabel;
    Label4: TLabel;
    mJWT: TMemo;
    procedure Button1Click(Sender: TObject);
  end;

var
  Form1: TForm1;

implementation

{$R *.lfm}

function HexToAscii(const HexStr: string): AnsiString;
Var
  B: Byte;
  Cmd: string;
  I, L: Integer;
begin
  Result := '';
  Cmd := Trim(HexStr);
  I := 1;
  L := Length(Cmd);
  while I < L do
  begin
     B := StrToInt('$' + copy(Cmd, I, 2));
     Result := Result + AnsiChar(chr(B));
     Inc( I, 2);
  end;
end;

procedure TForm1.Button1Click(Sender: TObject);
var
  LJWT: TJWT;
  LHMAC: IHMAC;
  LSignCalc: String;
begin
  LJWT := TJWT.Create;
  try
    //https://jwt.io/
    LJWT.JOSE.alg := 'HS256';
    LJWT.JOSE.typ := 'JWT';

    if edJWT.Text = EmptyStr then
    begin
      LJWT.Claims.sub := '1234567890';
      LJWT.Claims.iss := 'John Doe asadsadsad';
      LJWT.Claims.iat := 1516239022;
      edJWT.Text := LJWT.AsString;
    end
    else
      LJWT.AsString := edJWT.Text;

    if (LJWT.JOSE.alg = 'HS256') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256)
    else if (LJWT.JOSE.alg = 'HS384') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384)
    else if (LJWT.JOSE.alg = 'HS512') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512)
    else
      raise Exception.Create('[alg] not implemented');

    LHMAC.Key := TConverters.ConvertStringToBytes(UTF8Encode(edSecretJWt.Text), TEncoding.UTF8);
    LSignCalc := HexToAscii(TConverters.ConvertBytesToHexString(LHMAC.ComputeString(UTF8Encode(Trim(edJWT.Text)), TEncoding.UTF8).GetBytes,False));
    LSignCalc := LJWT.Base64ToBase64URL(EncodeStringBase64(LSignCalc));

    edAssinatura.Text := LSignCalc;

    mJWT.Lines.Clear;
    mJWT.Lines.Add(edJWT.Text+'.'+edAssinatura.Text);
  finally
    LJWT.Free;
  end;
end;

end.

