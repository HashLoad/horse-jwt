program samples_auth;

{$APPTYPE CONSOLE}

uses
  Horse,
  Horse.Jhonson,
  JOSE.Core.JWT,
  JOSE.Core.Builder,
  System.SysUtils,
  System.JSON;

{$R *.res}

begin
  THorse.Use(Jhonson);

  THorse.Get('/auth',
    procedure(Req: THorseRequest; Res: THorseResponse)
    var
      LToken: TJWT;
    begin
      LToken := TJWT.Create;
      try
        LToken.Claims.Issuer := 'Horse';
        LToken.Claims.Subject := 'Vinicius Sanchez';
        LToken.Claims.Expiration := Now + 1;
        Res.Send(TJSONObject.Create(TJSONPair.Create('token', TJOSE.SHA256CompactToken('my-private-key', LToken))));
      finally
        LToken.Free;
      end;
    end);

  THorse.Listen(3000);
end.
