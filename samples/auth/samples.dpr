program samples;

{$APPTYPE CONSOLE}

uses
  Horse,
  Horse.Jhonson,
  JOSE.Core.JWT,
  JOSE.Core.Builder,
  System.SysUtils,
  System.JSON;

{$R *.res}

var
  App: THorse;

begin
  App := THorse.Create(9000);

  App.Use(Jhonson);

  App.Get('/auth',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LToken: TJWT;
    begin
      LToken := TJWT.Create;
      try
        LToken.Claims.Issuer := 'Horse';
        LToken.Claims.Subject := 'Vinicius Sanchez';
        LToken.Claims.Expiration := Now + 1;
        Res.Send(TJSONObject.Create(TJSONPair.Create('token', TJOSE.SHA256CompactToken('EC2019', LToken))));
      finally
        LToken.Free;
      end;
    end);

  App.Start;
end.
