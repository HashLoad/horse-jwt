program Session;

{$MODE DELPHI}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Horse,
  Horse.JWT,
  Horse.Jhonson,
  SysUtils,
  DateUtils,
  fpjwt,
  fpjwasha256,
  fpjson;

procedure DoAuth(Req: THorseRequest; Res: THorseResponse; Next: TProc);
var
  LJWT: TJWT;
  LToken: String;
  LResult: TJSONObject;
begin
  LJWT := TJWT.Create;
  try
    LJWT.JOSE.alg := 'HS256';
    LJWT.Claims.iss := 'Horse';
    LJWT.Claims.sub := 'Leandro';
    LJWT.Claims.exp := DateTimeToUnix(IncMinute(Now, 1));
    LToken := LJWT.Sign(TJWTKey.Create('my-private-key'));
    LResult := TJSONObject.Create;
    LResult.Add('token', LToken);
    Res.Send<TJSONObject>(LResult);
  finally
    LJWT.Free;
  end;
end;

procedure GetPing(Req: THorseRequest; Res: THorseResponse; Next: TNextProc);
var
  LSession: TClaims;
  LResult: TJSONObject;
begin
  LSession := Req.Session<TClaims>;
  LResult := TJSONObject.Create;
  LResult.Add('iss', LSession.iss);
  LResult.Add('sub', LSession.sub);
  Res.Send<TJSONObject>(LResult);
end;

procedure OnListen(Horse: THorse);
begin
  Writeln(Format('Server is running in %d.', [Horse.Port]));
end;

begin
  THorse.Use(Jhonson);

  THorse.Get('/auth', @DoAuth);

  THorse
    .AddCallback(HorseJWT('my-private-key', THorseJWTConfig.New.SessionClass(TClaims)))
    .Get('ping', GetPing);

  THorse.Listen(9000, OnListen);

end.
