unit Horse.JWT;

interface

uses
  Horse, System.Classes, System.JSON, Web.HTTPApp, System.SysUtils,
  JOSE.Core.JWT, JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators,
  JOSE.Consumer, JOSE.Context, REST.JSON;

procedure Middleware(Req: THorseRequest; Res: THorseResponse; Next: TProc);
function HorseJWT(ASecretJWT: string): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass)
  : THorseCallback; overload;

implementation

var
  SecretJWT: string;
  SessionClass: TClass;

function HorseJWT(ASecretJWT: string): THorseCallback; overload;
begin
  SecretJWT := ASecretJWT;
  Result := Middleware;
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass)
  : THorseCallback; overload;
begin
  SecretJWT := ASecretJWT;
  SessionClass := ASessionClass;
  Result := Middleware;
end;

procedure Middleware(Req: THorseRequest; Res: THorseResponse;
  Next: TProc);
var
  LValidations: TJOSEConsumer;
  LJWT: TJOSEContext;
  LToken: string;
  LSession: TObject;
  LJSON: TJSONObject;
begin
  if not Req.Headers.TryGetValue('authorization', LToken) then
  begin
    Res.Send('Token not found').Status(401);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := LToken.Replace('bearer ', '', [rfIgnoreCase]);

  LValidations := TJOSEConsumerBuilder.NewConsumer.SetVerificationKey
    (SecretJWT).SetSkipVerificationKeyValidation.
    SetRequireExpirationTime.Build;

  LJWT := TJOSEContext.Create(LToken, TJWTClaims);
  try
    LValidations.ProcessContext(LJWT);
    LJSON := LJWT.GetClaims.JSON;

    if Assigned(SessionClass) then
    begin
      LSession := SessionClass.Create;
      TJson.JsonToObject(LSession, LJSON);
    end
    else
      LSession := LJSON;

    THorseHackRequest(Req).SetSession(LSession);
  except
    Res.Send('Unauthorized').Status(401);
    raise EHorseCallbackInterrupted.Create;
  end;
end;

end.
