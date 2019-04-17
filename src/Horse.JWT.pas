unit Horse.JWT;

interface

uses
  Horse, System.Classes, System.JSON, Web.HTTPApp, System.SysUtils,
  JOSE.Core.JWT, JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators,
  JOSE.Consumer, JOSE.Context, REST.JSON;

procedure Middleware(Req: THorseRequest; Res: THorseResponse; Next: TProc);
function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization')
  : THorseCallback; overload;

implementation

var
  SecretJWT: string;
  SessionClass: TClass;
  Header: string;

function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;
begin
  Header := 'authorization';
  SecretJWT := ASecretJWT;
  Header := AHeader;
  Result := Middleware
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization')
  : THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT);
  SessionClass := ASessionClass;
  Header := AHeader;
end;

procedure Middleware(Req: THorseRequest; Res: THorseResponse; Next: TProc);
var
  LValidations: TJOSEConsumer;
  LJWT: TJOSEContext;
  LToken: string;
  LSession: TObject;
  LJSON: TJSONObject;
begin
  if not Req.Headers.TryGetValue(Header, LToken) and not Req.Query.TryGetValue(Header, LToken) then
  begin
    Res.Send('Token not found').Status(401);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := LToken.Replace('bearer ', '', [rfIgnoreCase]);

  LValidations := TJOSEConsumerBuilder.NewConsumer.SetVerificationKey(SecretJWT)
    .SetSkipVerificationKeyValidation.SetRequireExpirationTime.Build;

  LJWT := TJOSEContext.Create(LToken, TJWTClaims);
  try
    try
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
        Next();
      finally
        LSession.Free;
      end;

    except
      Res.Send('Unauthorized').Status(401);
      raise EHorseCallbackInterrupted.Create;
    end;
  finally
    LJWT.Free;
  end;
end;

end.
