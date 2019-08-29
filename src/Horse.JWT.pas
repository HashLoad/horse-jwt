unit Horse.JWT;

interface

uses Horse, System.Classes, System.JSON, Web.HTTPApp, System.SysUtils, JOSE.Core.JWT, JOSE.Core.JWK, JOSE.Core.Builder,
  JOSE.Consumer.Validators, JOSE.Consumer, JOSE.Context, REST.JSON;

procedure Middleware(Req: THorseRequest; Res: THorseResponse; Next: TProc);
function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization'): THorseCallback; overload;

implementation

var
  SecretJWT: string;
  SessionClass: TClass;
  Header: string;

function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;
begin
  SecretJWT := ASecretJWT;
  Header := AHeader;
  Result := Middleware;
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization'): THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT, AHeader);
  SessionClass := ASessionClass;
end;

procedure Middleware(Req: THorseRequest; Res: THorseResponse; Next: TProc);
const
  BEARER_AUTH = 'bearer ';
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

  if not LToken.ToLower.StartsWith(BEARER_AUTH) then
  begin
    Res.Send('Invalid authorization type').Status(401);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := LToken.Replace(BEARER_AUTH, '', [rfIgnoreCase]);
  LValidations := TJOSEConsumerBuilder.NewConsumer.SetVerificationKey(SecretJWT).SetSkipVerificationKeyValidation
    .SetRequireExpirationTime.Build;

  try
    LJWT := TJOSEContext.Create(LToken, TJWTClaims);
    try
      try
        LValidations.ProcessContext(LJWT);
        LJSON := LJWT.GetClaims.JSON;

        if Assigned(SessionClass) then
          LSession := SessionClass.Create
        else
          LSession := TJSONValue.Create;

        TJson.JsonToObject(LSession, LJSON);
        THorseHackRequest(Req).SetSession(LSession);
      except
        on E: exception do
        begin
          if E.InheritsFrom(EHorseCallbackInterrupted) then
            raise EHorseCallbackInterrupted(E);
          Res.Send('Unauthorized').Status(401);
          raise EHorseCallbackInterrupted.Create;
        end;
      end;

      try
        Next();
      finally
        if Assigned(LSession) then
          LSession.Free;
      end;

    finally
      LJWT.Free;
    end;
  finally
    LValidations.Free;
  end;
end;

end.
