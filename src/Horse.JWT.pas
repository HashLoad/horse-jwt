unit Horse.JWT;

interface

uses
  System.Generics.Collections, System.Classes, System.JSON, System.SysUtils, Web.HTTPApp, REST.JSON,
  JOSE.Core.JWT, JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators, JOSE.Consumer, JOSE.Context,
  Horse, Horse.Commons;

type

  THorseJWTCallback = class
  private
    { private declarations }
    FSecretJWT: string;
    FSessionClass: TClass;
    FHeader: string;
    FExpectedAudience: TArray<string>;
    FRequireAudience: Boolean;
  protected
    { protected declarations }
  public
    { public declarations }
    class function New: THorseJWTCallback;
    function SetSecretJWT(ASecretJWT: string): THorseJWTCallback;
    function SetSessionClass(ASessionClass: TClass): THorseJWTCallback;
    function SetHeader(AHeader: string): THorseJWTCallback;
    function SetExpectedAudience(AExpectedAudience: TArray<string>): THorseJWTCallback;
    function SetRequireAudience(ARequireAudience: Boolean): THorseJWTCallback;
    procedure Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
  end;

  THorseJWTManager = class
  private
    { private declarations }
    FCallbackList: TObjectList<THorseJWTCallback>;
    class var FDefaultManager: THorseJWTManager;
    procedure SetCallbackList(const Value: TObjectList<THorseJWTCallback>);
  protected
    { protected declarations }
    class function GetDefaultManager: THorseJWTManager; static;
  public
    { public declarations }
    constructor Create;
    destructor Destroy; override;
    property CallbackList: TObjectList<THorseJWTCallback> read FCallbackList write SetCallbackList;
    class destructor UnInitialize;
    class property DefaultManager: THorseJWTManager read GetDefaultManager;
  end;

{$IFDEF ConditionalExpressions}

function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'; AExpectedAudience: TArray<string> = {$IF CompilerVersion >= 32.0} [] {$ELSE} nil
{$IFEND}; ARequireAudience: Boolean = False): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization'; AExpectedAudience: TArray<string> = {$IF CompilerVersion >= 32.0} [] {$ELSE} nil
{$IFEND}; ARequireAudience: Boolean = False): THorseCallback; overload;
{$ENDIF}

implementation


function HorseJWT(ASecretJWT: string; AHeader: string; AExpectedAudience: TArray<string>; ARequireAudience: Boolean): THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT, nil, AHeader, AExpectedAudience, ARequireAudience);
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string; AExpectedAudience: TArray<string>; ARequireAudience: Boolean): THorseCallback; overload;
var
  LHorseJWTCallback: THorseJWTCallback;
begin
  LHorseJWTCallback := THorseJWTCallback.Create;
  THorseJWTManager
    .DefaultManager
    .CallbackList
    .Add(LHorseJWTCallback);
  Result :=
    LHorseJWTCallback
    .SetSecretJWT(ASecretJWT)
    .SetHeader(AHeader)
    .SetExpectedAudience(AExpectedAudience)
    .SetRequireAudience(ARequireAudience)
    .SetSessionClass(ASessionClass)
    .Callback;
end;

{ THorseJWTCallback }

procedure THorseJWTCallback.Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
var
  LValidations: TJOSEConsumer;
  LJWT: TJOSEContext;
  LToken, LHeaderNormalize: string;
  LSession: TObject;
  LJSON: TJSONObject;
begin
  LHeaderNormalize := FHeader;

  if Length(LHeaderNormalize) > 0 then
    LHeaderNormalize[1] := UpCase(LHeaderNormalize[1]);

  LToken := AHorseRequest.Headers[FHeader];
  if LToken.Trim.IsEmpty and not AHorseRequest.Query.TryGetValue(FHeader, LToken) and not AHorseRequest.Query.TryGetValue(LHeaderNormalize, LToken) then
  begin
    AHorseResponse.Send('Token not found').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  if Pos('bearer', LowerCase(LToken)) = 0 then
  begin
    AHorseResponse.Send('Invalid authorization type').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := LToken.Replace('bearer ', '', [rfIgnoreCase]);

  LValidations := TJOSEConsumerBuilder
    .NewConsumer
    .SetVerificationKey(FSecretJWT)
    .SetExpectedAudience(FRequireAudience, FExpectedAudience)
    .SetSkipVerificationKeyValidation
    .SetRequireExpirationTime
    .Build;

  try
    LJWT := TJOSEContext.Create(LToken, TJWTClaims);
    try
      try
        LValidations.ProcessContext(LJWT);
        LJSON := LJWT.GetClaims.JSON;

        if Assigned(FSessionClass) then
        begin
          LSession := SessionClass.Create;
          TJWTClaims(LSession).JSON := LJSON.Clone as TJSONObject;
        end
        else
          LSession := LJSON.Clone;

        THorseHackRequest(AHorseRequest).SetSession(LSession);
      except
        on E: exception do
        begin
          if E.InheritsFrom(EHorseCallbackInterrupted) then
            raise EHorseCallbackInterrupted(E);
          AHorseResponse.Send('Unauthorized').Status(THTTPStatus.Unauthorized);
          raise EHorseCallbackInterrupted.Create;
        end;
      end;
      try
        ANext();
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

class function THorseJWTCallback.New: THorseJWTCallback;
begin
  Result := THorseJWTCallback.Create;
end;

function THorseJWTCallback.SetExpectedAudience(AExpectedAudience: TArray<string>): THorseJWTCallback;
begin
  Result := Self;
  FExpectedAudience := AExpectedAudience;
end;

function THorseJWTCallback.SetHeader(AHeader: string): THorseJWTCallback;
begin
  Result := Self;
  FHeader := AHeader;
end;

function THorseJWTCallback.SetRequireAudience(ARequireAudience: Boolean): THorseJWTCallback;
begin
  Result := Self;
  FRequireAudience := ARequireAudience;
end;

function THorseJWTCallback.SetSecretJWT(ASecretJWT: string): THorseJWTCallback;
begin
  Result := Self;
  FSecretJWT := ASecretJWT;
end;

function THorseJWTCallback.SetSessionClass(ASessionClass: TClass): THorseJWTCallback;
begin
  Result := Self;
  FSessionClass := ASessionClass;
end;

{ THorseJWTManager }

constructor THorseJWTManager.Create;
begin
  FCallbackList := TObjectList<THorseJWTCallback>.Create(True);
end;

destructor THorseJWTManager.Destroy;
begin
  FCallbackList.Free;
  inherited;
end;

class function THorseJWTManager.GetDefaultManager: THorseJWTManager;
begin
  if FDefaultManager = nil then
    FDefaultManager := THorseJWTManager.Create;
  Result := FDefaultManager;
end;

procedure THorseJWTManager.SetCallbackList(const Value: TObjectList<THorseJWTCallback>);
begin
  FCallbackList := Value;
end;

class destructor THorseJWTManager.UnInitialize;
begin
  FreeAndNil(FDefaultManager);
end;

end.
