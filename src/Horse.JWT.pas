unit Horse.JWT;

interface

uses System.Generics.Collections, System.Classes, System.JSON, System.SysUtils, Web.HTTPApp, REST.JSON, JOSE.Core.JWT,
  JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators, JOSE.Consumer, JOSE.Context, Horse, Horse.Commons;

type
  THorseJWTConfig = class
  private
    FIsRequireAudience: Boolean;
    FExpectedAudience: TArray<string>;
    FIsRequiredExpirationTime: Boolean;
    FIsRequiredIssuedAt: Boolean;
    FIsRequiredNotBefore: Boolean;
    FIsRequiredSubject: Boolean;
  public
    constructor Create;
    class function New: THorseJWTConfig;
    property IsRequiredSubject: Boolean read FIsRequiredSubject write FIsRequiredSubject;
    property IsRequiredIssuedAt: Boolean read FIsRequiredIssuedAt write FIsRequiredIssuedAt;
    property IsRequiredNotBefore: Boolean read FIsRequiredNotBefore write FIsRequiredNotBefore;
    property IsRequiredExpirationTime: Boolean read FIsRequiredExpirationTime write FIsRequiredExpirationTime;
    property IsRequireAudience: Boolean read FIsRequireAudience write FIsRequireAudience;
    property ExpectedAudience: TArray<string> read FExpectedAudience write FExpectedAudience;
  end;

  THorseJWTCallback = class
  private
    FConfig : THorseJWTConfig;
    FSecretJWT: string;
    FSessionClass: TClass;
    FHeader: string;
  public
    constructor Create;
    destructor Destroy; override;
    class function New: THorseJWTCallback;
    property Config: THorseJWTConfig read FConfig;
    function SetConfig(AConfig: THorseJWTConfig): THorseJWTCallback;
    function SetSecretJWT(ASecretJWT: string): THorseJWTCallback;
    function SetSessionClass(ASessionClass: TClass): THorseJWTCallback;
    function SetHeader(AHeader: string): THorseJWTCallback;
    procedure Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
  end;

  THorseJWTManager = class
  private
    FCallbackList: TObjectList<THorseJWTCallback>;
    class var FDefaultManager: THorseJWTManager;
    procedure SetCallbackList(const Value: TObjectList<THorseJWTCallback>);
  protected
    class function GetDefaultManager: THorseJWTManager; static;
  public
    constructor Create;
    destructor Destroy; override;
    property CallbackList: TObjectList<THorseJWTCallback> read FCallbackList write SetCallbackList;
    class destructor UnInitialize;
    class property DefaultManager: THorseJWTManager read GetDefaultManager;
  end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AConfig: THorseJWTConfig; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; AConfig: THorseJWTConfig; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;

implementation

function HorseJWT(ASecretJWT: string; AHeader: string): THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT, nil, nil, AHeader);
end;

function HorseJWT(ASecretJWT: string; AConfig: THorseJWTConfig; AHeader: string): THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT, nil, AConfig, AHeader);
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string): THorseCallback; overload;
begin
  Result := HorseJWT(ASecretJWT, ASessionClass, nil, AHeader);
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AConfig: THorseJWTConfig; AHeader: string): THorseCallback; overload;
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
    .SetSessionClass(ASessionClass)
    .SetConfig(AConfig)
    .Callback;
end;

{ THorseJWTCallback }

procedure THorseJWTCallback.Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
var
  LBuilder: IJOSEConsumerBuilder;
  LValidations: IJOSEConsumer;
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

  LBuilder  :=  TJOSEConsumerBuilder
    .NewConsumer
    .SetVerificationKey(FSecretJWT)
    .SetSkipVerificationKeyValidation;

  if Assigned(FConfig) then
  begin
    LBuilder.SetExpectedAudience(FConfig.IsRequireAudience, FConfig.ExpectedAudience);
    if FConfig.IsRequiredExpirationTime then
      LBuilder.SetRequireExpirationTime;
    if FConfig.IsRequiredIssuedAt then
      LBuilder.SetRequireIssuedAt;
    if FConfig.IsRequiredNotBefore then
      LBuilder.SetRequireNotBefore;
    if FConfig.IsRequiredSubject then
      LBuilder.SetRequireSubject;
  end;

  LValidations := LBuilder.Build;

  try
    LJWT := TJOSEContext.Create(LToken, TJWTClaims);
  except
    on E: exception do
    begin
      AHorseResponse.Send('Invalid token authorization').Status(THTTPStatus.Unauthorized);
      raise EHorseCallbackInterrupted.Create;
    end;
  end;

  try
    try
      LValidations.ProcessContext(LJWT);
      LJSON := LJWT.GetClaims.JSON;

      if Assigned(FSessionClass) then
      begin
        LSession := FSessionClass.Create;
        TJWTClaims(LSession).JSON := LJSON.Clone as TJSONObject;
      end
      else
        LSession := LJSON.Clone;

      AHorseRequest.Session(LSession);
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
end;

constructor THorseJWTCallback.Create;
begin
  FConfig := THorseJWTConfig.Create;
end;

destructor THorseJWTCallback.Destroy;
begin
  if Assigned(FConfig) then
    FConfig.Free;
  inherited;
end;

class function THorseJWTCallback.New: THorseJWTCallback;
begin
  Result := THorseJWTCallback.Create;
end;

function THorseJWTCallback.SetConfig(AConfig: THorseJWTConfig): THorseJWTCallback;
begin
  Result := Self;
  if Assigned(AConfig) then
  begin
    if Assigned(FConfig) and (FConfig <> AConfig) then
      FConfig.Free;
    FConfig := AConfig;
  end;
end;

function THorseJWTCallback.SetHeader(AHeader: string): THorseJWTCallback;
begin
  Result := Self;
  FHeader := AHeader;
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

{ THorseJWTConfig }

constructor THorseJWTConfig.Create;
begin
  FIsRequireAudience := False;
  FIsRequiredExpirationTime := False;
  FIsRequiredIssuedAt := False;
  FIsRequiredNotBefore := False;
  FIsRequiredSubject := False;
end;

class function THorseJWTConfig.New: THorseJWTConfig;
begin
  Result := Self.Create;
end;

end.
