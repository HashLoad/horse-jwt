unit Horse.JWT;

{$IF DEFINED(FPC)}
  {$MODE DELPHI}{$H+}
{$ENDIF}

interface

uses
{$IF DEFINED(FPC)}
  Generics.Collections, Classes, fpjson, SysUtils, HTTPDefs, fpjwt, Base64, DateUtils, jsonparser,
  HlpIHashInfo, HlpConverters, HlpHashFactory, StrUtils,
{$ELSE}
  System.Generics.Collections, System.Classes, System.JSON, System.SysUtils, Web.HTTPApp, REST.JSON, JOSE.Core.JWT,
  JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators, JOSE.Consumer, JOSE.Context,
{$ENDIF}
  Horse, Horse.Commons;

type
  IHorseJWTConfig = interface
  ['{71A29190-1528-4E4D-932D-86094DDA9B4A}']
     function SkipRoutes: TArray<string>; overload;
     function SkipRoutes(const ARoutes: TArray<string>): IHorseJWTConfig; overload;
     function SkipRoutes(const ARoute: string): IHorseJWTConfig; overload;
     function Header: string; overload;
     function Header(const AValue: string): IHorseJWTConfig; overload;
     function IsRequiredSubject: Boolean; overload;
     function IsRequiredSubject(const AValue: Boolean): IHorseJWTConfig; overload;
     function IsRequiredIssuedAt: Boolean; overload;
     function IsRequiredIssuedAt(const AValue: Boolean): IHorseJWTConfig; overload;
     function IsRequiredNotBefore: Boolean; overload;
     function IsRequiredNotBefore(const AValue: Boolean): IHorseJWTConfig; overload;
     function IsRequiredExpirationTime: Boolean; overload;
     function IsRequiredExpirationTime(const AValue: Boolean): IHorseJWTConfig; overload;
     function IsRequireAudience: Boolean; overload;
     function IsRequireAudience(const AValue: Boolean): IHorseJWTConfig; overload;
     function ExpectedAudience: TArray<string>; overload;
     function ExpectedAudience(const AValue: TArray<string>): IHorseJWTConfig; overload;
     function SessionClass: TClass; overload;
     function SessionClass(const AValue: TClass): IHorseJWTConfig; overload;
  end;

  { THorseJWTConfig }

  THorseJWTConfig = class(TInterfacedObject, IHorseJWTConfig)
  private
    FHeader: string;
    FSkipRoutes: TArray<string>;
    FIsRequireAudience: Boolean;
    FExpectedAudience: TArray<string>;
    FIsRequiredExpirationTime: Boolean;
    FIsRequiredIssuedAt: Boolean;
    FIsRequiredNotBefore: Boolean;
    FIsRequiredSubject: Boolean;
    FSessionClass: TClass;
    function SkipRoutes: TArray<string>; overload;
    function SkipRoutes(const ARoutes: TArray<string>): IHorseJWTConfig; overload;
    function SkipRoutes(const ARoute: string): IHorseJWTConfig; overload;
    function Header: string; overload;
    function Header(const AValue: string): IHorseJWTConfig; overload;
    function IsRequiredSubject: Boolean; overload;
    function IsRequiredSubject(const AValue: Boolean): IHorseJWTConfig; overload;
    function IsRequiredIssuedAt: Boolean; overload;
    function IsRequiredIssuedAt(const AValue: Boolean): IHorseJWTConfig; overload;
    function IsRequiredNotBefore: Boolean; overload;
    function IsRequiredNotBefore(const AValue: Boolean): IHorseJWTConfig; overload;
    function IsRequiredExpirationTime: Boolean; overload;
    function IsRequiredExpirationTime(const AValue: Boolean): IHorseJWTConfig; overload;
    function IsRequireAudience: Boolean; overload;
    function IsRequireAudience(const AValue: Boolean): IHorseJWTConfig; overload;
    function ExpectedAudience: TArray<string>; overload;
    function ExpectedAudience(const AValue: TArray<string>): IHorseJWTConfig; overload;
    function SessionClass: TClass; overload;
    function SessionClass(const AValue: TClass): IHorseJWTConfig; overload;
  public
    constructor Create;
    class function New: IHorseJWTConfig;
  end;

function HorseJWT(ASecretJWT: string; AConfig: IHorseJWTConfig = nil): THorseCallback;
procedure Middleware(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF});

implementation

var
  Config: IHorseJWTConfig;
  SecretJWT: string;

function HorseJWT(ASecretJWT: string; AConfig: IHorseJWTConfig): THorseCallback;
begin
  SecretJWT := ASecretJWT;
  Config := AConfig;
  if not Assigned(AConfig) then
    Config := THorseJWTConfig.New;
  Result := {$IF DEFINED(FPC)}@Middleware{$ELSE}Middleware{$ENDIF};
end;

procedure Middleware(AHorseRequest: THorseRequest;
  AHorseResponse: THorseResponse; ANext: {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF});
var
{$IF DEFINED(FPC)}
  LJWT: TJWT;
{$ELSE}
  LBuilder: IJOSEConsumerBuilder;
  LValidations: IJOSEConsumer;
  LJWT: TJOSEContext;
{$ENDIF}
  LPathInfo: string;
  LToken, LHeaderNormalize: string;
  LSession: TObject;
  LJSON: TJSONObject;
{$IF DEFINED(FPC)}
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

  function ValidateSignature: Boolean;
  var
    LHMAC: IHMAC;
    LSignCalc: String;
  begin
    if (LJWT.JOSE.alg = 'HS256') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256)
    else if (LJWT.JOSE.alg = 'HS384') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384)
    else if (LJWT.JOSE.alg = 'HS512') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512)
    else
      raise Exception.Create('[alg] not implemented');

    LHMAC.Key := TConverters.ConvertStringToBytes(UTF8Encode(SecretJWT), TEncoding.UTF8);
    LSignCalc := HexToAscii(TConverters.ConvertBytesToHexString(LHMAC.ComputeString(UTF8Encode(Trim(Copy(LToken,1,NPos('.',LToken,2)-1))), TEncoding.UTF8).GetBytes,False));
    LSignCalc := LJWT.Base64ToBase64URL(EncodeStringBase64(LSignCalc));

    Result := (LJWT.Signature = LSignCalc);
  end;
{$ENDIF}
begin
  LPathInfo := AHorseRequest.RawWebRequest.PathInfo;
  if LPathInfo = EmptyStr then
    LPathInfo := '/';
  if MatchRoute(LPathInfo, Config.SkipRoutes) then
  begin
    ANext();
    Exit;
  end;

  LHeaderNormalize := Config.Header;

  if Length(LHeaderNormalize) > 0 then
    LHeaderNormalize[1] := UpCase(LHeaderNormalize[1]);

  LToken := AHorseRequest.Headers[Config.Header];
  if LToken.Trim.IsEmpty and not AHorseRequest.Query.TryGetValue(Config.Header, LToken) and not AHorseRequest.Query.TryGetValue(LHeaderNormalize, LToken) then
  begin
    AHorseResponse.Send('Token not found').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  if Pos('bearer', LowerCase(LToken)) = 0 then
  begin
    AHorseResponse.Send('Invalid authorization type').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  LToken := Trim(LToken.Replace('bearer', '', [rfIgnoreCase]));

  {$IFNDEF FPC}
  LBuilder  :=  TJOSEConsumerBuilder
    .NewConsumer
    .SetVerificationKey(SecretJWT)
    .SetSkipVerificationKeyValidation;

  if Assigned(Config) then
  begin
    LBuilder.SetExpectedAudience(Config.IsRequireAudience, Config.ExpectedAudience);
    if Config.IsRequiredExpirationTime then
      LBuilder.SetRequireExpirationTime;
    if Config.IsRequiredIssuedAt then
      LBuilder.SetRequireIssuedAt;
    if Config.IsRequiredNotBefore then
      LBuilder.SetRequireNotBefore;
    if Config.IsRequiredSubject then
      LBuilder.SetRequireSubject;
  end;

  LValidations := LBuilder.Build;
  {$ENDIF}

  try
    {$IF DEFINED(FPC)}
    LJWT := TJWT.Create;
    LJWT.AsString := LToken;
    if (Trim(LJWT.Signature) = EmptyStr) or (not ValidateSignature) then
      raise Exception.Create('Invalid signature');

    if (LJWT.Claims.exp <> 0) and (LJWT.Claims.exp < DateTimeToUnix(Now)) then
      raise  Exception.Create(Format(
            'The JWT is no longer valid - the evaluation time [%s] is on or after the Expiration Time [exp=%s]',
            [DateToISO8601(Now, False), DateToISO8601(LJWT.Claims.exp, False)]));

    if (LJWT.Claims.nbf <> 0) and (LJWT.Claims.nbf < DateTimeToUnix(Now)) then
      raise  Exception.Create(Format('The JWT is not yet valid as the evaluation time [%s] is before the NotBefore [nbf=%s]',
            [DateToISO8601(Now, False), DateToISO8601(LJWT.Claims.nbf)]));

    if Assigned(Config) then
    begin
      if Config.IsRequireAudience and ((LJWT.Claims.aud) = EmptyStr) then
        raise  Exception.Create('No Audience [aud] claim present');

      if (Length(Config.ExpectedAudience)>0) and (not MatchText(LJWT.Claims.aud, Config.ExpectedAudience)) then
        raise  Exception.Create('Audience [aud] claim present in the JWT but no expected audience value(s) were provided');

      if Config.IsRequiredExpirationTime and ((LJWT.Claims.exp) = 0) then
        raise  Exception.Create('No Expiration Time [exp] claim present');

      if Config.IsRequiredIssuedAt and ((LJWT.Claims.iat) = 0) then
        raise  Exception.Create('No IssuedAt [iat] claim present');

      if Config.IsRequiredNotBefore and ((LJWT.Claims.nbf) = 0) then
        raise  Exception.Create('No NotBefore [nbf] claim present');

      if Config.IsRequiredSubject and ((LJWT.Claims.sub) = EmptyStr) then
        raise  Exception.Create('No Subject [sub] claim present');
    end;
    {$ELSE}
    LJWT := TJOSEContext.Create(LToken, TJWTClaims);
    {$ENDIF}
  except
    on E: exception do
    begin
      AHorseResponse.Send('Invalid token authorization. '+E.Message).Status(THTTPStatus.Unauthorized);
      raise EHorseCallbackInterrupted.Create;
    end;
  end;

  try
    try
      {$IF DEFINED(FPC)}
      LJSON := TJSONObject(LJWT.Claims.AsString);
      {$ELSE}
      LValidations.ProcessContext(LJWT);
      LJSON := LJWT.GetClaims.JSON;
      {$ENDIF}

      if Assigned(Config.SessionClass) then
      begin
        LSession := Config.SessionClass.Create;
        {$IF DEFINED(FPC)}
        TClaims(LSession).LoadFromJSON(LJSON);
        {$ELSE}
        TJWTClaims(LSession).JSON := LJSON.Clone as TJSONObject;
        {$ENDIF}
      end
      else
      {$IF DEFINED(FPC)}
        LSession := LJSON;
      {$ELSE}
        LSession := LJSON.Clone;
      {$ENDIF}

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
      {$IFNDEF FPC}
      if Assigned(LSession) then
        LSession.Free;
      {$ENDIF}
    end;
  finally
    LJWT.Free;
  end;
end;

{ THorseJWTConfig }

function THorseJWTConfig.SkipRoutes: TArray<string>;
begin
  Result := FSkipRoutes;
end;

function THorseJWTConfig.SkipRoutes(const ARoutes: TArray<string>): IHorseJWTConfig;
var
  I: Integer;
begin
  FSkipRoutes := ARoutes;
  for I := 0 to Pred(Length(FSkipRoutes)) do
    if Copy(Trim(FSkipRoutes[I]), 1, 1) <> '/' then
      FSkipRoutes[I] := '/' + FSkipRoutes[I];
  Result := Self;
end;

function THorseJWTConfig.Header: string;
begin
  Result := FHeader;
end;

function THorseJWTConfig.Header(const AValue: string): IHorseJWTConfig;
begin
  FHeader := AValue;
  Result := Self;
end;

function THorseJWTConfig.IsRequiredSubject: Boolean;
begin
  Result := FIsRequiredSubject;
end;

function THorseJWTConfig.IsRequiredSubject(const AValue: Boolean): IHorseJWTConfig;
begin
  FIsRequiredSubject := AValue;
  Result := Self;
end;

function THorseJWTConfig.IsRequiredIssuedAt: Boolean;
begin
  Result := FIsRequiredIssuedAt;
end;

function THorseJWTConfig.IsRequiredIssuedAt(const AValue: Boolean): IHorseJWTConfig;
begin
  FIsRequiredIssuedAt := AValue;
  Result := Self;
end;

function THorseJWTConfig.IsRequiredNotBefore: Boolean;
begin
  Result := FIsRequiredNotBefore;
end;

function THorseJWTConfig.IsRequiredNotBefore(const AValue: Boolean): IHorseJWTConfig;
begin
  FIsRequiredNotBefore := AValue;
  Result := Self;
end;

function THorseJWTConfig.IsRequiredExpirationTime: Boolean;
begin
  Result := FIsRequiredExpirationTime;
end;

function THorseJWTConfig.IsRequiredExpirationTime(const AValue: Boolean): IHorseJWTConfig;
begin
  FIsRequiredExpirationTime := AValue;
  Result := Self;
end;

function THorseJWTConfig.IsRequireAudience: Boolean;
begin
  Result := FIsRequireAudience;
end;

function THorseJWTConfig.IsRequireAudience(const AValue: Boolean): IHorseJWTConfig;
begin
  FIsRequireAudience := AValue;
  Result := Self;
end;

function THorseJWTConfig.ExpectedAudience: TArray<string>;
begin
  Result := FExpectedAudience;
end;

function THorseJWTConfig.ExpectedAudience(const AValue: TArray<string>): IHorseJWTConfig;
begin
  FExpectedAudience := AValue;
  Result := Self;
end;

function THorseJWTConfig.SessionClass: TClass;
begin
  Result := FSessionClass;
end;

function THorseJWTConfig.SessionClass(const AValue: TClass): IHorseJWTConfig;
begin
  FSessionClass := AValue;
  Result := Self;
end;

function THorseJWTConfig.SkipRoutes(const ARoute: string): IHorseJWTConfig;
begin
  Result := SkipRoutes([ARoute]);
end;

constructor THorseJWTConfig.Create;
begin
  FHeader := 'authorization';
  FIsRequireAudience := False;
  FIsRequiredExpirationTime := False;
  FIsRequiredIssuedAt := False;
  FIsRequiredNotBefore := False;
  FIsRequiredSubject := False;
end;

class function THorseJWTConfig.New: IHorseJWTConfig;
begin
  Result := Self.Create;
end;

end.
