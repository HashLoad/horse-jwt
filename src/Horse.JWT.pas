unit Horse.JWT;

{$IF DEFINED(FPC)}
{$MODE DELPHI}{$H+}
{$ENDIF}

interface

uses
  {$IF DEFINED(FPC)}
  Generics.Collections, Classes, fpjson, SysUtils, HTTPDefs, fpjwt, Base64, DateUtils, jsonparser,
  HlpIHashInfo, HlpConverters, HlpHashFactory,
  {$ELSE}
  System.Generics.Collections, System.Classes, System.JSON, System.SysUtils, Web.HTTPApp, REST.JSON, JOSE.Core.JWT,
  JOSE.Core.JWK, JOSE.Core.Builder, JOSE.Consumer.Validators, JOSE.Consumer, JOSE.Context,
  {$ENDIF}
  Horse, Horse.Commons;

type
  IHorseJWTConfig = interface
  ['{71A29190-1528-4E4D-932D-86094DDA9B4A}']
     procedure SetSkipRoutes(const ARoutes: TArray<string>);
  end;

  THorseJWTConfig = class(TInterfacedObject, IHorseJWTConfig)
  private
    FSkipRoutes: TArray<string>;
    FIsRequireAudience: Boolean;
    FExpectedAudience: TArray<string>;
    FIsRequiredExpirationTime: Boolean;
    FIsRequiredIssuedAt: Boolean;
    FIsRequiredNotBefore: Boolean;
    FIsRequiredSubject: Boolean;
    procedure SetSkipRoutes(const ARoutes: TArray<string>);
  public
    constructor Create;
    class function New: THorseJWTConfig;
    property IsRequiredSubject: Boolean read FIsRequiredSubject write FIsRequiredSubject;
    property IsRequiredIssuedAt: Boolean read FIsRequiredIssuedAt write FIsRequiredIssuedAt;
    property IsRequiredNotBefore: Boolean read FIsRequiredNotBefore write FIsRequiredNotBefore;
    property IsRequiredExpirationTime: Boolean read FIsRequiredExpirationTime write FIsRequiredExpirationTime;
    property IsRequireAudience: Boolean read FIsRequireAudience write FIsRequireAudience;
    property ExpectedAudience: TArray<string> read FExpectedAudience write FExpectedAudience;
    property SkipRoutes: TArray<string> read FSkipRoutes write SetSkipRoutes;
  end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AConfig: THorseJWTConfig; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; AConfig: THorseJWTConfig; AHeader: string = 'authorization'): THorseCallback; overload;
function HorseJWT(ASecretJWT: string; AHeader: string = 'authorization'): THorseCallback; overload;
procedure Middleware(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF});

implementation

uses
  {$IF DEFINED(FPC)}
  StrUtils
  {$ELSE}
  System.StrUtils
  {$ENDIF}
  ;

var
  Config: THorseJWTConfig;
  SecretJWT: string;
  SessionClass: TClass;
  Header: string;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AConfig: THorseJWTConfig; AHeader: string): THorseCallback;
begin
  SecretJWT := ASecretJWT;
  SessionClass := ASessionClass;
  Config := AConfig;
  Header := AHeader;
  Result := {$IF DEFINED(FPC)}@Middleware{$ELSE}Middleware{$ENDIF};
end;

function HorseJWT(ASecretJWT: string; ASessionClass: TClass; AHeader: string): THorseCallback;
begin
  SecretJWT := ASecretJWT;
  SessionClass := ASessionClass;
  Header := AHeader;
  Result := {$IF DEFINED(FPC)}@Middleware{$ELSE}Middleware{$ENDIF};
end;

function HorseJWT(ASecretJWT: string; AConfig: THorseJWTConfig; AHeader: string): THorseCallback;
begin
  SecretJWT := ASecretJWT;
  Config := AConfig;
  Header := AHeader;
  Result := {$IF DEFINED(FPC)}@Middleware{$ELSE}Middleware{$ENDIF};
end;

function HorseJWT(ASecretJWT: string; AHeader: string): THorseCallback; overload;
begin
  SecretJWT := ASecretJWT;
  Header := AHeader;
  Result := {$IF DEFINED(FPC)}@Middleware{$ELSE}Middleware{$ENDIF};
end;

procedure Middleware(AHorseRequest: THorseRequest;
  AHorseResponse: THorseResponse; ANext:  {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF});
var
  {$IF DEFINED(FPC)}
  LJWT: TJWT;
  {$ELSE}
  LBuilder: IJOSEConsumerBuilder;
  LValidations: IJOSEConsumer;
  LJWT: TJOSEContext;
  {$ENDIF}
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
  if Assigned(Config)then
  begin
    if MatchText(AHorseRequest.RawWebRequest.PathInfo, Config.SkipRoutes) then
    begin
      ANext();
      Exit;
    end;
  end;

  LHeaderNormalize := Header;

  if Length(LHeaderNormalize) > 0 then
    LHeaderNormalize[1] := UpCase(LHeaderNormalize[1]);

  LToken := AHorseRequest.Headers[Header];
  if LToken.Trim.IsEmpty and not AHorseRequest.Query.TryGetValue(Header, LToken) and not AHorseRequest.Query.TryGetValue(LHeaderNormalize, LToken) then
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

      if Assigned(SessionClass) then
      begin
        LSession := SessionClass.Create;
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

procedure THorseJWTConfig.SetSkipRoutes(const ARoutes: TArray<string>);
var
  I: Integer;
begin
  FSkipRoutes := ARoutes;
  for I := 0 to Pred(Length(FSkipRoutes)) do
    if Copy(Trim(FSkipRoutes[I]), 1, 1) <> '/' then
      FSkipRoutes[I] := '/' + FSkipRoutes[I];
end;

end.
