unit Horse.JWT;

{$IF DEFINED(FPC)}
  {$MODE DELPHI}{$H+}
{$ENDIF}

interface

uses
{$IF DEFINED(FPC)}
  Classes,
  fpjson,
  SysUtils,
  HTTPDefs,
  fpjwt,
  Base64,
  DateUtils,
  jsonparser,
  HlpIHashInfo,
  HlpConverters,
  HlpHashFactory,
  StrUtils,
{$ELSE}
  System.Generics.Collections,
  System.Classes,
  System.JSON,
  System.SysUtils,
  Web.HTTPApp,
  REST.JSON,
  JOSE.Core.JWT,
  JOSE.Core.JWK,
  JOSE.Core.Builder,
  JOSE.Consumer.Validators,
  JOSE.Consumer,
  JOSE.Context,
{$ENDIF}
  Horse,
  Horse.Commons;

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

function HorseJWT(const ASecretJWT: string; const AConfig: IHorseJWTConfig = nil): THorseCallback;

implementation

{$IF DEFINED(FPC) AND NOT DEFINED(HORSE_FPC_FUNCTIONREFERENCES)}
var
  SecretJWT: string;
  Config: IHorseJWTConfig;
{$ENDIF}

const
  TOKEN_NOT_FOUND = 'Token not found';
  INVALID_AUTHORIZATION_TYPE = 'Invalid authorization type';
  UNAUTHORIZED = 'Unauthorized';

procedure Middleware(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF}; const ASecretJWT: string; const AConfig: IHorseJWTConfig);
var
{$IF DEFINED(FPC)}
  LJWT: TJWT;
  LStartTokenPayloadPos: Integer;
  LEndTokenPayloadPos: Integer;
{$ELSE}
  LBuilder: IJOSEConsumerBuilder;
  LValidations: IJOSEConsumer;
  LJWT: TJOSEContext;
{$ENDIF}
  LPathInfo: string;
  LToken, LHeaderNormalize: string;
  LSession: TObject;
  LJSON: TJSONObject;
  LConfig: IHorseJWTConfig;
{$IF DEFINED(FPC)}
  function HexToAscii(const HexStr: string): AnsiString;
  var
    LByte: Byte;
    LCmd: string;
    LLength: Integer;
    LIndex: Integer;
  begin
    Result := '';
    LCmd := Trim(HexStr);
    LIndex := 1;
    LLength := Length(LCmd);
    while LIndex < LLength do
    begin
      LByte := StrToInt('$' + copy(LCmd, LIndex, 2));
      Result := Result + AnsiChar(chr(LByte));
      Inc(LIndex, 2);
    end;
  end;

  function ValidateSignature: Boolean;
  var
    LHMAC: IHMAC;
    LSignCalc: string;
  begin
    if (LJWT.JOSE.alg = 'HS256') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_256)
    else
      if (LJWT.JOSE.alg = 'HS384') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_384)
    else
      if (LJWT.JOSE.alg = 'HS512') then
      LHMAC := THashFactory.THMAC.CreateHMAC(THashFactory.TCrypto.CreateSHA2_512)
    else
      raise Exception.Create('[alg] not implemented');

    LHMAC.Key := TConverters.ConvertStringToBytes(UTF8Encode(ASecretJWT), TEncoding.UTF8);
    LSignCalc := HexToAscii(TConverters.ConvertBytesToHexString(LHMAC.ComputeString(UTF8Encode(Trim(copy(LToken, 1, NPos('.', LToken, 2) - 1))), TEncoding.UTF8).GetBytes, False));
    LSignCalc := LJWT.Base64ToBase64URL(EncodeStringBase64(LSignCalc));

    Result := (LJWT.Signature = LSignCalc);
  end;
{$ENDIF}
begin
  LConfig := AConfig;
  if AConfig = nil then
    LConfig := THorseJWTConfig.New;
  LPathInfo := AHorseRequest.RawWebRequest.PathInfo;
  if LPathInfo = EmptyStr then
    LPathInfo := '/';
  if MatchRoute(LPathInfo, LConfig.SkipRoutes) then
  begin
    ANext();
    Exit;
  end;

  LHeaderNormalize := LConfig.Header;

  if Length(LHeaderNormalize) > 0 then
    LHeaderNormalize[1] := UpCase(LHeaderNormalize[1]);

  LToken := AHorseRequest.Headers[LConfig.Header];
  if LToken.Trim.IsEmpty and not AHorseRequest.Query.TryGetValue(
    LConfig.Header, LToken) and not AHorseRequest.Query.TryGetValue(
    LHeaderNormalize, LToken) then
  begin
    AHorseResponse.Send(TOKEN_NOT_FOUND).Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create(TOKEN_NOT_FOUND);
  end;

  if Pos('bearer', LowerCase(LToken)) = 0 then
  begin
    AHorseResponse.Send(INVALID_AUTHORIZATION_TYPE).Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create(INVALID_AUTHORIZATION_TYPE);
  end;

  LToken := Trim(LToken.Replace('bearer', '', [rfIgnoreCase]));
  try
{$IFNDEF FPC}
    LBuilder := TJOSEConsumerBuilder.NewConsumer.SetVerificationKey(ASecretJWT)
      .SetSkipVerificationKeyValidation;

    if Assigned(LConfig) then
    begin
      LBuilder.SetExpectedAudience(LConfig.IsRequireAudience, LConfig.ExpectedAudience);
      if LConfig.IsRequiredExpirationTime then
        LBuilder.SetRequireExpirationTime;
      if LConfig.IsRequiredIssuedAt then
        LBuilder.SetRequireIssuedAt;
      if LConfig.IsRequiredNotBefore then
        LBuilder.SetRequireNotBefore;
      if LConfig.IsRequiredSubject then
        LBuilder.SetRequireSubject;
    end;

    try
      LJWT := TJOSEContext.Create(LToken, TJWTClaims);
    except
      AHorseResponse.Send(UNAUTHORIZED).Status(THTTPStatus.Unauthorized);
      raise EHorseCallbackInterrupted.Create(UNAUTHORIZED);
    end;

    try
      if LJWT.GetJOSEObject = nil then
      begin
        AHorseResponse.Send(UNAUTHORIZED).Status(THTTPStatus.Unauthorized);
        raise EHorseCallbackInterrupted.Create(UNAUTHORIZED);
      end;

      LValidations := LBuilder.Build;
      try
        LValidations.ProcessContext(LJWT);
        LJSON := LJWT.GetClaims.JSON;
        if Assigned(LConfig.SessionClass) then
        begin
          LSession := LConfig.SessionClass.Create;
          TJWTClaims(LSession).JSON := LJSON.Clone as TJSONObject;
        end
        else
          LSession := LJSON.Clone;
{$ELSE}
    LJWT := TJWT.Create;
    try
      LJWT.AsString := LToken;
      try
        if (Trim(LJWT.Signature) = EmptyStr) or (not ValidateSignature) then
          raise Exception.Create('Invalid signature');

        if (LJWT.Claims.exp <> 0) and (LJWT.Claims.exp < DateTimeToUnix(Now)) then
          raise Exception.Create(Format(
            'The JWT is no longer valid - the evaluation time [%s] is on or after the Expiration Time [exp=%s]',
            [DateToISO8601(Now, False), DateToISO8601(LJWT.Claims.exp, False)]));

        if (LJWT.Claims.nbf <> 0) and (LJWT.Claims.nbf < DateTimeToUnix(Now)) then
          raise Exception.Create(Format('The JWT is not yet valid as the evaluation time [%s] is before the NotBefore [nbf=%s]',
            [DateToISO8601(Now, False), DateToISO8601(LJWT.Claims.nbf)]));

        if Assigned(LConfig) then
        begin
          if LConfig.IsRequireAudience and ((LJWT.Claims.aud) = EmptyStr) then
            raise Exception.Create('No Audience [aud] claim present');

          if (Length(LConfig.ExpectedAudience) > 0) and (not MatchText(LJWT.Claims.aud, LConfig.ExpectedAudience)) then
            raise Exception.Create('Audience [aud] claim present in the JWT but no expected audience value(s) were provided');

          if LConfig.IsRequiredExpirationTime and ((LJWT.Claims.exp) = 0) then
            raise Exception.Create('No Expiration Time [exp] claim present');

          if LConfig.IsRequiredIssuedAt and ((LJWT.Claims.iat) = 0) then
            raise Exception.Create('No IssuedAt [iat] claim present');

          if LConfig.IsRequiredNotBefore and ((LJWT.Claims.nbf) = 0) then
            raise Exception.Create('No NotBefore [nbf] claim present');

          if LConfig.IsRequiredSubject and ((LJWT.Claims.sub) = EmptyStr) then
            raise Exception.Create('No Subject [sub] claim present');
        end;
        LStartTokenPayloadPos := Pos('.', LToken) + 1;
        LEndTokenPayloadPos := NPos('.', LToken, 2) - LStartTokenPayloadPos;
        LJSON := GetJSON(LJWT.DecodeString(copy(LToken, LStartTokenPayloadPos, LEndTokenPayloadPos))) as TJSONObject;
        if Assigned(LConfig.SessionClass) then
        begin
          try
            LSession := LConfig.SessionClass.Create;
            TClaims(LSession).LoadFromJSON(LJSON);
          finally
            if Assigned(LJSON) then
              LJSON.Free;
          end;
        end
        else
          LSession := LJSON;
{$ENDIF}
        AHorseRequest.Session(LSession);
      except
        on E: Exception do
        begin
          AHorseResponse.Send(UNAUTHORIZED).Status(THTTPStatus.Unauthorized);
          raise EHorseCallbackInterrupted.Create(UNAUTHORIZED);
        end;
      end;
    finally
      LJWT.Free;
    end;
  except
    on E: EHorseCallbackInterrupted do
      raise;
    on E: Exception do
    begin
      AHorseResponse.Send('Invalid token authorization. ' + E.Message).Status(THTTPStatus.Unauthorized);
      raise EHorseCallbackInterrupted.Create;
    end;
  end;
  try
    ANext();
  finally
    LSession.Free;
  end;
end;

{$IF DEFINED(FPC) AND NOT DEFINED(HORSE_FPC_FUNCTIONREFERENCES)}
procedure Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: {$IF DEFINED(FPC)}TNextProc{$ELSE}TProc{$ENDIF});
begin
  Middleware(AHorseRequest, AHorseResponse, ANext, SecretJWT, Config);
end;
{$ENDIF}

function HorseJWT(const ASecretJWT: string; const AConfig: IHorseJWTConfig): THorseCallback;
{$IF DEFINED(FPC) AND DEFINED(HORSE_FPC_FUNCTIONREFERENCES)}
  procedure InternalCallback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TNextProc);
  begin
    Middleware(AHorseRequest, AHorseResponse, ANext, ASecretJWT, AConfig);
  end;
{$ENDIF}
begin
{$IF DEFINED(FPC)}
{$IF NOT DEFINED(HORSE_FPC_FUNCTIONREFERENCES)}
  SecretJWT := ASecretJWT;
  Config := AConfig;
  Result := Callback;
{$ELSE}
  Result := InternalCallback;
{$ENDIF}
{$ELSE}
  Result := procedure(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc)
    begin
      Middleware(AHorseRequest, AHorseResponse, ANext, ASecretJWT, AConfig);
    end;
{$ENDIF}
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
    if copy(Trim(FSkipRoutes[I]), 1, 1) <> '/' then
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
