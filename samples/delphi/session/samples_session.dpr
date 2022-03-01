program samples_session;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  Horse,
  Horse.Jhonson,
  Horse.JWT,
  JOSE.Core.JWT,
  JOSE.Core.Builder,
  JOSE.Types.JSON,
  System.SysUtils,
  System.JSON;

type
  TMyClaims = class(TJWTClaims)
  private
    function GetuserId: string;
    procedure SetuserId(const Value: string);

  public
    property userId: string read GetuserId write SetuserId;
  end;

{ TMyClaims }

function TMyClaims.GetuserId: string;
begin
  Result := TJSONUtils.GetJSONValue('userId', FJSON).AsString;
end;

procedure TMyClaims.SetuserId(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('userId', Value, FJSON);
end;

begin
  {$IFDEF MSWINDOWS}
  ReportMemoryLeaksOnShutdown := True;
  IsConsole := False;
  {$ENDIF}

  THorse.Use(Jhonson);

  THorse.Get('/auth',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LJWT: TJWT;
      LClaims: TMyClaims;
      LToken: String;
    begin
      LJWT := TJWT.Create(TMyClaims);
      try
        LClaims := TMyClaims(LJWT.Claims);

        LClaims.Issuer := 'Horse';
        LClaims.Subject := 'Vinicius Sanchez';
        LClaims.Expiration := Now + 1;
        LClaims.userId := '1234';
        LToken := TJOSE.SHA256CompactToken('my-private-key', LJWT);
        Res.Send(TJSONObject.Create(TJSONPair.Create('token', LToken)));
      finally
        LJWT.Free;
      end;
    end);

  THorse
    .AddCallback(HorseJWT('my-private-key', THorseJWTConfig.New.SessionClass(TMyClaims)))
    .Get('ping',
      procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
      var
        LJSON: TJSONObject;
        LSession: TMyClaims;
      begin
        LSession := Req.Session<TMyClaims>;
        LJSON := TJSONObject.Create;
        LJSON.AddPair('userId', LSession.userId);
        Res.Send<TJSONObject>(LJSON);
      end);

  THorse.Listen(9000,
    procedure(Horse: THorse)
    begin
      System.Writeln(Format('Server is running in %d. Press Enter to finish...', [Horse.Port]));
      System.Readln;
    end);

end.
