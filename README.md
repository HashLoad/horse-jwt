# Horse-JWT

Basic JWT middleware for Horse.

### For install in your project using [boss](https://github.com/HashLoad/boss):
``` sh
$ boss install github.com/hashload/horse-jwt
```
or

``` sh
$ boss install horse-jwt
```

## Usage

#### All requests need token authorization.

```delphi
uses Horse, Horse.JWT;

begin
  THorse.Use(HorseJWT('MY-PASSWORD')); 

  THorse.Post('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('pong');
    end);

  THorse.Listen(9000);
end.
```

#### Some routes require authentication

```delphi
uses Horse, Horse.JWT;

begin
  THorse.Get('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('pong');
    end);

  THorse.Get('private', HorseJWT('MY-PASSWORD'),
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('route private');
    end);

  THorse.Listen(9000);
end.
```

## Usage samples

#### How to create the token?

```delphi
uses
  Horse, Horse.JWT,
  JOSE.Core.JWT, JOSE.Core.Builder,
  System.DateUtils, System.SysUtils;

begin
  THorse.Post('create-token',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LJWT: TJWT;
      LToken: String;
    begin
      LJWT := TJWT.Create();
      try
        // Enter the payload data
        LJWT.Claims.Expiration := IncHour(Now, 1);

        // Generating the token
        LToken := TJOSE.SHA256CompactToken('MY-PASSWORD', LJWT);
      finally
        FreeAndNil(LJWT);
      end;

      // Sending the token
      Res.Send(LToken);
    end);

  THorse.Listen(9000);
end.
```

#### How to create a custom Payload?

* Here is an example of a custom payload class.
* For the following examples, it is necessary to use this class.

```delphi
unit MyClaims;

interface

uses
  JOSE.Core.JWT, JOSE.Types.JSON;

type
  TMyClaims = class(TJWTClaims)
  strict private
    function GetId: string;
    procedure SetId(const Value: string);
    function GetName: string;
    procedure SetName(const Value: string);
    function GetEmail: string;
    procedure SetEmail(const Value: string);
  public
    property Id: string read GetId write SetId;
    property name: string read GetName write SetName;
    property Email: string read GetEmail write SetEmail;
  end;

implementation

{ TMyClaims }

function TMyClaims.GetId: string;
begin
  Result := TJSONUtils.GetJSONValue('id', FJSON).AsString;
end;

procedure TMyClaims.SetId(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('id', Value, FJSON);
end;

function TMyClaims.GetName: string;
begin
  Result := TJSONUtils.GetJSONValue('name', FJSON).AsString;
end;

procedure TMyClaims.SetName(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('name', Value, FJSON);
end;

function TMyClaims.GetEmail: string;
begin
  Result := TJSONUtils.GetJSONValue('email', FJSON).AsString;
end;

procedure TMyClaims.SetEmail(const Value: string);
begin
  TJSONUtils.SetJSONValueFrom<string>('email', Value, FJSON);
end;

end.
```

#### How to create a token with the custom payload?

```delphi
uses
  Horse, Horse.JWT,

  MyClaims in 'MyClaims.pas',

  JOSE.Core.JWT, JOSE.Core.Builder,
  System.DateUtils, System.SysUtils;

begin
  THorse.Post('create-token',
  procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
  var
    LJWT: TJWT;
    LClaims: TMyClaims;
    LToken: String;
  begin
    // Add the class
    LJWT := TJWT.Create(TMyClaims);
    try
      // Casting using the class
      LClaims := TMyClaims(LJWT.Claims);

      // Enter the payload data
      LClaims.Expiration := IncHour(Now, 1);
      LClaims.Id := '1';
      LClaims.Name := 'Horse';
      LClaims.Email := 'horse@jwt.com';

      // Generating the token
      LToken := TJOSE.SHA256CompactToken('MY-PASSWORD', LJWT);
    finally
      FreeAndNil(LJWT);    
    end;

    // Sending the token
    Res.Send(LToken);
  end);

  THorse.Listen(9000);
end.
```

#### How to read the custom Payload?

```Delphi
uses
  Horse, Horse.JWT,
  MyClaims in 'MyClaims.pas',
  System.SysUtils;

begin
  THorse.Get('ping', HorseJWT('MY-PASSWORD', TMyClaims), // Add custom payload class
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LClaims: TMyClaims;
      LId, LName, LEmail: string;
    begin
      // Get the Payload information from the Session
      LClaims := Req.Session<TMyClaims>;

      LId := LClaims.Id;
      LName := LClaims.Name;
      LEmail := LClaims.Email;

      Res.Send(Format('I’m %s and this is my email %s',[LName, LEmail]));
    end);

  THorse.Listen(9000);
end.
```

#### How to create public and private routes?

```Delphi
uses
  Horse, Horse.JWT,

  MyClaims in 'MyClaims.pas',

  JOSE.Core.JWT, JOSE.Core.Builder,
  System.DateUtils, System.SysUtils;

begin
  // Create token
  THorse.Post('create-token',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LJWT: TJWT;
      LClaims: TMyClaims;
      LToken: String;
    begin
      // Add the class
      LJWT := TJWT.Create(TMyClaims);
      try
        // Casting using the class
        LClaims := TMyClaims(LJWT.Claims);

        // Enter the payload data
        LClaims.Expiration := IncHour(Now, 1);
        LClaims.Id := '1';
        LClaims.Name := 'Horse';
        LClaims.Email := 'horse@jwt.com';

        // Generating the token
        LToken := TJOSE.SHA256CompactToken('MY-PASSWORD', LJWT);
      finally
        FreeAndNil(LJWT);
      end;

      // Sending the token
      Res.Send(LToken);
    end);

  // Route public
  THorse.Get('public',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('Route public');
    end);

  // Route private
  THorse.Get('private', HorseJWT('MY-PASSWORD', TMyClaims), // Add custom payload class
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    var
      LClaims: TMyClaims;
      LId, LName, LEmail: string;
    begin
      // Get the Payload information from the Session
      LClaims := Req.Session<TMyClaims>;

      LId := LClaims.Id;
      LName := LClaims.Name;
      LEmail := LClaims.Email;

      Res.Send(Format('I’m %s and this is my email %s', [LName, LEmail]));
    end);

  THorse.Listen(9000);
end.
```
