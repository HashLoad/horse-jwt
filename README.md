# Horse-JWT
<b>Horse-JWT</b> is a official middleware for generate and validate <a href="https://jwt.io/">JWT</a> in APIs developed with the <a href="https://github.com/HashLoad/horse">Horse</a> framework.
<br>We created a channel on Telegram for questions and support:<br><br>
<a href="https://t.me/hashload">
  <img src="https://img.shields.io/badge/telegram-join%20channel-7289DA?style=flat-square">
</a>

## ⭕ Prerequisites
##### Delphi
- [**delphi-jose-jwt**](https://github.com/paolo-rossi/delphi-jose-jwt) - JOSE is a standard that provides a general approach to the signing and encryption of any content.

##### Lazarus
- [**hashlib4pascal**](https://github.com/andre-djsystem/hashlib4pascal) - is an Object Pascal hashing library released under the permissive MIT License which provides an easy to use interface for computing hashes and checksums of data. It also supports state based (incremental) hashing.


## ⚙️ Installation
Installation is done using the [`boss install`](https://github.com/HashLoad/boss) command:
``` sh
boss install horse-jwt
```
If you choose to install manually, simply add the following folders to your project, in *Project > Options > Resource Compiler > Directories and Conditionals > Include file search path*

##### Delphi
```
../horse-jwt/src
../delphi-jose-jwt/Source/Common
../delphi-jose-jwt/Source/JOSE
```

##### Lazarus
```
../horse-jwt/src
../HashLib/src/Base
../HashLib/src/Checksum
../HashLib/src/Crypto
../HashLib/src/Hash128
../HashLib/src/Hash32
../HashLib/src/Hash64
../HashLib/src/Include
../HashLib/src/Interfaces
../HashLib/src/KDF
../HashLib/src/NullDigest
../HashLib/src/Nullable
../HashLib/src/Packages
../HashLib/src/Utils
```

## ✔️ Compatibility
This middleware is compatible with projects developed in:
- [X] Delphi
- [X] Lazarus

## ⚡️ Quickstart Delphi

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

  THorse
    .AddCallback(HorseJWT('MY-PASSWORD'))
    .Get('private',
      procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
      begin
        Res.Send('route private');
      end);

  THorse.Listen(9000);
end.
```

#### Skip routes

```delphi
uses Horse, Horse.JWT;

begin
  THorse.Use(HorseJWT('MY-PASSWORD', THorseJWTConfig.New.SkipRoutes(['public'])));

  THorse.Get('public',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('public route');
    end);

  THorse.Get('private',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('private route');
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
  THorse
    .AddCallback(HorseJWT('MY-PASSWORD', THorseJWTConfig.New.SessionClass(TMyClaims))) // Add custom payload class
    .Get('ping', 
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
  THorse
    .AddCallback(HorseJWT('MY-PASSWORD', THorseJWTConfig.New.SessionClass(TMyClaims))) // Add custom payload class  
    .Get('private', 
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

## ⚡️ Quickstart Lazarus

#### All requests need token authorization.

```delphi
{$MODE DELPHI}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Horse, Horse.JWT, SysUtils;

procedure GetPing(Req: THorseRequest; Res: THorseResponse; Next: TNextProc);
begin
  Res.Send('Pong');
end;

begin
  THorse.Use(HorseJWT('my-private-key'));

  THorse.Get('/ping', GetPing);

  THorse.Listen(9000);
end.
```

#### Some routes require authentication

```delphi
{$MODE DELPHI}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Horse, Horse.JWT, SysUtils;

procedure GetPing(Req: THorseRequest; Res: THorseResponse; Next: TNextProc);
begin
  Res.Send('Pong');
end;

procedure GetPrivate(Req: THorseRequest; Res: THorseResponse; Next: TNextProc);
begin
  Res.Send('route private');
end;

begin
  THorse.Get('/ping', GetPing);
  
  THorse
    .AddCallback(HorseJWT('my-private-key'))
    .Get('private', GetPrivate);

  THorse.Listen(9000);
end.
```

## ⚠️ License
`horse-jwt` is free and open-source middleware licensed under the [MIT License](https://github.com/HashLoad/horse-jwt/blob/master/LICENSE).
