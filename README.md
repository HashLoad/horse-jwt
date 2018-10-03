# horse-jwt
Middleware for JWT in HORSE

Sample Horse Server Validate JWT
```delphi
uses
  Horse, Horse.JWT;

var
  App: THorse;

begin
  App := THorse.Create(9000);

  App.Use(HorseJWT('jwt-secret')); 

  App.Post('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Req.Session<TJSONObject>; //Default Payload is JSON
    end);

  App.Start;
```

Validate JWT and get custom session
```delphi
uses
  Horse, Horse.JWT;

var
  App: THorse;

begin
  App := THorse.Create(9000);

  App.Use(HorseJWT('jwt-secret', TMySession)); 

  App.Post('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Req.Session<TMySession>.MyField;
    end);

  App.Start;
```