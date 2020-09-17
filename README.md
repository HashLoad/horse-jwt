# horse-jwt
Middleware for JWT in HORSE

Sample Horse Server Validate JWT
```delphi
uses Horse, Horse.JWT;

begin
  THorse.Use(HorseJWT('jwt-secret')); 

  App.Post('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Req.Session<TJSONObject>; //Default Payload is JSON
    end);

  THorse.Listen(9000);
```

Validate JWT and get custom session
```delphi
uses Horse, Horse.JWT;

begin
  THorse.Use(HorseJWT('jwt-secret', TMySession)); 

  THorse.Post('ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Req.Session<TMySession>.MyField;
    end);

  THorse.Listen(9000);
```
