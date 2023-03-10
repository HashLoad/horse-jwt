program samples_client;

{$APPTYPE CONSOLE}

uses
  Horse,
  Horse.JWT;

{$R *.res}

begin
  THorse.Use(HorseJWT('my-private-key'));

  THorse.Get('/ping',
    procedure(Req: THorseRequest; Res: THorseResponse)
    begin
      Res.Send('pong');
    end);

  THorse.Listen(9000);
end.
