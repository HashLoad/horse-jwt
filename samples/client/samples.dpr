program samples;

{$APPTYPE CONSOLE}

uses
  Horse,
  Horse.JWT;

{$R *.res}

begin
  THorse.Use(HorseJWT('my-private-key'));

  THorse.Get('/ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('pong');
    end);

  THorse.Listen(9000);
end.
