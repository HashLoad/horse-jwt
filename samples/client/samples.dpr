program samples;

{$APPTYPE CONSOLE}

uses
  Horse,
  Horse.JWT;

{$R *.res}

var
  App: THorse;

begin
  App := THorse.Create(9000);

  App.Use(HorseJWT('EC2019'));

  App.Get('/ping',
    procedure(Req: THorseRequest; Res: THorseResponse; Next: TProc)
    begin
      Res.Send('pong');
    end);

  App.Start;
end.
