program Console;

{$MODE DELPHI}{$H+}

uses
  {$IFDEF UNIX}{$IFDEF UseCThreads}
  cthreads,
  {$ENDIF}{$ENDIF}
  Horse, Horse.JWT, SysUtils;

procedure GetPing(Req: THorseRequest; Res: THorseResponse);
begin
  Res.Send('Pong');
end;

begin
  THorse.Use(HorseJWT('my-private-key'));

  THorse.Get('/ping', GetPing);

  THorse.Listen(9000);
end.
