# figure out what stuff is

module APPID;

redef record Conn::Info += { app:string &optional &log; };

# sort out what we can deduce!
event connection_state_remove(c: connection)
      {
      c$conn$app = "Hello World";
      }

event zeek_init()
      {
      }