# figure out what stuff is

module APPID;

redef record Conn::Info += { app:string &optional &log; };
type Netinfo: record {net:addr; app: string; };

# look for this stuff
#   networks that match at all
global nets: set[subnet] = set(192.168.211.1/32);
# what the app is
global netinfo: table[subnet] of string = { "192.168.211.1/32" = "Hello World"};

# sort out what we can deduce!
event connection_state_remove(c: connection)
      {
      c$conn$app = "Hello World";
      }

event zeek_init()
      {
      }