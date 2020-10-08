# figure out what stuff is

module APPID;

redef record Conn::Info += { app:string &optional &log; };
type Netinfo: record {net:addr; app: string; };

# look for this stuff
#   networks that match at all
global nets: set[subnet] = set(192.168.211.1/32);
# what the app is
global netinfo: table[subnet] of string = { [192.168.211.1/32] = "Hello World", [1.1.1.1]="die"};

# sort out what we can deduce!
event connection_state_remove(c: connection)
      {
      if (c$conn?$app) return;
      
      if ( c?$id && c$conn$id$orig_h in nets) {
      	 c$conn$app = netinfo[c$id$orig_h];
      } else if ( c?$id && c$id$resp_h in nets) {
      	 c$conn$app = netinfo[c$id$resp_h];
      }
      }

event zeek_init()
      {
      if ( |nets| != |netinfo| )
         {
         print "nets and netinfo entries must match";
         exit(1);
         } 
      }