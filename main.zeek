# figure out what stuff is

module APPID;

redef record Conn::Info += { app:string &optional &log; };

# look for this stuff
#   networks that match at all
global nets: set[subnet] = set();
# what the app is
global netinfo: table[subnet] of Val;

type Idx: record {
    ips: subnet;
    };
type Val: record {
    name: string;
    };

# sort out what we can deduce!
event connection_state_remove(c: connection)
    {
    if (c$conn?$app) return;
	
    if ( c?$id && c$conn$id$orig_h in nets)
        {
        c$conn$app = netinfo[c$id$orig_h];
        return;
        }
    if ( c?$id && c$id$resp_h in nets)
	{
      	c$conn$app = netinfo[c$id$resp_h];
        return;
        }

    }

event Input::end_of_data(name: string, source: string)
    {
    # now all data is in the table
    if ( source == "nets.in") print fmt("I have %d networks", |nets|);
    if ( source == "names.in") print fmt("I have %d names", |netinfo|);
    }

event zeek_init()
    {
    Input::add_table([$source="nets.in",
        $idx=Idx, $name="nets", $destination=nets,
        $mode=Input::REREAD]);      

    Input::add_table([$source="names.in",
        $idx=Idx, $val=Val, $name="names", $destination=netinfo,
        $mode=Input::REREAD]);      

    if ( |nets| != |netinfo| )
        {
        print "nets and netinfo entries must match";
        exit(1);
        } 
    }