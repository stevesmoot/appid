# figure out what stuff is

module APPID;

@load domain-tld/__load__.bro

redef record Conn::Info += { app:string &optional &log; };

type Idx: record {
    ips: subnet;
    };
type Val: record {
    name: string;
    };

# look for this stuff
#   networks that match at all
global nets: set[subnet] = set();
# what the app is
global netinfo: table[subnet] of Val;

const serviceMap: table[string] of string = [["pop3"] = "email", ["imap"]= "email", ["bittorrent"] = "file-transfer",
    ["gnutella"] = "file-transfer", ["ftp"] = "file-transfer", ["arp"]="infra", ["dhcp"]="infra", ["dnp3"]="infra",
    ["dns"] = "infra", ["irc"] = "chat", ["modbus"] = "infra", ["mqtt"] = "infra", ["ntp"]="infra", ["radius"]="infra",
    ["sip"]="chat", ["smtp"]="email", ["syslog"]="infra", ["vxlan"]="infra", ["xmpp"]="inra"];

function my_effective_domain(s:string): string
    {
    local ed=DomainTLD::effective_domain(s);
    local tld=DomainTLD::effective_tld(s);
    return ed[0:|ed|-|tld|-1];
    }

# sort out what we can deduce!
event connection_state_remove(c: connection)
    {
    if (c$conn?$app) return;
	
    if ( c?$id && c$conn$id$orig_h in nets)
        {
        c$conn$app = netinfo[c$id$orig_h]$name;
        return;
        }
    if ( c?$id && c$id$resp_h in nets)
	{
      	c$conn$app = netinfo[c$id$resp_h]$name;
        return;
        }
    if ( c?$http && c$http?$host )
	{
      	c$conn$app = my_effective_domain(c$http$host);
        return;
        }
    if ( c?$ssl && c$ssl?$server_name )
	{
      	c$conn$app = my_effective_domain(c$ssl$server_name);
        return;
        }
    if ( c$conn?$service && c$conn$service in serviceMap )
	{
	c$conn$app = serviceMap[c$conn$service];
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
    }