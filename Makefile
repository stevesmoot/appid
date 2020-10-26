all: install rules

install:
	rm -rf nDPI
	git clone https://github.com/ntop/nDPI.git

refresh:
	cd nDPI; git pull
	make rules

rules:
	grep " 0x" nDPI/src/lib/ndpi_content_match.c.inc | grep -v '0x0, 0, 0' > raw.txt
	echo "#fields	ips">nets.in
	echo "#fields	ips	name">names.in
	sed -e 's=^.*{ 0x[0-9A-Za-z]* /. \([^ /]*\).*, *\([0-9][0-9]*\) *,.*=\1/\2=' < raw.txt >> nets.in
	sed -e 's=^.*{ 0x[0-9A-Za-z]* /. \([^ /]*\).*, *\([0-9][0-9]*\) *, NDPI_PROTOCOL_\([A-Za-z0-9_]*\) .*=\1/\2	\3=' < raw.txt >> names.in

run:
	cp main.zeek `mktemp archive/XXXXXX`
	git commit main.zeek
	build/src/zeek -Cr ../try-zeek/manager/static/pcaps/http.pcap  __load__.zeek

qrun:
	build/src/zeek -Cr ../try-zeek/manager/static/pcaps/http.pcap  __load__.zeek

rrun:
	build/src/zeek -Cr ../try-zeek/manager/static/pcaps/http.pcap  me.zeek
