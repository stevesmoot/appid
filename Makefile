all: install rules

install:
	rm -rf nDPI
	git clone https://github.com/ntop/nDPI.git

refresh:
	cd nDPI; git pull
	make rules

rules:
	grep 0x nDPI/src/lib/ndpi_content_match.c.inc > raw.txt
