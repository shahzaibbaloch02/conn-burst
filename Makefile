all:

install:
	@echo "Installing conn-burst Zeek package"

clean:
	@echo "Cleaning conn-burst Zeek package"

test:
	@echo "Testing conn-burst Zeek package"
	zeek -r test.pcap scripts/main.zeek

.PHONY: all install clean test