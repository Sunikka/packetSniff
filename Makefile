

build: 
	gcc -o packet_sniffer packet_sniffer.c -lpcap

run: build
	sudo ./packet_sniffer

clean:
	rm -f packet_sniffer
