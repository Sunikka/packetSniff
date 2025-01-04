#include "pcap.h"
#include <pcap/pcap.h>
#include <stdio.h>

#define SNAP_LEN 1518

void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("packet captured, length: %d \n", header->len);
	printf("data: \n");
	for (int i = 0; i < header->len; i++) {
		printf("%02X", packet[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n");
}

// for printing Mac Addresses
void formatMAC(const uint8_t addr[6], char* buffer) {
	snprintf(buffer, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);	
}

void parse_ethernet_header(const u_char *packet) {
	struct ethernet_header{
		uint8_t dest[6]; // Destination MAC Address
		uint8_t src[6]; // Source MAC Address
		uint16_t ethertype;
	};
	
	struct ethernet_header *eth = (struct ethernet_header *)packet;
	
	// Buffers for formatted MAC's
	char destMAC[18];
	char srcMAC[18];

	// Format MAC's
	formatMAC(eth->dest, destMAC);
	formatMAC(eth->src, srcMAC);
	printf("Source: %s \n", srcMAC);
	printf("Destination: %s \n", destMAC);
}



int main() {
	char errBuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *dev, *allDevs; // Network device(s) to capture from

	if (pcap_findalldevs(&allDevs, errBuf) == -1) {
		fprintf(stderr, "Error finding devices: %s\n",errBuf);
		return 1;
	}

	dev = allDevs;
	if (dev == NULL) {
		fprintf(stderr,  "Error finding devices: %s\n", errBuf);
		return 1;
	}

	printf("Capturing on device: %s \n", dev->name);

	// Open the first device for capture
	pcap_t *handle = pcap_open_live(dev->name, SNAP_LEN, 1, 1000, errBuf);	
	if (handle == NULL ) {
		fprintf(stderr, "Couldn't open device: %s \n", errBuf);
		pcap_freealldevs(allDevs);
		return 1;
	}

	// Capture packets
	if (pcap_loop(handle, 10, packet_handler, NULL) < 0) {
		fprintf(stderr, "Capturing packets failed: %s \n", errBuf);
		pcap_close(handle);
		return 1;
	}


	pcap_freealldevs(allDevs);


	pcap_close(handle);
	printf("Capture complete. \n");
	return 0;
}





