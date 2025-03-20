#include "pcap.h"
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include "types.h"


#define SNAP_LEN 1518

// for printing Mac Addresses
void formatMAC(const uint8_t addr[6], char* buffer) {
	snprintf(buffer, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
	  addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);	
}

void formatIPv4(const uint32_t addr, char* buffer) {
	snprintf(buffer, 16, "%u.%u.%u.%u",
	  (addr >> 24) & 0xFF,
	  (addr >> 16) & 0xFF,
	  (addr >> 8) & 0xFF,
	  addr & 0xFF
	  );	
}

void formatIPv6(const uint8_t addr[16], char* buffer) {
	snprintf(buffer, 40, "%x:%x:%x:%x:%x:%x:%x:%x",
	  (addr[0] << 8 | addr[1]),
	  (addr[2] << 8 | addr[3]),
	  (addr[4] << 8 | addr[5]),
	  (addr[6] << 8 | addr[7]),
	  (addr[8] << 8 | addr[9]),
	  (addr[10] << 8 | addr[11]),
	  (addr[12] << 8 | addr[13]),
	  (addr[14] << 8 | addr[15])
	  );
}; 



uint16_t parse_ethernet_header(const u_char *packet) {
	struct ethernet_header *eth = (struct ethernet_header *)packet;
	
	// Buffers for formatted MAC's
	char destMAC[18];
	char srcMAC[18];

	// Format MAC's
	formatMAC(eth->dest, destMAC);
	formatMAC(eth->src, srcMAC);
	printf("Source: %s \n", srcMAC);
	printf("Destination: %s \n", destMAC);
	return eth->ethertype;
}

void parse_ipv_header(const u_char *packet, uint16_t ethertype) {
	if(ntohs(ethertype) == 0x0800) { // if ethertype is IPv4
		struct  ipv4_header *iph = (struct ipv4_header *)packet + sizeof(struct ethernet_header);
		char destIP[16];			
		char srcIP[16];
		formatIPv4(iph->dest_address, destIP);
		formatIPv4(iph->src_address, srcIP);
		printf("[IPv4]: %s --> %s ", srcIP, destIP);

	} else if (ntohs(ethertype) == 0x86DD) { // if ethertype is IPv6
		struct ipv6_header *iph = (struct ipv6_header *)packet;	
		char destIP[40];	
		char srcIP[40];	
		formatIPv6(iph->dest_address, destIP);
		formatIPv6(iph->src_address, srcIP);
		printf("[IPv6]: %s --> %s ", srcIP, destIP);
	}else {
		printf("Unidentified IP version: %04x\n", ntohs(ethertype));

	}
}
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("packet captured, length: %d \n", header->len);

	uint16_t ethertype = parse_ethernet_header(packet);
	if (ntohs(ethertype) < 0x0600) {
		printf("IEEE 802.3 frame detected. Length: %d bytes\n", ntohs(ethertype));
	} else {
		parse_ipv_header(packet, ethertype);
	}  
	printf("\n\n");
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

	printf("Capturing on device: %s \n\n", dev->name);

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





