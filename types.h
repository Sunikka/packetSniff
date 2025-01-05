#ifndef TYPES_H
#define TYPES_H

#include <stdint.h>

struct ethernet_header{
	uint8_t dest[6]; // Destination MAC Address
	uint8_t src[6]; // Source MAC Address
	uint16_t ethertype;
};
	

struct ipv4_header {
	uint8_t version_ihl; // version and length
	uint8_t dscp_ecn; // types of service + Explicit congestion notification
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragment_offset;
	uint8_t ttl; // Time to live
	uint8_t protocol;
	uint16_t checksum;
	uint32_t src_address;
	uint32_t dest_address;
	uint32_t options;
};

struct ipv6_header {
	uint32_t v_tc_flow_label; // version (4 bits), Traffic class (8 bits) and flow label (20 bits)
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t src_address[16];
	uint8_t dest_address[16];
};

#endif // !TYPES_H

