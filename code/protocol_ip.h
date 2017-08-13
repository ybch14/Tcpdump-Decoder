#ifndef IP_INCLUDED
#define IP_INCLUDED
#include <string>
#include <cstdio>
enum IP_version{IPv4,IPv6};
enum transport_layer_type{TCP,UDP,ICMP,IGMP};
class IP_head
{
private:
	transport_layer_type up_type;
	IP_version version;
	std::string src_IP;
	std::string dst_IP;
	unsigned char* data;
public:
	IP_head();
	IP_head(unsigned char *temp_data);
	~IP_head();
	// get the IP version
	IP_version ip_version();
	// get the head length from IHL
	unsigned int head_length();
	// get the total length from "total length"
	unsigned int total_length();
	// get the ID from "Identification"
 	unsigned int identification();
	// get the information from MF
	bool isfragment();
	// get the fragment offset from "Fragment Offset" region
	unsigned int fragment_offset();
	// get the live time from "Time to live" region
	unsigned int live_time();
	// get the transport protocol type from Protocol
	transport_layer_type upper_type();
	// get the src IP address (int value) of this group
	unsigned int src_addr();
	// get the dst IP address (int value) of this group
	unsigned int dst_addr();
	unsigned char* transport_layer_data();
};
#endif