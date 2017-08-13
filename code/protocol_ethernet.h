#ifndef ETHERNET_INCLUDED
#define ETHERNET_INCLUDED
#include <string>
#include <cstdio>
enum network_layer_type{IP,ARP};
class Ethernet_head
{
private:
	std::string src_MAC;
	std::string dst_MAC;
	// the protocol type of network layer
	network_layer_type up_type;
	unsigned char* data;
public:
	Ethernet_head();
	Ethernet_head(unsigned char *temp_data);
	~Ethernet_head();
	// get the frame length
	unsigned int frame_length();
	// get the type of the network layer
	network_layer_type upper_type();
	// get the dst MAC address (int value) of this frame
	unsigned long long dst_addr();
	// get the src MAC address (int value) of this frame
	unsigned long long src_addr();
	// get the length of data range
	unsigned int data_length();
	// get the data of the network layer
	unsigned char* network_layer_data();
};
#endif