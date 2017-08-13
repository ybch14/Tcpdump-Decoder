#include "protocol_ethernet.h"
Ethernet_head::Ethernet_head()
{

}
Ethernet_head::Ethernet_head(unsigned char* temp_data)
{
	data=temp_data;
	char buffer[18];
	sprintf(buffer,"%02X:%02X:%02X:%02X:%02X:%02X",data[8],data[9],data[10],data[11],data[12],data[13]);
	dst_MAC=buffer;
	sprintf(buffer,"%02X:%02X:%02X:%02X:%02X:%02X",data[14],data[15],data[16],data[17],data[18],data[19]);
	src_MAC=buffer;
	// 0x0800 is IP and 0x0806 is ARP
	if(data[20]==8 && data[21]==0)
		up_type=IP;
	else if(data[20]==8 && data[21]==6)
		up_type=ARP;
}
Ethernet_head::~Ethernet_head()
{

}
unsigned int Ethernet_head::frame_length()
{
	return data[0]+(data[1]<<8);
}
unsigned char* Ethernet_head::network_layer_data()
{
	return data+22;
}
unsigned long long Ethernet_head::dst_addr()
{
	return (((data[8]<<16)+(data[9]<<8)+(data[10]))<<24)+(data[11]<<16)+(data[12]<<8)+(data[13]);
}
unsigned long long Ethernet_head::src_addr()
{
	return (((data[14]<<16)+(data[15]<<8)+(data[16]))<<24)+(data[17]<<16)+(data[18]<<8)+(data[19]);
}
network_layer_type Ethernet_head::upper_type()
{
	return up_type;
}