#include "protocol_ip.h"
IP_head::IP_head()
{

}
IP_head::IP_head(unsigned char *temp_data)
{
	data=temp_data;
	// data[9]=protocol 1-ICMP,2-IGMP,6-TCP,17-UDP
	if(data[9]==1) up_type=ICMP;
	else if(data[9]==2) up_type=IGMP;
	else if(data[9]==6) up_type=TCP;
	else if(data[9]==17) up_type=UDP;
	// data[0]&0xf0={version,0000} version:4-IPv4,6-IPv6
	if((data[0]&0xf0)==0x40)
		version=IPv4;
	else if((data[0]&0xf0)==0x60)
		version=IPv6;
	if(version==IPv4)
	{
		char buffer[16];
		sprintf(buffer,"%d.%d.%d.%d",data[12],data[13],data[14],data[15]);
		src_IP=buffer;
		sprintf(buffer,"%d.%d.%d.%d",data[16],data[17],data[18],data[19]);
		dst_IP=buffer;
	}
}
IP_head::~IP_head()
{

}
IP_version IP_head::ip_version()
{
	return version;
}
unsigned int IP_head::head_length()
{
	if(version==IPv4)
		return 4*(data[0]&0x0f);
}
unsigned int IP_head::total_length()
{
	if(version==IPv4)
		return (unsigned int)(data[2]<<8)+data[3];
}
unsigned int IP_head::identification()
{
	if(version==IPv4)
		return (data[4]<<8)+data[5];
}
bool IP_head::isfragment()
{
	if(version==IPv4)
		return (data[6]&0x20)?true:false;
}
unsigned int IP_head::fragment_offset()
{
	return ((data[6]&0x1f)<<8)+data[7];
}
unsigned int IP_head::live_time()
{
	return data[8];
}
transport_layer_type IP_head::upper_type()
{
	return up_type;
}
unsigned int IP_head::src_addr()
{
	return (data[12]<<24)+(data[13]<<16)+(data[14]<<8)+data[15];
}
unsigned int IP_head::dst_addr()
{
	return (data[16]<<24)+(data[17]<<16)+(data[18]<<8)+data[19];
}
unsigned char* IP_head::transport_layer_data()
{
	return data+head_length();
}