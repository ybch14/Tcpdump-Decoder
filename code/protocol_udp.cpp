#include "protocol_udp.h"
UDP_head::UDP_head()
{

}
UDP_head::UDP_head(unsigned char *temp_data)
{
	data=temp_data;
	source_port=(data[0]<<8)+data[1];
	destination_port=(data[2]<<8)+data[3];
}
UDP_head::~UDP_head()
{

}

unsigned int UDP_head::sourceport()
{
	return source_port;
}
unsigned int UDP_head::destinationport()
{
	return destination_port;
}
unsigned int UDP_head::head_length()
{
	return 8;
}
unsigned int UDP_head::length()
{
	return (data[4]<<8)+data[5];
}
unsigned char* UDP_head::app_data()
{
	return data+head_length();
}