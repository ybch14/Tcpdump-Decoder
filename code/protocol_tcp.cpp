#include "protocol_tcp.h"
TCP_head::TCP_head()
{

}
TCP_head::TCP_head(unsigned char * temp_data)
{
	data=temp_data;
	source_port=(data[0]<<8)+data[1];
	destination_port=(data[2]<<8)+data[3];
}
TCP_head::~TCP_head()
{

}
unsigned int TCP_head::head_length()
{
	//there are four zeros after & so /4 not *4
	return (unsigned int)((data[12]&0xf0)/4);
}
unsigned int TCP_head::sourceport()
{
	return source_port;
}
unsigned int TCP_head::destinationport()
{
	return destination_port;
}
unsigned int TCP_head::seq_number()
{
	return (data[4]<<24)+(data[5]<<16)+(data[6]<<8)+(data[7]);
}
unsigned int TCP_head::ack_number()
{
	return (data[8]<<24)+(data[9]<<16)+(data[10]<<8)+(data[11]);
}
bool TCP_head::isURG()
{
	return (data[13]&0x20)?true:false;
}
bool TCP_head::isACK()
{
	return (data[13]&0x10)?true:false;
}
bool TCP_head::isPSH()
{
	return (data[13]&0x08)?true:false;
}
bool TCP_head::isRST()
{
	return (data[13]&0x04)?true:false;
}
bool TCP_head::isSYN()
{
	return (data[13]&0x02)?true:false;
}
bool TCP_head::isFIN()
{
	return (data[13]&0x01)?true:false;
}
unsigned int TCP_head::window_size()
{
	return (data[14]<<8)+data[15];
}
unsigned char* TCP_head::application_layer_data()
{
	return data+head_length();
}