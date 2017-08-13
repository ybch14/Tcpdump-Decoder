#ifndef UDP_INCLUDED
#define UDP_INCLUDED
class UDP_head
{
private:
	unsigned int source_port;
	unsigned int destination_port;
	unsigned char* data;
public:
	UDP_head();
	UDP_head(unsigned char* temp_data);
	~UDP_head();
	unsigned int sourceport();
	unsigned int destinationport();
	unsigned int head_length();
	unsigned int length();
	unsigned char* app_data();
};
#endif