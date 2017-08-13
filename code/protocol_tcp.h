#ifndef TCP_INCLUDED
#define TCP_INCLUDED
class TCP_head
{
private:
	unsigned int source_port;
	unsigned int destination_port;
	unsigned char* data;
public:
	TCP_head();
	TCP_head(unsigned char* temp_data);
	~TCP_head();
	// get the head length from TCP head length
	unsigned int head_length();
	// get the source port number
	unsigned int sourceport();	
	// get the destination port number
	unsigned int destinationport();
	// get the SEQ from Sequence Number
	unsigned int seq_number();
	// get the ACK from Acknowledge Number
	unsigned int ack_number();
	// get the six bool from TCP head
	bool isURG();
	bool isACK();
	bool isPSH();
	bool isRST();
	bool isSYN();
	bool isFIN();
	// get the window size
	unsigned int window_size();
	unsigned char* application_layer_data();	
};
#endif