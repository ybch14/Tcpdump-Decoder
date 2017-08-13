#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdio>
#include <map>
#include <algorithm>
#include <vector>
#include "protocol_ethernet.h"
#include "protocol_ip.h"
#include "protocol_tcp.h"
#include "protocol_udp.h"
using namespace std;
// turn the keyboard input ip address to unsigned int
unsigned int get_ip_address(unsigned char addr[])
{
	int count=0;int part=1;
	int temp[4]={0,0,0,0};
	int result=0;
	while(addr[count]!='\0')
	{
		if(addr[count]>='0'&&addr[count]<='9')
			temp[part-1]=temp[part-1]*10+addr[count]-48;
		else if(addr[count]=='.')
		{
			if(temp[part-1]>255)
				return 0;
			part++;
		}
		else
			return 0;
		count++;
	}
	if(part<4)
		return 0;
	return (temp[0]<<24)+(temp[1]<<16)+(temp[2]<<8)+temp[3];
}
bool Compare(const pair<int,int> p1,const pair<int,int> p2)
{
	return p1.second>p2.second;
}
int main()
{
	//data initialize
	unsigned char temp[16];
	unsigned char *buffer=new unsigned char[2000];
	Ethernet_head eth_head;IP_head ip_head;TCP_head tcp_head;UDP_head udp_head;
	char mode[4];bool dir;fstream f1;
	// get the local ip address
	cout<<"please input the local ip address: "<<endl;
	cin>>temp;
	unsigned int local_ip=get_ip_address(temp);
	// get the direction of local ip, in or out
	// input-dir false; output-dir true
	// in-local ip==dst ip
	// out-local ip==src ip
	cout<<"please input the mode, in or out :"<<endl;
	cin>>mode;
	if(strcmp(mode,"in")==0 || strcmp(mode,"IN")==0)
		dir=false;
	else if(strcmp(mode,"out")==0 || strcmp(mode,"OUT")==0)
		dir=true;
	else 
		return 0;
	// prepare require data

	int count_ip=0;int length_ip=0;
	int count_tcp=0;int count_udp=0;int count_icmp=0; int count_igmp=0;
	int length_tcp=0;int length_udp=0;int length_icmp=0;int length_igmp=0;

	unsigned int last_id=0;bool last_isfragment=false;
	int count_fragment=0;int count_ip_fraged=0;int count_tcp_fraged=0;int count_udp_fraged=0;
	
	int step=20;int length_tab=0;
	int count_ip_length[21]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int count_tcp_length[21]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
	int count_udp_length[21]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	// map: key is port number and value is count
	map<int,int> tcp_src_port;map<int,int> tcp_dst_port;
	map<int,int> udp_src_port;map<int,int> udp_dst_port;

	int urg_count=0;int ack_count=0;int psh_count=0;
	int rst_count=0;int syn_count=0;int fin_count=0;

	// open the file
	f1.open("result.txt",ios_base::binary|ios_base::in);
	f1.seekg(0,ios_base::end);
	int total_data_length=(int)f1.tellg();
	f1.seekg(32,ios_base::beg);
	int current_pos=32;
	f1.read((char*)buffer,2000);
	while(current_pos<total_data_length)
	{
		eth_head=Ethernet_head(buffer);
		if(eth_head.upper_type()==IP)
		{
			ip_head=IP_head(eth_head.network_layer_data());
			if(ip_head.ip_version()==IPv4 && dir?(ip_head.src_addr()==local_ip):(ip_head.dst_addr()==local_ip))
			{
				// get the number of ip groups and four protocol numbers(number & length)
				count_ip++;
				length_ip+=ip_head.total_length();
 				if(ip_head.upper_type()==TCP)
				{
					count_tcp++;
					length_tcp+=ip_head.total_length();
				}
				else if (ip_head.upper_type()==UDP)
				{
					count_udp++;
					length_udp+=ip_head.total_length();
				}
				else if (ip_head.upper_type()==ICMP)
				{
					count_icmp++;
					length_icmp+=ip_head.total_length();
				}
				else if (ip_head.upper_type()==IGMP)
				{
					count_igmp++;
					length_igmp+=ip_head.total_length();
				}
				// get the fragment information
				if(ip_head.isfragment())
				{
					// a new fragment
					count_fragment++;
					if(!last_isfragment)
					{
						// the last group is not a fragment, means this group belongs to a new id
						count_ip_fraged++;
						if(ip_head.upper_type()==TCP)
							count_tcp_fraged++;
						else if (ip_head.upper_type()==UDP)
							count_udp_fraged++;
						last_isfragment=true;
						last_id=ip_head.identification();
					}
				}
				else if(last_isfragment && last_id==ip_head.identification())
				{
					// the last group is fragment and have the same id, means this group is the last group of a long data
					count_fragment++;
					last_isfragment=false;
				}
				// get length distribution, step=20, 21 groups
				length_tab=int(ip_head.total_length()/20);
				length_tab=(length_tab>20)?20:length_tab;
				count_ip_length[length_tab]++;
				if(ip_head.upper_type()==TCP)
					count_tcp_length[length_tab]++;
				else if (ip_head.upper_type()==UDP)
					count_udp_length[length_tab]++;
				// get traffic port distribution
				if(ip_head.upper_type()==TCP)
				{
					tcp_head=TCP_head(ip_head.transport_layer_data());
					// if cannot find, add the port into the map
					if(tcp_src_port.find(tcp_head.sourceport())==tcp_src_port.end())
						tcp_src_port[tcp_head.sourceport()]=1;
					// if find, add the count number
					else 
						tcp_src_port[tcp_head.sourceport()]++;
					// if cannot find, add the port into the map
					if(tcp_dst_port.find(tcp_head.destinationport())==tcp_dst_port.end())
						tcp_dst_port[tcp_head.destinationport()]=1;
					// if find, add the count number
					else 
						tcp_dst_port[tcp_head.destinationport()]++;
					if(tcp_head.isURG())
						urg_count++;
					if(tcp_head.isACK())
						ack_count++;
					if(tcp_head.isPSH())
						psh_count++;
					if(tcp_head.isRST())
						rst_count++;
					if(tcp_head.isSYN())
						syn_count++;
					if(tcp_head.isFIN())
						fin_count++;
				}
				else if (ip_head.upper_type()==UDP)
				{
					udp_head=UDP_head(ip_head.transport_layer_data());
					// if cannot find, add the port into the map
					if(udp_src_port.find(udp_head.sourceport())==udp_src_port.end())
						udp_src_port[udp_head.sourceport()]=1;
					// if find, add the count number
					else 
						udp_src_port[udp_head.sourceport()]++;
					// if cannot find, add the port into the map
					if(udp_dst_port.find(udp_head.destinationport())==udp_dst_port.end())
						udp_dst_port[udp_head.destinationport()]=1;
					// if find, add the count number
					else 
						udp_dst_port[udp_head.destinationport()]++;
				}
			}
		}
		//cout<<"ԴMAC��"<<eth_head.src.str<<" Ŀ��MAC��"<<eth_head.dst.str<<endl;
		//cout<<"ԴIP ��"<<ip_head.src.str<<" Ŀ��IP ��"<<ip_head.dst.str<<endl;
		//if(ip_head.upper_type()==TCP)
		//	cout<<"TCPԴ�˿ڣ�"<<tcp_head.sourceport()<<" TCPĿ��˿ڣ�"<<tcp_head.destinationport()<<endl;
		//else if (ip_head.upper_type()==UDP)
		//	cout<<"UDPԴ�˿ڣ�"<<udp_head.sourceport()<<" UDPĿ��˿ڣ�"<<udp_head.destinationport()<<endl;
		//cout<<"=============================================="<<endl;
		if(f1.eof())
		f1.clear();
		f1.seekg(current_pos+eth_head.frame_length()+16);
		current_pos+=eth_head.frame_length()+16;
		f1.read((char*)buffer,2000);
	}
	// put the map value into vector
	vector <pair <int,int>> tcp_src_port_count(tcp_src_port.begin(),tcp_src_port.end());
	vector <pair <int,int>> tcp_dst_port_count(tcp_dst_port.begin(),tcp_dst_port.end());
	vector <pair <int,int>> udp_src_port_count(udp_src_port.begin(),udp_src_port.end());
	vector <pair <int,int>> udp_dst_port_count(udp_dst_port.begin(),udp_dst_port.end());
	// sort and find the top 10 ports
	std::sort(tcp_src_port_count.begin(),tcp_src_port_count.end(),Compare);
	std::sort(tcp_dst_port_count.begin(),tcp_dst_port_count.end(),Compare);
	std::sort(udp_src_port_count.begin(),udp_src_port_count.end(),Compare);
	std::sort(udp_dst_port_count.begin(),udp_dst_port_count.end(),Compare);
	// get the top 10 ports distribution, key is port number, value is distribution vector
	map <int,vector <int>> tcp_src_port_length_count;
	map <int,vector <int>> tcp_dst_port_length_count;
	map <int,vector <int>> udp_src_port_length_count;
	map <int,vector <int>> udp_dst_port_length_count;
	// step=100, 11 groups; initialize the vectors
	for (int i=0;i<10 && i<(int)tcp_src_port_count.size();i++)
		tcp_src_port_length_count[tcp_src_port_count[i].first].assign(21,0);
	for (int i=0;i<10 && i<(int)tcp_dst_port_count.size();i++)
		tcp_dst_port_length_count[tcp_dst_port_count[i].first].assign(21,0);
	for (int i=0;i<10 && i<(int)udp_src_port_count.size();i++)
		udp_src_port_length_count[udp_src_port_count[i].first].assign(21,0);
	for (int i=0;i<10 && i<(int)udp_dst_port_count.size();i++)
		udp_dst_port_length_count[udp_dst_port_count[i].first].assign(21,0);
	f1.clear();
	f1.seekg(32,ios_base::beg);
	current_pos=32;
	f1.read((char*)buffer,2000);
	while(current_pos<total_data_length)
	{
		eth_head=Ethernet_head(buffer);
		if(eth_head.upper_type()==IP)
		{
			ip_head=IP_head(eth_head.network_layer_data());
			if(ip_head.ip_version()==IPv4)
			{
				if(ip_head.upper_type()==TCP)
				{
					tcp_head=TCP_head(ip_head.transport_layer_data());
					for(int i=0;i<10 && i<(int)tcp_src_port_count.size();i++)
					{
						if(tcp_src_port_count[i].first==tcp_head.sourceport())
						{
							length_tab=int(ip_head.total_length()/20);
							length_tab=(length_tab>20)?20:length_tab;
							tcp_src_port_length_count[tcp_head.sourceport()][length_tab]++;
						}
					}
					for(int i=0;i<10 && i<(int)tcp_dst_port_count.size();i++)
					{
						if(tcp_dst_port_count[i].first==tcp_head.destinationport())
						{
							length_tab=int(ip_head.total_length()/20);
							length_tab=(length_tab>20)?20:length_tab;
							tcp_dst_port_length_count[tcp_head.destinationport()][length_tab]++;
						}
					}
				}
				else if(ip_head.upper_type()==UDP)
				{
					udp_head=UDP_head(ip_head.transport_layer_data());
					for(int i=0;i<10 && i<(int)udp_src_port_count.size();i++)
					{
						if(udp_src_port_count[i].first==udp_head.sourceport())
						{
							length_tab=int(ip_head.total_length()/20);
							length_tab=(length_tab>20)?20:length_tab;
							udp_src_port_length_count[udp_head.sourceport()][length_tab]++;
						}
					}
					for(int i=0;i<10 && i<(int)udp_dst_port_count.size();i++)
					{
						if(udp_dst_port_count[i].first==udp_head.destinationport())
						{
							length_tab=int(ip_head.total_length()/20);
							length_tab=(length_tab>20)?20:length_tab;
							udp_dst_port_length_count[udp_head.destinationport()][length_tab]++;
						}
					}
				}
			}
		}
		if(f1.eof())
			f1.clear();
		f1.seekg(current_pos+eth_head.frame_length()+16,ios_base::beg);
		current_pos+=eth_head.frame_length()+16;
		f1.read((char*)buffer,2000);
	}
	// output the results
	cout<<"Mission Complete!"<<endl;
	cout<<(dir?"�������":"���뷽��")<<endl;
	cout<<"��һ�ʣ�"<<endl;
	cout<<"IP�����ܸ�����"<<count_ip<<"��TCP���������"<<count_tcp<<"��UDP���������"<<count_udp<<"��ICMP���������"<<count_icmp<<"��IGMP���������"<<count_igmp<<endl;
	cout<<"IP�����ܳ��ȣ�"<<length_ip<<"��TCP���鳤�ȣ�"<<length_tcp<<"��UDP���鳤�ȣ�"<<length_udp<<"��ICMP���鳤�ȣ�"<<length_icmp<<"��IGMP���鳤�ȣ�"<<length_igmp<<endl;
	cout<<"============================================================================================="<<endl;
	cout<<"�ڶ��ʣ�"<<endl;
	cout<<"��Ƭ�ε�IP���������"<<count_fragment<<"�����ֶε�IP���ݱ�������"<<count_ip_fraged<<"�����ֶε��غ�TCP��IP���ݱ�������"<<count_tcp_fraged<<"�����ֶε��غ�UDP��IP���ݱ�������"<<count_udp_fraged<<endl;
	cout<<"============================================================================================="<<endl;
	cout<<"�����ʣ�"<<endl;
	cout<<"IP���ݱ����ȵķֲ����Ϊ��"<<endl;
	cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
	for(int i=0;i<7;i++)
		cout<<count_ip_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
	for(int i=7;i<14;i++)
		cout<<count_ip_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
	for(int i=14;i<21;i++)
		cout<<count_ip_length[i]<<'\t'<<'\t';
	cout<<endl;

	cout<<"�غ�ΪTCP��IP���ݱ����ȵķֲ����Ϊ��"<<endl;
	cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
	for(int i=0;i<7;i++)
		cout<<count_tcp_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
	for(int i=7;i<14;i++)
		cout<<count_tcp_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
	for(int i=14;i<21;i++)
		cout<<count_tcp_length[i]<<'\t'<<'\t';
	cout<<endl;

	cout<<"�غ�ΪUDP��IP���ݱ����ȵķֲ����Ϊ��"<<endl;
	cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
	for(int i=0;i<7;i++)
		cout<<count_udp_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
	for(int i=7;i<14;i++)
		cout<<count_udp_length[i]<<'\t'<<'\t';
	cout<<endl;
	cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
	for(int i=14;i<21;i++)
		cout<<count_udp_length[i]<<'\t'<<'\t';
	cout<<endl;

	cout<<"============================================================================================="<<endl;
	cout<<"�����ʣ�"<<endl;
	cout<<"TCPԴ�˿���ǰ10�Ķ˿ںźͶ�Ӧ��Ŀ��"<<endl;
	for(int i=0;i<10;i++)
		cout<<tcp_src_port_count[i].first<<"\t";
	cout<<endl;
	for(int i=0;i<10;i++)
		cout<<tcp_src_port_count[i].second<<"\t";
	cout<<endl<<endl;
	cout<<"TCPĿ��˿���ǰ10�Ķ˿ںźͶ�Ӧ��Ŀ��"<<endl;
	for(int i=0;i<10;i++)
		cout<<tcp_dst_port_count[i].first<<"\t";
	cout<<endl;
	for(int i=0;i<10;i++)
		cout<<tcp_dst_port_count[i].second<<"\t";
	cout<<endl<<endl;
	cout<<"UDPԴ�˿���ǰ10�Ķ˿ںźͶ�Ӧ��Ŀ��"<<endl;
	for(int i=0;i<10;i++)
		cout<<udp_src_port_count[i].first<<"\t";
	cout<<endl;
	for(int i=0;i<10;i++)
		cout<<udp_src_port_count[i].second<<"\t";
	cout<<endl<<endl;
	cout<<"UDPĿ��˿���ǰ10�Ķ˿ںźͶ�Ӧ��Ŀ��"<<endl;
	for(int i=0;i<10;i++)
		cout<<udp_dst_port_count[i].first<<"\t";
	cout<<endl;
	for(int i=0;i<10;i++)
		cout<<udp_dst_port_count[i].second<<"\t";
	cout<<endl<<endl;

	cout<<"TCPԴ�˿���ǰ10�����ݱ����ȷֲ������"<<endl;
	for(int i=0;i<10 && i<(int)tcp_src_port_count.size();i++)
	{
		cout<<"�˿ںţ�"<<tcp_src_port_count[i].first<<endl;
		cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
		for(int j=0;j<7;j++)
			cout<<tcp_src_port_length_count[tcp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
		for(int j=7;j<14;j++)
			cout<<tcp_src_port_length_count[tcp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
		for(int j=14;j<21;j++)
			cout<<tcp_src_port_length_count[tcp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
	}
	cout<<endl<<"TCPĿ��˿���ǰ10�����ݱ����ȷֲ������"<<endl;
	for(int i=0;i<10 && i<(int)tcp_dst_port_count.size();i++)
	{
		cout<<"�˿ںţ�"<<tcp_dst_port_count[i].first<<endl;
		cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
		for(int j=0;j<7;j++)
			cout<<tcp_dst_port_length_count[tcp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
		for(int j=7;j<14;j++)
			cout<<tcp_dst_port_length_count[tcp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
		for(int j=14;j<21;j++)
			cout<<tcp_dst_port_length_count[tcp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
	}
	cout<<endl<<"UDPԴ�˿���ǰ10�����ݱ����ȷֲ������"<<endl;
	for(int i=0;i<10 && i<(int)udp_src_port_count.size();i++)
	{
		cout<<"�˿ںţ�"<<udp_src_port_count[i].first<<endl;
		cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
		for(int j=0;j<7;j++)
			cout<<udp_src_port_length_count[udp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
		for(int j=7;j<14;j++)
			cout<<udp_src_port_length_count[udp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
		for(int j=14;j<21;j++)
			cout<<udp_src_port_length_count[udp_src_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
	}
	cout<<endl<<"UDPĿ��˿���ǰ10�����ݱ����ȷֲ������"<<endl;
	for(int i=0;i<10 && i<(int)udp_dst_port_count.size();i++)
	{
		cout<<"�˿ںţ�"<<udp_dst_port_count[i].first<<endl;
		cout<<"0��20\t\t20��40\t\t40��60\t\t60��80\t\t80��100\t\t100��120\t120��140"<<endl;
		for(int j=0;j<7;j++)
			cout<<udp_dst_port_length_count[udp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"140-160\t\t160-180\t\t180-200\t\t200-220\t\t220-240\t\t240-260\t\t260-280"<<endl;
		for(int j=7;j<14;j++)
			cout<<udp_dst_port_length_count[udp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
		cout<<"280-300\t\t300-320\t\t320-340\t\t340-360\t\t360-380\t\t380-400\t\t400-all"<<endl;
		for(int j=14;j<21;j++)
			cout<<udp_dst_port_length_count[udp_dst_port_count[i].first][j]<<'\t'<<'\t';
		cout<<endl;
	}
	cout<<"============================================================================================="<<endl;
	cout<<"�����ʣ�"<<endl;
	cout<<"�غ�ΪTCP��IP���ݱ�������"<<count_tcp<<endl;
	cout<<"URGΪ1�����ݱ�������"<<urg_count<<endl;
	cout<<"ACKΪ1�����ݱ�������"<<ack_count<<endl;
	cout<<"PSHΪ1�����ݱ�������"<<psh_count<<endl;
	cout<<"RSTΪ1�����ݱ�������"<<rst_count<<endl;
	cout<<"SYNΪ1�����ݱ�������"<<syn_count<<endl;
	cout<<"FINΪ1�����ݱ�������"<<fin_count<<endl;
	return 0;
}
