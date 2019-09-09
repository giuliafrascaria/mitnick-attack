#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types>
#include <unistd.h>


//eth level data -> do I need this??
#define KEVIN_MAC "02:00:ac:10:10:02"
#define SERVER_MAC "02:00:ac:10:10:03"
#define XTERMINAL_MAC "02:00:ac:10:10:04"

//ip level data
#define KEVIN_IP "172.16.16.2"
#define SERVER_IP "172.16.16.3"
#define XTERMINAL_IP "172.16.16.4"

//tcp level data
#define PORT 513
#define PAYLOAD_DOS "disable"
#define PAYLOAD_RST "enable"

int craft_tcp_packet();

int main (void)
{
	//initialize libnett stuff
	char e_buff[LIBNET_ERRBUF_SIZE];
	libnet_t * l;

	l = libnet_init(LIBNET_RAW4, "eth0", e_buff);
	if (l == NULL)
	{
		printf("libnet init error\n");
		exit(EXIT_FAILURE);
	}

	//start DOS part
	//ip conversion
	u_long server_ip = libnet_name2addr4(l, SERVER_IP, LIBNET_DONT_RESOLVE);
	u_long kevin_ip = libnet_name2addr4(l, KEVIN_IP, LIBNET_DONT_RESOLVE);

	if (server_ip == -1)
	{
		printf("error in server ip conversion\n");
		exit(EXIT_FAILURE);
	}
	if (kevin_ip == -1)
	{
		printf("error in kevin ip conversion\n");
		exit(EXIT_FAILURE);
	}


	//packet crafting
	int check = craft_tcp_packet();


	//dos the server
	for (int i = 0; i < 10; i++)
	{
		//send packet
		printf("floooood\n");
	}
	//now the server will ignore syn acks, that's exactly what I need because
	
	//I will send spoofed syn
	//The xterminal will send real synack to the server
	//I will respond with spoofed ack cause I know the server seq num
	//will have a trusted connection on the xterminal

	//contact xterminal to figure out next seq #


	//impersonate trusted server


	exit(EXIT_SUCCESS);
}


int craft_tcp_packet()
{
	libnet_ptag_t ptag;
	return 1;
}
