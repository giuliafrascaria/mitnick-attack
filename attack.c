#include <libnet.h>
#include <stdio.h>
#include <stdlib.h>
//#include <sys/types>
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


int main (void)
{
	char e_buff[LIBNET_ERRBUF_SIZE];
	libnet_t * l;

	l = libnet_init(LIBNET_RAW4, NULL, e_buff);
	if (l == NULL)
	{
		printf("libnet init error\n");
		exit(EXIT_FAILURE);
	}

	u_long kevin_ip;
	u_long server_ip = libnet_name2addr4(l, SERVER_IP, LIBNET_RESOLVE);

	exit(EXIT_SUCCESS);
}
