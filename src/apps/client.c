#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include "sio.h"

#include "sdtl.h"

#define	HOSTNAME	"localhost"
#define PORT		"4242"

const char* address_families[] = {
	"AF_UNSPEC",
	"AF_UNIX",
	"AF_INET",
	"AF_AX25",
	"AF_IPX",
	"AF_APPLETALK",
	"AF_NETROM",
	"AF_BRIDGE",
	"AF_ATMPVC",
	"AF_X25",
	"AF_INET6",
	"AF_ROSE",
	"AF_DECnet",
	"AF_NETBEUI",
	"AF_SECURITY",
	"AF_KEY",
	"AF_NETLINK",
	"AF_PACKET",
	"AF_ASH",
	"AF_ECONET",
	"AF_ATMSVC",
	"AF_RDS",
	"AF_SNA",
	"AF_IRDA",
	"AF_PPPOX",
	"AF_WANPIPE",
	"AF_LLC",
	"AF_IB",
	"(address family not defined)",
	"AF_CAN",
	"AF_TIPC",
	"AF_BLUETOOTH",
	"AF_IUCV",
	"AF_RXRPC",
	"AF_ISDN",
	"AF_PHONET",
	"AF_IEEE802154",
	"AF_CAIF",
	"AF_ALG",
	"AF_NFC",
	"AF_VSOCK"
};

const char* socket_types[] = {
	"SOCK_STREAM",
	"SOCK_DGRAM",
	"SOCK_RAW",
	"SOCK_RDM",
	"SOCK_SEQPACKET",
	"SOCK_DCCP",
	"SOCK_PACKET"
};

int main(int argc, char* argv[], char* envp[])
{
	struct addrinfo filter, *servinfo, *p;
	int r, i, fd = -1;

	memset(&filter, 0, sizeof(filter));
	filter.ai_family = AF_UNSPEC;
	filter.ai_socktype = SOCK_STREAM; /* TCP */
	filter.ai_protocol = 0; /* any */
	filter.ai_flags = 0; /* none */

	if ((r = getaddrinfo(HOSTNAME, PORT, &filter, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
	#if 0
		printf("ai_flags:\t%d\n", p->ai_flags);
		printf("ai_family:\t%s\n", address_families[p->ai_family]);
		printf("ai_socktype:\t%s\n", socket_types[p->ai_socktype]);
		printf("ai_protocol:\t%d\n", p->ai_protocol);
		printf("ai_canonname:\t%s\n", p->ai_canonname);
	#endif
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			perror("unable to create socket");
			exit(~0);
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) < 0) {
			close(fd);
			fd = -1;
			continue;
		} else
			break;
	}

	if (fd < 0) {
		perror("unable to connect to server");
		freeaddrinfo(servinfo);
		exit(~0);
	}

	sdtl_write_fd_t sdtl_wfd;
	int dbg_fd = fileno(stdout);

	sdtl_open_write(&sdtl_wfd, fd, &dbg_fd);

	unsigned char buf[65535];

	memset(buf, 0, 65535);

	sdtl_write_start_struct(&sdtl_wfd, "operation");
		sdtl_write_enum(&sdtl_wfd, "do", "add_resource");
		sdtl_write_start_struct(&sdtl_wfd, "param");
			sdtl_write_number(&sdtl_wfd, "uuid", "84654232316898463");
			sdtl_write_utf8string(&sdtl_wfd, "name", "some_document.pdf");
		sdtl_write_end_struct(&sdtl_wfd);
	sdtl_write_end_struct(&sdtl_wfd);

	sdtl_write_start_octet_stream(&sdtl_wfd, "resource_stream");

	// loop over sdtl_write_chunk(&sdtl_wfd, unsigned char* data, uint16_t len)
	for (i = 0; i < 10; ++i) {
		/* TODO:
		 *  	adjust SDTL to support resource streams without
		 *	chunks in order to be able to make full use of the
		 *	linux sendfile() API (it's possible with the current
		 *	variable chunksize solution of SDTL octet streams but
		 *	it would limit sendfile calls to 64kB chunks at max)
		*/
		sdtl_write_chunk(&sdtl_wfd, buf, 65535);
	}

	sdtl_write_end_octet_stream(&sdtl_wfd);

	sdtl_write_number(&sdtl_wfd, "uuid2", "234242342342");
	sdtl_flush(&sdtl_wfd);

	close(fd);
	freeaddrinfo(servinfo);

	return 0;
}
