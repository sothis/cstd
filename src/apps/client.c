#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include "sio.h"

#define	HOSTNAME	"127.0.0.1"
#define PORT		1337

int main_select(int argc, char* argv[], char* envp[])
{
	int cli_sock = 0;

	cli_sock = sio_connect4(HOSTNAME, PORT);
	if (cli_sock < 0) {
		pdie("Couldn't connect to server via IPv4.");
	}

	sio_close(cli_sock);
	return 0;
}

#if 0
       int getaddrinfo(const char *node, const char *service,
                       const struct addrinfo *hints,
                       struct addrinfo **res);

       void freeaddrinfo(struct addrinfo *res);

       const char *gai_strerror(int errcode);
#endif

int main(int argc, char* argv[], char* envp[])
{
	struct addrinfo filter, *servinfo, *p;
	int r, fd;

	memset(&filter, 0, sizeof(filter));
	filter.ai_family = AF_UNSPEC;
	filter.ai_socktype = SOCK_STREAM;

	if ((r = getaddrinfo("www.google.de", "https", &filter, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
			perror("socket");
			continue;
		}
		if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(fd);
			perror("connect");
			continue;
		}
		break;
	}


	return 0;
}
