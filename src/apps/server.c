#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include "sio.h"

#define	IFCE		"127.0.0.1"
#define PORT		1337
#define REUSEADDR	1
#define BACKLOG		10

int main(int argc, char* argv[], char* envp[])
{
	int srv_sock = 0;

	srv_sock = sio_listen4(IFCE, PORT, REUSEADDR, BACKLOG);
	if (srv_sock < 0) {
		pdie("Couldn't create listening IPv4 socket.");
	}

	sio_close(srv_sock);
	return 0;
}
