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

static void log_client_accepted(int sock)
{
	struct sockaddr_in a;
	socklen_t s = sizeof(a);

	getpeername(sock, (struct sockaddr*)&a, &s);
	eprintf(LOG_INFO, "accepted connection from [%s]:%u\n",
		inet_ntoa(a.sin_addr), htons(a.sin_port));
}

static void handle_client_requests(int sock)
{
	sio_close(sock);
	return;
}

int main(int argc, char* argv[], char* envp[])
{
	int res = 0;
	int srv_sock = 0;
	int new_client_sock = 0;
	fd_set active_set;
	fd_set read_set;


	srv_sock = sio_listen4(IFCE, PORT, REUSEADDR, BACKLOG);
	if (srv_sock < 0)
		pdie("Couldn't create listening IPv4 socket.");

	FD_ZERO(&active_set);
	FD_SET(srv_sock, &active_set);

	while (1) {
		read_set = active_set;

		res = sio_select(srv_sock+1, &read_set, 0, 0);
		if (res < 0)
			pdie("select() failed.");

		if (FD_ISSET(srv_sock, &read_set)) {
			new_client_sock = sio_accept(srv_sock);
			if (new_client_sock < 0)
				pdie("accept() failed.");

			log_client_accepted(new_client_sock);
			handle_client_requests(new_client_sock);
		}
	}

	sio_close(srv_sock);
	return 0;
}
