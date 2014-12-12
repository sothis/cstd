#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include "sio.h"

#include "sdtl.h"

#define	IFCE		"127.0.0.1"
#define PORT		4242
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

static void add_new_client(int sock)
{
	log_client_accepted(sock);
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
	if (srv_sock >= FD_SETSIZE)
		pdie("socket larger or equal than FD_SETSIZE (%d).", srv_sock);

	FD_SET(srv_sock, &active_set);

	while (1) {
		read_set = active_set;

		res = sio_select(srv_sock+1, &read_set, 0, 0);
		if (res < 0)
			pdie("select() failed.");
		if (res == 0)
			/* timeout */
			pdie("no select() timeout expected.");

		if (FD_ISSET(srv_sock, &read_set)) {
			new_client_sock = sio_accept(srv_sock);
			if (new_client_sock < 0)
				pdie("accept() failed.");

			/* we do not add the client socket to the
			 * active fd set, so that it definitely means
			 * that a new client tries to connect when the
			 * select returns */
			add_new_client(new_client_sock);
		}
	}

	sio_close(srv_sock);
	return 0;
}
