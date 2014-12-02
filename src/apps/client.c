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

int main(int argc, char* argv[], char* envp[])
{
	int cli_sock = 0;

	cli_sock = sio_connect4(HOSTNAME, PORT);
	if (cli_sock < 0) {
		pdie("Couldn't connect to server via IPv4.");
	}

	sio_close(cli_sock);
	return 0;
}
