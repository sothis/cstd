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
#define TESTFILE	"/home/sothis/rimg.bin.copy"

static void log_client_accepted(int sock)
{
	struct sockaddr_in a;
	socklen_t s = sizeof(a);

	getpeername(sock, (struct sockaddr*)&a, &s);
	eprintf(LOG_INFO, "accepted connection from [%s]:%u\n",
		inet_ntoa(a.sin_addr), htons(a.sin_port));
}

static int sbegin = 0;
static int test_fd = 0;

int _on_sdtl_event(void* userdata, sdtl_event_t e, sdtl_data_t* data)
{
	switch (e) {
		case ev_sdtl_stream_begin:
			eprintf(LOG_INFO, "stream begin\n");
			break;
		case ev_assignment_start:
			eprintf(LOG_INFO, "assignment start: '%s'\n", (char*)data->data);
			break;
		case ev_data:
			eprintf(LOG_INFO, "\tvalue data (%u bytes)\n", data->length);
			if (sbegin) {
				xwrite(test_fd, data->data, data->length);
			}
			break;
		case ev_struct_start:
			eprintf(LOG_INFO, "struct start\n");
			break;
		case ev_struct_end:
			eprintf(LOG_INFO, "struct end\n");
			break;
		case ev_array_new_row:
			eprintf(LOG_INFO, "array new row\n");
			break;
		case ev_array_end_row:
			eprintf(LOG_INFO, "array end row\n");
			break;
		case ev_octet_stream_start:
			sbegin = 1;
			test_fd = open(TESTFILE, O_RDWR | O_CREAT, 0644);
			eprintf(LOG_INFO, "stream start\n");
			break;
		case ev_octet_stream_end:
			sbegin = 0;
			close(test_fd);
			eprintf(LOG_INFO, "stream end\n");
			break;
		default:
			eprintf(LOG_CRIT, "unexpected event\n");
			return -1;
	}
	fflush(stderr);

	return 0;
}

static void add_new_client(int sock)
{
	log_client_accepted(sock);

	sdtl_read_fd_t sdtl_rfd;
	sdtl_read_flags_t sdtl_read_flags;

	memset(&sdtl_read_flags, 0, sizeof(sdtl_read_flags_t));
	sdtl_read_flags.on_event = &_on_sdtl_event;
	sdtl_read_flags.max_struct_nesting = 4;
	sdtl_read_flags.max_file_size =
	sdtl_read_flags.max_text_bytes = uint64_max;
	sdtl_read_flags.userdata = 0;

	int dbg_fd = fileno(stdout);
	sdtl_open_read(&sdtl_rfd, sock, &dbg_fd, &sdtl_read_flags);
	if (sdtl_read(&sdtl_rfd)) {
		eprintf(LOG_CRIT, "the parser has interrupted its work "
			"(error %d) @ '%c'\n",
			sdtl_get_error(&sdtl_rfd), sdtl_rfd.byte);
		pdie("Invalid SDTL input. Terminating.\n");
	}

	printf("closing connection\n");
	sio_close(sock);
	return;
}

int cstd_main(int argc, char* argv[], char* envp[])
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
			sio_set_recv_timeout(new_client_sock, 2000);
			add_new_client(new_client_sock);
		}
	}

	sio_close(srv_sock);
	return 0;
}
