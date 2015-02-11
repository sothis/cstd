#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>

#include "sio.h"

#include "sdtl.h"
#include <libk/libk.h>

#include <sys/epoll.h>
#include <sys/statvfs.h>

#define	IFCE		"127.0.0.1"
#define PORT		"4242"
#define REUSEADDR	1
#define BACKLOG		10
#define TESTFILE	"/home/sothis/rimg.bin.copy"

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
	"SOCK_UNSPEC",
	"SOCK_STREAM",
	"SOCK_DGRAM",
	"SOCK_RAW",
	"SOCK_RDM",
	"SOCK_SEQPACKET",
	"SOCK_DCCP",
	"SOCK_UNSPEC",
	"SOCK_UNSPEC",
	"SOCK_UNSPEC",
	"SOCK_PACKET"
};

int fn(void)
{
	struct addrinfo filter, *servinfo, *p;
	int r, fd = -1;

	debug("debug");
	info("info");
	notice("notice");
	warning("warning");
	err("error");
	crit("critical");
	alert("alert");
	emerg("emergency");


	errno = 13;
	pdie("test");

	memset(&filter, 0, sizeof(filter));
	/* supports also ipv4 after disabling IPV6_V6ONLY on the socket
	 * (default on most systems, except windows) */
	filter.ai_family = AF_INET6;
	filter.ai_socktype = SOCK_STREAM; /* TCP */
	filter.ai_protocol = 0; /* any */
	filter.ai_flags = AI_PASSIVE; /* suitable for accepting connections */

	if ((r = getaddrinfo(0, PORT, &filter, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		exit(1);
	}

	for(p = servinfo; p != NULL; p = p->ai_next) {
	#if 1
		printf("ai_flags:\t%d\n", p->ai_flags);
		printf("ai_family:\t%s\n", address_families[p->ai_family]);
		printf("ai_socktype:\t%s\n", socket_types[p->ai_socktype]);
		printf("ai_protocol:\t%d\n", p->ai_protocol);
		printf("ai_canonname:\t%s\n", p->ai_canonname);
	#endif
		fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (fd < 0) {
			perror("unable to create socket");
			continue;
		}
		/* ipv6_only is off per default according to RFC3493,
		 * but windows has it on by default to maintain backwards
		 * compatibility */
	//	sio_set_ipv6_only(fd, 0);
		sio_set_reuseaddr(fd, 1);
		if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
			close(fd);
			perror("bind1");
			continue;
		}
		/* listen backlog to tune the accept() queue size
		 * see /proc/sys/net/ipv4/tcp_max_syn_backlog for the queue
		 * size of already accepted TCP connections */
		if (listen(fd, 10)) {
			perror("listen");
			close(fd);
			continue;
		}
		break;

	}
	getchar();
	return 0;
}

#if 0
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
#endif

#if 0
struct statvfs {
    unsigned long  f_bsize;    /* file system block size */
    unsigned long  f_frsize;   /* fragment size */
    fsblkcnt_t     f_blocks;   /* size of fs in f_frsize units */
    fsblkcnt_t     f_bfree;    /* # free blocks */
    fsblkcnt_t     f_bavail;   /* # free blocks for unprivileged users */
    fsfilcnt_t     f_files;    /* # inodes */
    fsfilcnt_t     f_ffree;    /* # free inodes */
    fsfilcnt_t     f_favail;   /* # free inodes for unprivileged users */
    unsigned long  f_fsid;     /* file system ID */
    unsigned long  f_flag;     /* mount flags */
    unsigned long  f_namemax;  /* maximum filename length */
};
#endif

int cstd_main(int argc, char* argv[], char* envp[])
{
	int res = 0;
	int srv_sock = 0;
#if 0
	int new_client_sock = 0;
	fd_set active_set;
	fd_set read_set;
#endif
	if (k_run_unittests(0))
		pdie("some of the libk unit tests failed.");

	// fn();

	struct statvfs svfs;

	memset(&svfs, 0, sizeof(struct statvfs));

	if (statvfs("/home", &svfs)) {
		pdie("statvfs()");
	}
	printf("inodes:\t\t%" PRIu64 "\n", svfs.f_files);
	printf("used:\t\t%" PRIu64 "\n", svfs.f_files - svfs.f_ffree);
	printf("free root:\t%" PRIu64 "\n", svfs.f_ffree);
	printf("free user:\t%" PRIu64 "\n",svfs.f_favail);
	printf("max name:\t%" PRIu64 "\n",svfs.f_namemax);



#if 0
	srv_sock = sio_listen4(IFCE, PORT, REUSEADDR, BACKLOG);
	if (srv_sock < 0)
		pdie("Couldn't create listening IPv4 socket.");
#endif

#if 0
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
#endif
	return 0;
}
