#include "sio.h"
#include "constructor.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN32)
#include <io.h>
#define SHUT_RDWR	SD_BOTH
#define	close		closesocket
#define socklen_t	int
#define IO_BUF_TYPE	char
#else
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#define IO_BUF_TYPE	void
#endif


#if defined(__APPLE__) || defined(_WIN32)
#define MSG_NOSIGNAL	0
#endif

#if defined(_WIN32) && !defined(WIN32)
#define WIN32
#endif

#if !defined(WIN32)
static void sio_sigpipe(int signal, siginfo_t* info, void* context)
{
	/* just ignore */
}
#endif

static int eintr_handler(void)
{
	/* return 0 to restart an io primitive after an interrupt,
	 * or nonzero to cancel it */
	return 0;
}

static void _sio_cleanup(void)
{
#if defined(WIN32)
	WSACleanup();
#endif
}

#if TLS
SSL_CTX* sslctx;

SSL_CTX* InitServerCTX(void)
{
	SSL_CTX* ctx;

	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ERR_load_crypto_strings();
	ctx = SSL_CTX_new(SSLv23_server_method());
	if ( ctx == NULL ) {
		ERR_print_errors_fp(stderr);
		abort();
	}
#if 0
	if (!SSL_CTX_set_cipher_list(ctx, "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA")) {
		printf("could not set ciphers\n");
		exit(1);
	}
#endif
	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}

	if ( !SSL_CTX_check_private_key(ctx) )
	{
		fprintf(stderr, "Private key does not match the public certificate\n");
		abort();
	}
}
#endif /* TLS */

__constructor(_sio_init)
{
#if defined(WIN32)
	WORD wVersionRequested;
	WSADATA wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	WSAStartup(wVersionRequested, &wsaData);
#else
	struct sigaction action;
	memset(&action, 0, sizeof(action));

	action.sa_sigaction = &sio_sigpipe,
	action.sa_flags = SA_RESTART,
#if 0
	/* we should not need this, we're using MSG_NOSIGNAL on linux
	 * and SO_NOSIGPIPE on mac os. on windows this never happens. */
	sigaction(SIGPIPE, &action, 0);
#endif
#endif

#if TLS
	SSL_library_init();
	sslctx = InitServerCTX();
	LoadCertificates(sslctx, "test/e2e.crt", "test/e2e.key");
#endif /* TLS */

	atexit(&_sio_cleanup);
}

#if TLS
SSL* sio_ssl_new(void)
{
	return SSL_new(sslctx);
}
#endif /* TLS */

#if defined(__APPLE__)
static int sio_set_nosigpipe(int sock, int32_t val)
{
	int res;
	res = setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}
#endif

void sio_fd_clr(int sock, fd_set* set)
{
	#if defined(WIN32)
	FD_CLR((SOCKET)sock, set);
	#else
	FD_CLR(sock, set);
	#endif
}

void sio_fd_set(int sock, fd_set* set)
{
	#if defined(WIN32)
	FD_SET((SOCKET)sock, set);
	#else
	FD_SET(sock, set);
	#endif
}

int sio_fd_isset(int sock, fd_set* set)
{
	#if defined(WIN32)
	return FD_ISSET((SOCKET)sock, set);
	#else
	return FD_ISSET(sock, set);
	#endif
}

void sio_fd_zero(fd_set* set)
{
	FD_ZERO(set);
}

int sio_set_nonblock(int sock, int32_t val)
{
	int res;
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return -1;

	if (val)
		flags |= O_NONBLOCK;
	else
		flags &= ~O_NONBLOCK;

	res = fcntl(sock, F_SETFL, flags);
	return res;
}

int sio_set_reuseaddr(int sock, int32_t val)
{
	int res;
	res = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}

int sio_set_linger(int sock, int32_t val, int16_t seconds)
{
	int res;
	struct linger l;
	l.l_onoff = val;
	l.l_linger = seconds;
	res = setsockopt(sock, SOL_SOCKET, SO_LINGER,
		(const IO_BUF_TYPE*)&l, sizeof(struct linger));
	return res;
}

int sio_set_keepalive(int sock, int32_t val)
{
	int res;
	res = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}

int sio_set_ipv6_only(int af_inet6sock, int32_t val)
{
	int res;
	res = setsockopt(af_inet6sock, IPPROTO_IPV6, IPV6_V6ONLY,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}

int sio_set_tcp_no_delay(int sock, int32_t val)
{
	int res;
	res = setsockopt(sock, SOL_TCP, TCP_NODELAY,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}

int sio_set_tcp_cork(int sock, int32_t val)
{
	int res;
	res = setsockopt(sock, SOL_TCP, TCP_CORK,
		(const IO_BUF_TYPE*)&val, sizeof(int32_t));
	return res;
}

int sio_set_recv_timeout(int sock, int32_t milliseconds)
{
	int res;
#if defined(WIN32)
	DWORD ms = milliseconds;
	res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
		(const IO_BUF_TYPE*)&ms, sizeof(DWORD));
#else
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	res = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
		(const IO_BUF_TYPE*)&tv, sizeof(struct timeval));
#endif
	return res;
}

int sio_set_send_timeout(int sock, int32_t milliseconds)
{
	int res;
#if defined(WIN32)
	DWORD ms = milliseconds;
	res = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
		(const IO_BUF_TYPE*)&ms, sizeof(DWORD));
#else
	struct timeval tv;
	tv.tv_sec = milliseconds / 1000;
	tv.tv_usec = (milliseconds % 1000) * 1000;
	res = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
		(const IO_BUF_TYPE*)&tv, sizeof(struct timeval));
#endif
	return res;
}

int sio_recv(int sock, void* out, int length, int flags)
{
	int res;
	do {
		res = recv(sock, (IO_BUF_TYPE*)out, length, flags);
	} while ((res < 0) && ((errno == EINTR) && !eintr_handler()));
	return res;
}

int sio_send(int sock, const void* in, int length, int flags)
{
	int res;
	flags |= MSG_NOSIGNAL;

	do {
		res = send(sock, (const IO_BUF_TYPE*)in, length, flags);
	} while ((res < 0) && ((errno == EINTR) && !eintr_handler()));
	return res;
}

int sio_accept(int sock)
{
	int res;

	do {
		res = accept(sock, 0, 0);
	} while ((res < 0) && ((errno == EINTR) && !eintr_handler()));

	return res;
}

int sio_select(int nfds, fd_set* rd, fd_set* wr, fd_set* ex)
{
	int res;

	do {
		res = select(nfds, rd, wr, ex, 0);
	} while ((res < 0) && ((errno == EINTR) && !eintr_handler()));
	return res;
}

void sio_close(int sock)
{
	shutdown(sock, SHUT_RDWR);
	close(sock);
}

static int sio_connect(int sock, const struct sockaddr* addr, socklen_t addrlen)
{
	int res;

	do {
		res = connect(sock, addr, addrlen);
	} while ((res < 0) && ((errno == EINTR) && !eintr_handler()));

	return res;
}

int sio_connect4(const char* hostname, uint16_t port)
{
	int sock;
	struct hostent* hostinfo;
	struct sockaddr_in servername = {0};

	sock = (int)socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	#if defined(__APPLE__)
	if (sio_set_nosigpipe(sock, 1)) {
		close(sock);
		return -1;
	}
	#endif

	servername.sin_family = AF_INET;
	servername.sin_port = htons(port);
	/* TODO: gethostbyname is obsolete, use getaddrinfo() */
	hostinfo = gethostbyname(hostname ? hostname : "localhost");
	if (!hostinfo) {
		close(sock);
		return -1;
	}

	servername.sin_addr = *(struct in_addr*)hostinfo->h_addr;

	if (sio_connect(sock, (const struct sockaddr*)&servername,
	sizeof(struct sockaddr_in))) {
		close(sock);
		return -1;
	}

	return sock;
}

int sio_listen4(const char* ifce, uint16_t port, int reuseaddr, int backlog)
{
	int32_t sock;
	int32_t res;
	struct hostent* hostinfo;
	struct sockaddr_in addr;

	/* TODO: gethostbyname is obsolete, use getaddrinfo() */
	hostinfo = gethostbyname(ifce ? ifce : "0.0.0.0");
	if (!hostinfo)
		return -1;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		return -1;

	#if defined(__APPLE__)
	if (sio_set_nosigpipe(sock, 1)) {
		close(sock);
		return -1;
	}
	#endif

	if (reuseaddr && sio_set_reuseaddr(sock, 1)) {
		close(sock);
		return -1;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr = *(struct in_addr*)hostinfo->h_addr;
	addr.sin_port = htons(port);

	res = bind(sock, (struct sockaddr*)&addr,
		sizeof(struct sockaddr_in));
	if (res < 0) {
		close(sock);
		return -1;
	}

	res = listen(sock, backlog);
	if (res < 0) {
		close(sock);
		return -1;
	}

	return sock;
}

int sio_new_tcp_listening_socket(struct tcp_sock_opt_t* sock_opts)
{
	char _port[6];
	int r = 0, fd = -1;
	struct addrinfo* addresses = 0;
	struct addrinfo* it = 0;
	struct addrinfo addr_filter = {
		.ai_flags	= AI_PASSIVE | AI_NUMERICSERV,
		.ai_family	= AF_INET6,
		.ai_socktype	= SOCK_STREAM,
		.ai_protocol	= IPPROTO_TCP,
	};

	if (!sock_opts)
		return -1;

	if (!sock_opts->port)
		return -1;

	if (!sock_opts->backlog)
		sock_opts->backlog = SOMAXCONN;

	snprintf(_port, sizeof(_port), "%u", sock_opts->port);

	r = getaddrinfo(sock_opts->interface, _port, &addr_filter, &addresses);
	if (r < 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		return -1;
	}

	for (it = addresses; it; it = it->ai_next) {
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0) {
			perror("socket");
			continue;
		}

		if (sio_set_ipv6_only(fd, sock_opts->ipv6_only)) {
			perror("sio_set_ipv6_only()");
			sio_close(fd);
			continue;
		}
		if (sio_set_reuseaddr(fd, sock_opts->reuse_address)) {
			perror("sio_set_reuseaddr()");
			sio_close(fd);
			continue;
		}
		if (sio_set_keepalive(fd, sock_opts->keep_alive)) {
			perror("sio_set_keepalive()");
			sio_close(fd);
			continue;
		}
		if (sio_set_send_timeout(fd, sock_opts->send_timeout_ms)) {
			perror("sio_set_send_timeout()");
			sio_close(fd);
			continue;
		}
		if (sio_set_recv_timeout(fd, sock_opts->recv_timeout_ms)) {
			perror("sio_set_recv_timeout()");
			sio_close(fd);
			continue;
		}
		if (sio_set_tcp_no_delay(fd, sock_opts->no_delay)) {
			perror("sio_set_tcp_no_delay()");
			sio_close(fd);
			continue;
		}
		if (sio_set_tcp_cork(fd, sock_opts->cork)) {
			perror("sio_set_tcp_cork()");
			sio_close(fd);
			continue;
		}
		if (sio_set_linger(fd, sock_opts->set_linger,
		sock_opts->linger_seconds)) {
			perror("sio_set_linger()");
			sio_close(fd);
			continue;
		}
		if (sio_set_nonblock(fd, sock_opts->non_blocking)) {
			perror("sio_set_nonblock()");
			sio_close(fd);
			continue;
		}

		if (bind(fd, it->ai_addr, it->ai_addrlen) == -1) {
			perror("bind");
			sio_close(fd);
			continue;
		}
		/* accept the first socket we could bind to the interface */
		break;
	}
	if (addresses)
		freeaddrinfo(addresses);

	if (fd < 0)
		return -1;

	/* adjust listen backlog to tune the accept() queue size
	 * see /proc/sys/net/ipv4/tcp_max_syn_backlog for the queue
	 * size of already accepted TCP connections */
	if (listen(fd, sock_opts->backlog)) {
		perror("listen");
		sio_close(fd);
		return -1;
	}

	return fd;
}


int sio_new_tcp_connection(struct tcp_sock_opt_t* sock_opts)
{
	char _port[6];
	int r, fd = -1;
	struct addrinfo* addresses = 0;
	struct addrinfo* it = 0;
	struct addrinfo addr_filter = {
		.ai_flags	= AI_NUMERICSERV,
		.ai_family	= AF_UNSPEC,
		.ai_socktype	= SOCK_STREAM,
		.ai_protocol	= IPPROTO_TCP,
	};

	if (!sock_opts)
		return -1;

	if (!sock_opts->port)
		return -1;

	snprintf(_port, sizeof(_port), "%u", sock_opts->port);

	r = getaddrinfo(sock_opts->remotehost, _port, &addr_filter, &addresses);
	if (r < 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		return -1;
	}

	for (it = addresses; it; it = it->ai_next) {
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0) {
			perror("socket");
			continue;
		}

		if (sio_set_keepalive(fd, sock_opts->keep_alive)) {
			perror("sio_set_keepalive()");
			sio_close(fd);
			continue;
		}
		if (sio_set_send_timeout(fd, sock_opts->send_timeout_ms)) {
			perror("sio_set_send_timeout()");
			sio_close(fd);
			continue;
		}
		if (sio_set_recv_timeout(fd, sock_opts->recv_timeout_ms)) {
			perror("sio_set_recv_timeout()");
			sio_close(fd);
			continue;
		}
		if (sio_set_tcp_no_delay(fd, sock_opts->no_delay)) {
			perror("sio_set_tcp_no_delay()");
			sio_close(fd);
			continue;
		}
		if (sio_set_tcp_cork(fd, sock_opts->cork)) {
			perror("sio_set_tcp_cork()");
			sio_close(fd);
			continue;
		}
		if (sio_set_linger(fd, sock_opts->set_linger,
		sock_opts->linger_seconds)) {
			perror("sio_set_linger()");
			sio_close(fd);
			continue;
		}
		if (sio_set_nonblock(fd, sock_opts->non_blocking)) {
			perror("sio_set_nonblock()");
			sio_close(fd);
			continue;
		}

		if (connect(fd, it->ai_addr, it->ai_addrlen)) {
			perror("connect");
			sio_close(fd);
			continue;
		}
		/* accept the first socket we could connect */
		break;
	}
	if (addresses)
		freeaddrinfo(addresses);

	return fd;
}

static inline int check_event_err(uint32_t ev)
{
	return ((ev & EPOLLERR) || (ev & EPOLLHUP) || (!(ev & EPOLLIN)));
}

static inline int add_client_to_epoll_list(int ep_fdset, int cli_sock)
{
	int r;
	struct epoll_event ee = {
		.data.fd = 0,
		.events = EPOLLIN | EPOLLET,
	};

	r = epoll_ctl(ep_fdset, EPOLL_CTL_ADD, cli_sock, &ee);
	return r;
}

static void accept_pending_connections
(int srv_sock, int ep_fdset, struct tcp_sock_opt_t* cli_sock_opts)
{
	int cli_sock;
	struct sockaddr in_addr;
	socklen_t in_len = sizeof(struct sockaddr);

	while (1) {
		cli_sock = accept(srv_sock, &in_addr, &in_len);

		if (cli_sock < 0) {
			if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
				/* processed all pending connections */
				break;
			} else {
				perror("accept");
				continue;
			}
		}

#if 0
		char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
		int r;

		r = getnameinfo(&in_addr, in_len,
			hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
			NI_NUMERICHOST | NI_NUMERICSERV);

		if (!r) {
			printf("Accepted connection on descriptor %d "
				"(host=%s, port=%s)\n", client_fd, hbuf, sbuf);
		}
#endif

		if (sio_set_keepalive(cli_sock, cli_sock_opts->keep_alive)) {
			perror("sio_set_keepalive()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_send_timeout(cli_sock,
		cli_sock_opts->send_timeout_ms)) {
			perror("sio_set_send_timeout()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_recv_timeout(cli_sock,
		cli_sock_opts->recv_timeout_ms)) {
			perror("sio_set_recv_timeout()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_tcp_no_delay(cli_sock, cli_sock_opts->no_delay)) {
			perror("sio_set_tcp_no_delay()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_tcp_cork(cli_sock, cli_sock_opts->cork)) {
			perror("sio_set_tcp_cork()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_linger(cli_sock, cli_sock_opts->set_linger,
		cli_sock_opts->linger_seconds)) {
			perror("sio_set_linger()");
			sio_close(cli_sock);
			continue;
		}
		if (sio_set_nonblock(cli_sock, cli_sock_opts->non_blocking)) {
			perror("sio_set_nonblock()");
			sio_close(cli_sock);
			continue;
		}

		add_client_to_epoll_list(ep_fdset, cli_sock);
	}
}

static inline void handle_epoll_event
(int ep_fdset, int srv_sock, struct epoll_event* event,
struct tcp_sock_opt_t* cli_sock_opts)
{
	if (check_event_err(event->events)) {
		fprintf(stderr, "epoll error\n");
		sio_close(event->data.fd);
	} else if (event->data.fd == srv_sock) {
		accept_pending_connections(srv_sock, ep_fdset, cli_sock_opts);
	} else {
		//process_client_fd(event->data.fd);
	}
}


int sio_tcp_epoll_server
(int srv_sock, int epoll_max_events, struct tcp_sock_opt_t* cli_sock_opts)
{
	int ep_fdset, r;
	struct epoll_event* events;
	struct tcp_sock_opt_t* co;
	struct epoll_event ee;

	if (!cli_sock_opts)
		return -1;

	co = cli_sock_opts;

	if (!epoll_max_events)
		epoll_max_events = 512;

	events = calloc(epoll_max_events, sizeof(struct epoll_event));
	if (!events) {
		perror("calloc");
		return -1;
	}

	ep_fdset = epoll_create1(0);
	if (ep_fdset < 0) {
		perror("epoll_create1");
		free(events);
		return -1;
	}
	ee = (struct epoll_event) {
		.events		= EPOLLIN | EPOLLET,
		.data.fd	= srv_sock,
	};

	r = epoll_ctl(ep_fdset, EPOLL_CTL_ADD, srv_sock, &ee);
	if (r < 0) {
		perror("epoll_ctl");
		free(events);
		return -1;
	}

	for (;;) {
		int n, i;
		n = epoll_wait(ep_fdset, events, epoll_max_events, -1);
		for (i = 0; i < n; i++) {
			handle_epoll_event(ep_fdset, srv_sock, &events[i], co);
			#if 0
			if (check_event_err(events[i].events)) {
				fprintf(stderr, "epoll error\n");
				close(events[i].data.fd);
				continue;
			} else if (events[i].data.fd == srv_sock) {
				accept_pending_connections(listen_fd, ep_fdset);
				continue;
			} else {
				//process_client_fd(events[i].data.fd);
				continue;
			}
			#endif
		}
	}

	return 0;
}
