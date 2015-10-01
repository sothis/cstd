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

int sio_set_nonblock(int sock)
{
	int res;
	int flags;

	flags = fcntl(sock, F_GETFL, 0);
	if (flags < 0)
		return -1;

	flags |= O_NONBLOCK;
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

int sio_new_tcp_listening_socket
(const char* interface, uint16_t port, int backlog, int non_blocking)
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

	if (!port)
		return -1;

	snprintf(_port, sizeof(_port), "%u", port);

	r = getaddrinfo(interface, _port, &addr_filter, &addresses);
	if (r < 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(r));
		return -1;
	}

	for (it = addresses; it; it = it->ai_next) {
		fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
		if (fd < 0) {
		//	perror("socket");
			continue;
		}

		/* ipv6_only is off per default according to RFC3493,
		 * but windows has it on by default (what a surprise)
		 * to maintain backwards compatibility */
		if (sio_set_ipv6_only(fd, 0)) {
			perror("sio_set_ipv6_only(off)");
			sio_close(fd);
			continue;
		}
		if (sio_set_reuseaddr(fd, 1)) {
			perror("sio_set_reuseaddr(on)");
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

	if (non_blocking && sio_set_nonblock(fd)) {
		perror("sio_set_nonblock(on)");
		sio_close(fd);
		return -1;
	}

	/* adjust listen backlog to tune the accept() queue size
	 * see /proc/sys/net/ipv4/tcp_max_syn_backlog for the queue
	 * size of already accepted TCP connections */
	if (listen(fd, backlog)) {
		perror("listen");
		sio_close(fd);
		return -1;
	}

	return fd;
}
