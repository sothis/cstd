#ifndef _SIO_H
#define _SIO_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN	1
#define VC_EXTRALEAN		1
#include <windows.h>
#include <winsock2.h>
#else
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#endif

#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#if TLS
	#include "openssl/ssl.h"
	#include "openssl/err.h"
#endif /* TLS */

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct tcp_sock_opt_t {
	union {
		const char*	interface;
		const char*	remotehost;
	};
	uint16_t	port;
	int32_t		non_blocking;
	int32_t		keep_alive;
	int32_t		reuse_address; /* only for server sockets */
	int32_t		backlog; /* only for server sockets */
	/* ipv6_only is off per default according to RFC3493,
	 * but windows has it on by default (what a surprise)
	 * to maintain backwards compatibility. if set AF_INET6 server
	 * sockets don't accept IPv4 connections. */
	int32_t		ipv6_only;
	int32_t		no_delay;
	int32_t		cork;
	int32_t		recv_timeout_ms;
	int32_t		send_timeout_ms;
	/* set_linger 1 and linger_seconds 0 as a last resort for too may
	 * TIMED_WAIT sockets consuming system resources.
	 * if it's a problem redesign the protocol so that the client
	 * initiates shutdown. */
	int32_t		set_linger;
	uint16_t	linger_seconds;
} tcp_sock_opt_t;

typedef int (*fn_srv_callb_t)(int);

typedef struct tcp_epoll_srv_t {
	struct tcp_sock_opt_t	client_socket_options;
	int			listen_fd;
	int			max_epoll_events;
	int			max_accept_connections;
	fn_srv_callb_t		on_bytes_available;
} tcp_epoll_srv_t;

int sio_connect4(const char* hostname, uint16_t port);
int sio_listen4(const char* ifce, uint16_t port, int reuseaddr, int backlog);
int sio_select(int nfds, fd_set* rd, fd_set* wr, fd_set* ex);
int sio_accept(int sock);
void sio_close(int sock);

int sio_set_nonblock(int sock, int32_t val);
int sio_set_reuseaddr(int sock, int32_t val);
int sio_set_linger(int sock, int32_t val, int16_t seconds);
int sio_set_keepalive(int sock, int32_t val);
int sio_set_recv_timeout(int sock, int32_t milliseconds);
int sio_set_send_timeout(int sock, int32_t milliseconds);
int sio_set_ipv6_only(int af_inet6sock, int32_t val);
int sio_set_tcp_no_delay(int sock, int32_t val);
int sio_set_tcp_cork(int sock, int32_t val);

int sio_recv(int sock, void* out, int length, int flags);
int sio_send(int sock, const void* in, int length, int flags);

void sio_fd_clr(int sock, fd_set* set);
void sio_fd_set(int sock, fd_set* set);
int sio_fd_isset(int sock, fd_set* set);
void sio_fd_zero(fd_set* set);

int sio_new_tcp_listening_socket(struct tcp_sock_opt_t* sock_opts);
int sio_new_tcp_connection(struct tcp_sock_opt_t* sock_opts);
int sio_tcp_epoll_server(struct tcp_epoll_srv_t* srv_opts);


#if TLS
SSL* sio_ssl_new(void);
#endif /* TLS */

#if defined(__cplusplus)
}
#endif

#endif /* _SIO_H */
