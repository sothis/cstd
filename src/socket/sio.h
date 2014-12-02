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
#include <sys/select.h>
#endif

#include <arpa/inet.h>
#include <netdb.h>

#if TLS
	#include "openssl/ssl.h"
	#include "openssl/err.h"
#endif /* TLS */

#if defined(__cplusplus)
extern "C" {
#endif

int sio_connect4(const char* hostname, uint16_t port);
int sio_listen4(const char* ifce, uint16_t port, int reuseaddr, int backlog);
int sio_select(int nfds, fd_set* rd, fd_set* wr, fd_set* ex);
int sio_accept(int sock);
void sio_close(int sock);

int sio_set_reuseaddr(int sock, int32_t val);
int sio_set_linger(int sock, int32_t val, int16_t seconds);
int sio_set_keepalive(int sock, int32_t val);
int sio_set_recv_timeout(int sock, int32_t milliseconds);
int sio_set_send_timeout(int sock, int32_t milliseconds);

int sio_recv(int sock, void* out, int length, int flags);
int sio_send(int sock, const void* in, int length, int flags);

void sio_fd_clr(int sock, fd_set* set);
void sio_fd_set(int sock, fd_set* set);
int sio_fd_isset(int sock, fd_set* set);
void sio_fd_zero(fd_set* set);

#if TLS
SSL* sio_ssl_new(void);
#endif /* TLS */

#if defined(__cplusplus)
}
#endif

#endif /* _SIO_H */
