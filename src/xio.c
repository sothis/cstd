#include "xio.h"
#include <errno.h>

int xwrite(int fd, const void* buf, size_t nbyte)
{
	size_t total = 0;
	ssize_t written = 0;
	while (total != nbyte) {
		written = write(fd, buf + total, nbyte - total);
		if (written < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		total += written;
	}
	return 0;
}

ssize_t xread(int fd, void* buf, size_t nbyte)
{
	size_t total = 0;
	ssize_t nread = 0;
	while (total != nbyte) {
		nread = read(fd, buf + total, nbyte - total);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!nread) {
			/* EOF */
			return total;
		}
		total += nread;
	}
	return nbyte;
}
