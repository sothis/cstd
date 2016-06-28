#ifndef _KFILE_IO_COMMON_H_
#define _KFILE_IO_COMMON_H_

#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>

void _kf_calculate_header_digest(void* kfile);


static inline ssize_t _kf_fill_io_buf(int fd, unsigned char* buf, size_t nbyte)
{
	ssize_t nread = 0;
	ssize_t total = 0;

	while (total != nbyte) {
		nread = read(fd, buf + total, nbyte - total);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			else return nread;
		}
		if (nread == 0) {
			/* shall not happen in kfile context */
			return -1;
		}
		total += nread;
	}
	return total;
}

static inline int _kf_read_whole(int fd, void* buf, uint16_t nbyte)
{
	int32_t total = 0;

	total = _kf_fill_io_buf(fd, buf, nbyte);

	if (total != nbyte)
		return -1;

	return 0;
}

static inline ssize_t _kf_store_io_buf(int fd, unsigned char* buf, size_t nbyte)
{
	ssize_t nwritten = 0;
	ssize_t total = 0;

	while (total != nbyte) {
		nwritten = write(fd, buf + total, nbyte - total);
		if (nwritten < 0) {
			if (errno == EINTR)
				continue;
			else return nwritten;
		}
		total += nwritten;
	}
	return total;
}

static inline int _kf_write_whole(int fd, void* buf, uint16_t nbyte)
{
	int32_t total = 0;

	total = _kf_store_io_buf(fd, buf, nbyte);

	if (total != nbyte)
		return -1;

	return 0;
}

static inline void assign_uint8_size(uint8_t* dest, uint16_t val)
{
	*dest = (uint8_t)(val - 1);
}

static inline int check_uint8_size(uint16_t val)
{
	if (!val)
		return -1;

	if (val > 256)
		return -1;

	return 0;
}

#endif /* _KFILE_IO_COMMON_H_ */
