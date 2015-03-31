#ifndef _KFILE_IO_COMMON_H_
#define _KFILE_IO_COMMON_H_

#include <sys/types.h>

ssize_t _kf_fill_io_buf(int fd, unsigned char* buf, size_t nbyte);
void _kf_calculate_header_digest(void* kfile);

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
