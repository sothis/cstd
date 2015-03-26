#ifndef _KFILE_IO_COMMON_H_
#define _KFILE_IO_COMMON_H_

#include <sys/types.h>

ssize_t _kf_fill_io_buf(int fd, unsigned char* buf, size_t nbyte);
void _kf_calculate_header_digest(void* kfile);

#endif /* _KFILE_IO_COMMON_H_ */
