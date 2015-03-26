#ifndef _KFILE_READ_H_
#define _KFILE_READ_H_

#include "kfile_common.h"
#include <stddef.h>
#include <sys/types.h>


ssize_t kfile_read(kfile_read_fd_t fd, void* buf, size_t nbyte);


#endif /* _KFILE_READ_H_ */
