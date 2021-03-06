#ifndef _KFILE_UPDATE_H_
#define _KFILE_UPDATE_H_

#include "kfile_common.h"


ssize_t kfile_update(kfile_write_fd_t fd, const void* buf, size_t nbyte);
ssize_t _kfile_update_internal(kfile_write_fd_t fd, const void *buf, size_t nbyte);

#endif /* _KFILE_UPDATE_H_ */
