#ifndef _KFILE_CLOSE_H_
#define _KFILE_CLOSE_H_

#include "kfile_common.h"


void kfile_write_digests_and_close(kfile_write_fd_t fd);
int kfile_close(kfile_fd_t fd);


#endif /* _KFILE_CLOSE_H_ */
