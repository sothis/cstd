#ifndef _KFILE_OPEN_H_
#define _KFILE_OPEN_H_

#include "kfile_common.h"
#include <stdint.h>
#include <stddef.h>


typedef struct kfile_open_opts_t {
	uint64_t	uuid;
	size_t		iobuf_size;
	/* check cipher digest with kfile_open().
	 * might take a long time with very large encrypted resources. */
	uint32_t	check_cipherdigest;
	char		low_entropy_pass[KFILE_MAX_PASSWORD_LENGTH];
} kfile_open_opts_t;

kfile_read_fd_t kfile_open(kfile_open_opts_t* opts);

#endif /* _KFILE_OPEN_H_ */
