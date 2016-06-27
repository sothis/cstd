#ifndef _KFILE_H_
#define _KFILE_H_


#include "cstd.h"
#include <libk/libk.h>

#include "kfile_version.h"
#include "kfile_fs_layout.h"
#include "kfile_common.h"
#include "kfile_ondisk.h"
#include "kfile_io_common.h"
#include "kfile_kdf.h"
#include "kfile_create.h"
#include "kfile_open.h"
#include "kfile_read.h"
#include "kfile_update.h"
#include "kfile_close.h"


typedef struct kfile_t {
	int		fd;
	kfile_header_t	header;

	const struct kfile_fsl_desc* fs_layout;
	k_hash_t*	hash_plaintext;
	k_hash_t*	hash_ciphertext;
	k_sc_t*		scipher;
	k_prng_t*	prng;

	kfile_version_t	version;
	kfile_layout_t	layout;
	size_t		filesize;
	uint64_t	ciphersize;
	uint64_t	cipherstart;
	size_t		noncebytes;
	size_t		digestbytes;
	size_t		iobuf_size;
	unsigned char*	iobuf;
	unsigned char*	key;
	char		resourcename[KFILE_MAX_RES_NAME_LENGTH];
	unsigned char	resourcename_len;
	unsigned char*	headerdigest;
	unsigned char*	datadigest;
	unsigned char*	cipherdigest;
} kfile_t;


const char* kfile_get_resource_name(kfile_read_fd_t fd);


#endif /* _KFILE_H_ */
