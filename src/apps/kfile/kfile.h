#ifndef _KFILE_H_
#define _KFILE_H_

#include "cstd.h"
#include <libk/libk.h>


#include <dirent.h>


#include "kfile_version.h"
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
	DIR*		path_ds;
	int		path_fd;
	k_hash_t*	hash_plaintext;
	k_hash_t*	hash_ciphertext;
	k_sc_t*		scipher;
	k_prng_t*	prng;

	kfile_version_t	version;
	size_t		filesize;
	uint64_t	ciphersize;
	uint64_t	cipherstart;
	size_t		noncebytes;
	size_t		digestbytes;
	char*		path;
	char*		filename;
	size_t		iobuf_size;
	unsigned char*	iobuf;
	unsigned char*	key;
	char		resourcename[KFILE_MAX_RES_NAME_LENGTH];
	unsigned char	resourcename_len;
	unsigned char*	headerdigest;
	unsigned char*	datadigest;
	unsigned char*	cipherdigest;

	kfile_preamble_t		preamble;
	kfile_dynamic_data_header_t	dyndata;
	kfile_control_header_t		control;
	kfile_kdf_header_t		kdf_header;
	kfile_iv_header_t		iv_header;

} kfile_t;

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


void xuuid_to_path(uint64_t uuid, char** compl, char** fpath, char** fname);
const char* kfile_get_resource_name(kfile_read_fd_t fd);



#endif /* _KFILE_H_ */
