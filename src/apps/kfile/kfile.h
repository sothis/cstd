#ifndef _KFILE_H_
#define _KFILE_H_

#include "cstd.h"
#include <libk/libk.h>

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "kfile_version.h"
#include "kfile_common.h"
#include "kfile_ondisk.h"
#include "kfile_io_common.h"
#include "kfile_kdf.h"
#include "kfile_create.h"
#include "kfile_open.h"
#include "kfile_read.h"
#include "kfile_update.h"


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

static inline uint8_t get_pack_size(uint64_t n)
{
	/* is there a more efficient algorithm? */
	if (n <= 0xff)
		return 1;
	if (n <= 0xffff)
		return 2;
	if (n <= 0xffffff)
		return 3;
	if (n <= 0xffffffff)
		return 4;
	if (n <= 0xffffffffff)
		return 5;
	if (n <= 0xffffffffffff)
		return 6;
	if (n <= 0xffffffffffffff)
		return 7;
	if (n <= 0xffffffffffffffff)
		return 8;
	return 0;
}

static inline size_t pack_uint64(uint64_t n, unsigned char* out)
{
	uint8_t pack_size = get_pack_size(n);

	out[0] = pack_size - 1;
	memcpy(out + 1, &n, pack_size);

	return pack_size + 1;
}

static inline uint64_t unpack_uint64(unsigned char* in)
{
	uint64_t r = 0;
	uint8_t pack_size = in[0] + 1;

	memcpy(&r, in + 1, pack_size);
	return r;
}



void xuuid_to_path(uint64_t uuid, char** compl, char** fpath, char** fname);


void kfile_write_digests_and_close(kfile_write_fd_t fd);
const char* kfile_get_resource_name(kfile_read_fd_t fd);

int kfile_close(kfile_fd_t fd);

#endif /* _KFILE_H_ */
