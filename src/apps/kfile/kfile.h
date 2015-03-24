#ifndef _KFILE_H_
#define _KFILE_H_

#include "cstd.h"
#include <libk/libk.h>

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#define KFILE_MAX_NAME_LENGTH	(256ull) /* 255 byte + 1 zero byte */
#define KFILE_MAX_DIGEST_LENGTH	(128ull) /* 1024 bit */
#define KFILE_MAX_IV_LENGTH	(128ull) /* 1024 bit */

#define KFILE_MAX_RES_NAME_LENGTH	(256ull) /* 255 byte + 1 zero byte */
#define KFILE_MAX_PASSWORD_LENGTH	(256ull) /* 2048 bit */

#include "kfile_version.h"
#include "kfile_ondisk.h"
#include "kfile_kdf.h"
#include "kfile_create.h"
#include "kfile_open.h"

typedef struct kfile_header_t {
	/* Magic and version are stored including the terminating zero byte
	 * on disk. */
	char		magic[6];
	char		version[4];
	uint64_t	uuid;
	uint64_t	filesize;

	uint16_t	kdf_iterations;
	uint16_t	hashfunction;

	uint16_t	hashsize;
	uint16_t	cipher;

	uint16_t	ciphermode;
	uint16_t	keysize;

	uint8_t		kdf_salt[KFILE_MAX_IV_LENGTH];
	uint8_t		iv[KFILE_MAX_IV_LENGTH];
} __attribute__((packed)) kfile_header_t;
/* encrypted:
 * <headerdigest[(hashsize + 7 / 8)]>
 * <uint8_t resourcename_len><resourcename[resourcename_len]> // no zero byte termination
 * <filedata>
 * <datadigest[(hashsize + 7 / 8)]>
 * unencrypted:
 * <cipherdigest[(hashsize + 7 / 8)]>
*/

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
	//kfile_header_t	header;

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

typedef int kfile_fd_t;

void xuuid_to_path(uint64_t uuid, char** compl, char** fpath, char** fname);

int kfile_update(kfile_write_fd_t fd, const void* buf, size_t nbyte);
void kfile_write_digests_and_close(kfile_write_fd_t fd);

const char* kfile_get_resource_name(kfile_read_fd_t fd);
ssize_t kfile_read(kfile_read_fd_t fd, void* buf, size_t nbyte);

int kfile_close(kfile_fd_t fd);

#endif /* _KFILE_H_ */
