#ifndef _KFILE_H_
#define _KFILE_H_

#include "cstd.h"
#include <libk/libk.h>

#include <unistd.h>
#include <sys/types.h>
#include <dirent.h>

#define KFILE_MAX_NAME_LENGTH	(256ull) /* 255 byte + 1 zero byte */
#define KFILE_MAX_DIGEST_LENGTH	(128ull) /* 1024 bit */
#define KFILE_MAX_IV_LENGTH	(128ull) /* 1024 bit */

typedef enum kfile_version_t {
	KFILE_VERSION_0_1	= 0,
	KFILE_VERSION_1_0	= 1,
	KFILE_VERSION_MAX
} kfile_version_t;

#include "kfile_ondisk.h"
#include "kfile_create.h"

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

	size_t		filesize;
	size_t		noncebytes;
	size_t		digestbytes;
	char*		path;
	char*		filename;
	size_t		iobuf_size;
	unsigned char*	iobuf;
	unsigned char*	key;
	char		resourcename[KFILE_MAX_NAME_LENGTH];
	unsigned char	resourcename_len;
	unsigned char*	headerdigest;
	unsigned char*	datadigest;
	unsigned char*	cipherdigest;
	kfile_header_t	header;

	kfile_preamble_t	preamble;
	kfile_control_header_t	control;
	kfile_kdf_header_t	kdf_header;
	kfile_iv_header_t	iv_header;

} kfile_t;

typedef struct kfile_create_opts_t {
	uint64_t	uuid;
	mode_t		filemode;
	kfile_version_t	version;
	uint16_t	hashfunction;
	/* Hashsize in bits.
	 * Might be 0 in order to use the default state size of the
	 * specified hash function. */
	uint16_t	hashsize;
	/* mustn't be zero, kfiles are always encrypted */
	uint16_t	cipher;
	/* If the used cipher is a plain streamcipher, set ciphermode to 0.
	 * Otherwise only blockcipher modes are supported, that turn the
	 * specified blockcipher into a streamcipher (e.g. OFB, CTR or GCM) */
	uint16_t	ciphermode;
	/* keysize in bits */
	uint16_t	keysize;
	/* mustn't be zero */
	uint16_t	kdf_iterations;
	/* mustn't be zero */
	size_t		iobuf_size;
	/* padded with zero bytes */
	char		resourcename[KFILE_MAX_NAME_LENGTH];
	/* padded with zero bytes */
	char		low_entropy_pass[KFILE_MAX_NAME_LENGTH];
} kfile_create_opts_t;

typedef struct kfile_open_opts_t {
	uint64_t	uuid;
	size_t		iobuf_size;
	/* check cipher digest with kfile_open().
	 * might take a long time with very large encrypted resources. */
	uint32_t	check_cipherdigest;
	char		low_entropy_pass[KFILE_MAX_NAME_LENGTH];
} kfile_open_opts_t;


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

typedef int kfile_write_fd_t;
typedef int kfile_read_fd_t;
typedef int kfile_fd_t;

kfile_write_fd_t kfile_create(kfile_create_opts_t* opts);
kfile_write_fd_t kfile_create2(kfile_create_opts2_t* opts);
kfile_read_fd_t kfile_open(kfile_open_opts_t* opts);

int kfile_update(kfile_write_fd_t fd, const void* buf, size_t nbyte);
void kfile_write_digests_and_close(kfile_write_fd_t fd);

const char* kfile_get_resource_name(kfile_read_fd_t fd);
ssize_t kfile_read(kfile_read_fd_t fd, void* buf, size_t nbyte);

int kfile_close(kfile_fd_t fd);

#endif /* _KFILE_H_ */