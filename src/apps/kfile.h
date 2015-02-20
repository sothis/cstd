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

typedef struct kfile_header_t {
	/* Magic and version are stored including the terminating zero byte
	 * on disk. */
	char		magic[6];
	char		version[4];
	uint64_t	uuid;
	uint64_t	filesize;
	uint64_t	kdf_iterations;
	uint32_t	hashfunction;
	uint32_t	hashsize;
	uint32_t	cipher;
	uint32_t	ciphermode;
	uint32_t	keysize;

	uint8_t		kdf_salt[KFILE_MAX_IV_LENGTH];
	uint8_t		iv[KFILE_MAX_IV_LENGTH];
} __attribute__((packed)) kfile_header_t;
/* encrypted:
 * <headerdigest[128(1024bit)]>
 * <filename[256]>
 * <filedata>
 * <datadigest[128(1024bit)]>
*/

typedef struct kfile_t {
	int		fd;
	DIR*		path_ds;
	int		path_fd;
	k_hash_t*	hash;
	k_sc_t*		scipher;
	k_prng_t*	prng;

	size_t		noncebytes;
	char*		path;
	char*		filename;
	size_t		iobuf_size;
	unsigned char*	iobuf;
	unsigned char*	key;
	unsigned char	headerdigest[KFILE_MAX_DIGEST_LENGTH];
	unsigned char	datadigest[KFILE_MAX_DIGEST_LENGTH];
	kfile_header_t	header;
} kfile_t;

typedef struct kfile_create_opts_t {
	uint64_t	uuid;
	mode_t		filemode;
	kfile_version_t	version;
	uint32_t	hashfunction;
	/* Hashsize in bits.
	 * Might be 0 in order to use the default state size of the
	 * specified hash function. */
	uint32_t	hashsize;
	/* mustn't be zero, kfiles are always encrypted */
	uint32_t	cipher;
	/* If the used cipher is a plain streamcipher, set ciphermode to 0.
	 * Otherwise only blockcipher modes are supported, that turn the
	 * specified blockcipher into a streamcipher (e.g. OFB, CTR or GCM) */
	uint32_t	ciphermode;
	/* keysize in bits */
	uint32_t	keysize;
	/* mustn't be zero */
	uint64_t	kdf_iterations;
	/* mustn't be zero */
	size_t		iobuf_size;
	/* padded with zero bytes */
	char		filename[KFILE_MAX_NAME_LENGTH];
	/* padded with zero bytes */
	char		low_entropy_pass[KFILE_MAX_NAME_LENGTH];
} kfile_create_opts_t;

typedef struct kfile_open_opts_t {
	uint64_t	uuid;
	size_t		iobuf_size;
	char		low_entropy_pass[KFILE_MAX_NAME_LENGTH];
} kfile_open_opts_t;

typedef int kfile_write_fd_t;
typedef int kfile_read_fd_t;
typedef int kfile_fd_t;

kfile_write_fd_t kfile_create(kfile_create_opts_t* opts);
kfile_read_fd_t kfile_open(kfile_open_opts_t* opts);

int kfile_update(kfile_write_fd_t fd, const void *buf, size_t nbyte);
void kfile_final(kfile_write_fd_t fd);

int kfile_read(kfile_read_fd_t fd, const void *buf, size_t nbyte);

int kfile_close(kfile_fd_t fd);
