#include "cstd.h"
#include <libk/libk.h>

#define KFILE_MAGIC		("KFILE")
#define KFILE_MAX_NAME_LENGTH	(256ull)
#define KFILE_MAX_DIGEST_LENGTH	(128ull)
#define KFILE_MAX_IV_LENGTH	(128ull)
#define KFILE_KDF_ITERATIONS	(100000ull)
#define KFILE_IOBUF_SIZE	(65536ull)

typedef enum kfile_version_t {
	KFILE_VERSION_1_0	= 0,
	KFILE_VERSION_MAX
} kfile_version_t;

typedef struct kfile_header_t {
	/* Magic and version are stored including the terminating zero byte */
	char		magic[6];
	char		version[4];
	uint64_t	uuid;
//	uint64_t	filesize;
	uint64_t	kdf_iterations;
	uint32_t	hashfunction;
	uint32_t	hashsize;
	uint32_t	cipher;
	uint32_t	ciphermode;
	uint32_t	keysize;

	uint8_t		kdf_salt[KFILE_MAX_IV_LENGTH];
//	uint8_t		iv[KFILE_MAX_IV_LENGTH];

//	uint8_t		headerdigest[KFILE_MAX_DIGEST_LENGTH];
//	uint8_t		datadigest[KFILE_MAX_DIGEST_LENGTH];
} __attribute__((packed)) kfile_header_t;
/* <filename[256-1]><filedata> */

typedef struct kfile_t {
	int		fd;
	k_hash_t*	hash;
	k_sc_t*		scipher;
	k_prng_t*	prng;

	size_t		noncebytes;
	char		path[20];
	char		filename[5];
	unsigned char*	iobuf;
	unsigned char*	key;
	kfile_header_t	header;
} kfile_t;

typedef struct kfile_opts_t {
	uint64_t	uuid;
	mode_t		filemode;
	kfile_version_t	version;
	uint32_t	hashfunction;
	/* Hashsize in bits.
	 * Might be 0 in order to use the default state size of the
	 * specified hash function. */
	uint32_t	hashsize;
	/* if unencrypted set cipher to 0 */
	uint32_t	cipher;
	/* If the used cipher is a plain streamcipher, set ciphermode to 0.
	 * Otherwise only blockcipher modes are supported, that turn the
	 * specified blockcipher into a streamcipher (e.g. OFB, CTR or GCM) */
	uint32_t	ciphermode;
	/* keysize in bits */
	uint32_t	keysize;
	/* must be greater than zero */
	uint64_t	kdf_iterations;
	char		filename[KFILE_MAX_NAME_LENGTH];
	char		low_entropy_pass[KFILE_MAX_NAME_LENGTH];
} kfile_opts_t;

int kfile_create(kfile_opts_t* opts);
int kfile_close(int fd);
