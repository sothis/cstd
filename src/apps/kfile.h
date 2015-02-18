#include "cstd.h"
#include <libk/libk.h>

#define KFILE_MAGIC		("KFILE")
#define KFILE_VERSION		("1.0")
#define KFILE_MAX_NAME_LENGTH	(256ull)
#define KFILE_MAX_DIGEST_LENGTH	(128ull)
#define KFILE_MAX_IV_LENGTH	(128ull)
#define KFILE_KDF_ITERATIONS	(100000ull)
#define KFILE_IOBUF_SIZE	(65536ull)

typedef struct kfile_header_t {
	/* magic and version are stored including der terminating zero byte */
	char		magic[6];
	char		version[4];
	uint64_t	uuid;
//	uint64_t	filesize;
	/* used hashfunction and hashsize, _all_ digests are calculated
	 * with that function. NOTE: string digests are calculated including
	 * the terminating zero byte. */
	uint32_t	hashfunction;
	/* note: hashsize in bits might be 0 in order to use the default state
	 * size of the specified hashfunction */
	uint32_t	hashsize;
	/* if unencrypted set cipher to 0 */
	uint32_t	cipher;
	/* if the used cipher is a plain streamcipher, set ciphermode to 0 */
	uint32_t	ciphermode;
	/* keysize in bits */
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

	uint32_t	nonce_size;
	unsigned char*	iobuf;
	unsigned char*	key;
	kfile_header_t	header;
} kfile_t;

int kfile_create(uint64_t uuid, const char* pass);
int kfile_close(int fd);
