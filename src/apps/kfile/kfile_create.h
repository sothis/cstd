#ifndef _KFILE_CREATE_H_
#define _KFILE_CREATE_H_

#define KFILE_MAX_RES_NAME_LENGTH	(256ull) /* 255 byte + 1 zero byte */
#define KFILE_MAX_PASSWORD_LENGTH	(256ull) /* 2048 bit */

typedef struct kfile_create_opts2_t {
	uint64_t	uuid;
	mode_t		file_mode;
	kfile_version_t	version;
	uint8_t		hash_function;
	/* digest size in bytes, be aware of encoding rules */
	uint16_t	digest_bytes;
	/* mustn't be zero, kfiles are always encrypted */
	uint8_t		cipher_function;
	/* If the used cipher is a plain streamcipher, set cipher_mode to 0.
	 * Otherwise only blockcipher modes are supported, that turn the
	 * specified blockcipher into a streamcipher (e.g. OFB, CTR or GCM) */
	uint8_t		cipher_mode;
	/* key size in bytes, be aware of encoding rules */
	uint16_t	key_bytes;
	/* mustn't be zero */
	uint8_t		kdf_function;
	/* determines complexity (amount of iterations) in steps from
	 * 0 to 255. we use that to map to a well defined list of 256
	 * integers which represent the count of iterations to be used
	 * in the KDF */
	uint8_t		kdf_complexity;
	/* mustn't be zero */
	size_t		iobuf_size;
	/* padded with zero bytes */
	char		resource_name[KFILE_MAX_RES_NAME_LENGTH];
	/* padded with zero bytes */
	char		low_entropy_pass[KFILE_MAX_PASSWORD_LENGTH];
} kfile_create_opts2_t;


#endif /* _KFILE_CREATE_H_ */