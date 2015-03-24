#ifndef _KFILE_ONDISK_H_
#define _KFILE_ONDISK_H_

/* NOTE: All uint8_t sizes in the on-disk structures are encoded as such:
 *		(uint_least16_t)real_size = sz_bytes + 1
 * 	This implies that a real_size of 0 is not allowed and the max real_size
 * 	that can be encoded is 256.
 *	Be aware that the resource name length is also encoded in this way
 * 	but it is still limited to 255 bytes at max to ensure that it
 * 	fits on most modern filesystems.
 */

typedef struct kfile_preamble_t {
	/* Magic and version are stored including the terminating zero byte
	 * on disk. */
	char		magic[6];
	char		version[4];
	uint64_t	cipher_data_bytes;
} __attribute__((packed)) kfile_preamble_t;

typedef struct kfile_control_header_t {
	uint8_t		hash_function;
	uint8_t		digest_bytes;
	uint8_t		cipher_function;
	uint8_t		cipher_mode;
	uint8_t		key_bytes;
	uint8_t		kdf_function;
	uint8_t		kdf_complexity;
} __attribute__((packed)) kfile_control_header_t;

typedef struct kfile_kdf_header_t {
	uint8_t		kdf_salt_bytes;
	unsigned char*	kdf_salt;
} __attribute__((packed)) kfile_kdf_header_t;

typedef struct kfile_iv_header_t {
	uint8_t		iv_bytes;
	unsigned char*	iv;
} __attribute__((packed)) kfile_iv_header_t;

/*	current layout (wip):
 *
 *	kfile_preamble_t
 *	kfile_control_header_t
 * 	kfile_kdf_header_t
 * 	kfile_iv_header_t
 * 	kfile_cipher_data_t
 *	kfile_cipher_mac_t
 *
 *
 * kfile_cipher_data_t consists of following:
 *	<header_mac[kfile_control_header_t.digest_bytes+1]>
 * 		(calculated over kfile_control_header_t,
 * 		kfile_kdf_header_t and kfile_iv_header_t)
 *	<uint8_t resourcename_len>
 *	<resourcename[resourcename_len+1]> // no zero byte termination
 *	<plain_text[unknown size]>
 *	<plain_text_mac[kfile_control_header_t.digest_bytes+1]>
*/

#endif /* _KFILE_ONDISK_H_ */
