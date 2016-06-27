#include "kfile.h"

void _kf_calculate_header_digest(void* kfile)
{
	kfile_t* kf = kfile;

	k_hash_update(kf->hash_plaintext,
		&kf->header.control, sizeof(kfile_control_header_t));

	k_hash_update(kf->hash_plaintext,
		&kf->header.kdf_header.kdf_salt_bytes, 1);

	k_hash_update(kf->hash_plaintext,
		kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1);

	k_hash_update(kf->hash_plaintext,
		&kf->header.iv_header.iv_bytes, 1);

	k_hash_update(kf->hash_plaintext,
		kf->header.iv_header.iv, kf->header.iv_header.iv_bytes+1);

	k_hash_final(kf->hash_plaintext, kf->headerdigest);
	k_hash_reset(kf->hash_plaintext);


	k_hash_update(kf->hash_ciphertext,
		&kf->header.control, sizeof(kfile_control_header_t));

	k_hash_update(kf->hash_ciphertext,
		&kf->header.kdf_header.kdf_salt_bytes, 1);

	k_hash_update(kf->hash_ciphertext,
		kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1);

	k_hash_update(kf->hash_ciphertext,
		&kf->header.iv_header.iv_bytes, 1);

	k_hash_update(kf->hash_ciphertext,
		kf->header.iv_header.iv, kf->header.iv_header.iv_bytes+1);
}
