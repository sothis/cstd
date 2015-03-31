#include "kfile.h"
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

ssize_t _kf_fill_io_buf(int fd, unsigned char* buf, size_t nbyte)
{
	ssize_t nread = 0;
	ssize_t total = 0;

	while (total != nbyte) {
		nread = read(fd, buf + total, nbyte - total);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			else return nread;
		}
		if (nread == 0) {
			/* shall not happen */
			return -1;
		}
		total += nread;
	}
	return total;
}

void _kf_calculate_header_digest(void* kfile)
{
	kfile_t* kf = kfile;

	k_hash_update(kf->hash_plaintext, &kf->control, sizeof(kfile_control_header_t));

	k_hash_update(kf->hash_plaintext, &kf->kdf_header.kdf_salt_bytes, 1);
	k_hash_update(kf->hash_plaintext, kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1);

	k_hash_update(kf->hash_plaintext, &kf->iv_header.iv_bytes, 1);
	k_hash_update(kf->hash_plaintext, kf->iv_header.iv, kf->iv_header.iv_bytes+1);

	k_hash_final(kf->hash_plaintext, kf->headerdigest);
	k_hash_reset(kf->hash_plaintext);


	k_hash_update(kf->hash_ciphertext, &kf->control, sizeof(kfile_control_header_t));

	k_hash_update(kf->hash_ciphertext, &kf->kdf_header.kdf_salt_bytes, 1);
	k_hash_update(kf->hash_ciphertext, kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1);

	k_hash_update(kf->hash_ciphertext, &kf->iv_header.iv_bytes, 1);
	k_hash_update(kf->hash_ciphertext, kf->iv_header.iv, kf->iv_header.iv_bytes+1);
}
