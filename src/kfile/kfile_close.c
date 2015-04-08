#include "kfile.h"
#include "xio.h"
#include <stdlib.h>
#include <unistd.h>

int kfile_close(kfile_fd_t fd)
{
	kfile_t* kf;

	if (fd < 0)
		return -1;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	if (kf->header.kdf_header.kdf_salt)
		free(kf->header.kdf_header.kdf_salt);
	if (kf->header.iv_header.iv)
		free(kf->header.iv_header.iv);
	if (kf->hash_plaintext)
		k_hash_finish(kf->hash_plaintext);
	if (kf->hash_ciphertext)
		k_hash_finish(kf->hash_ciphertext);
	if (kf->prng)
		k_prng_finish(kf->prng);
	if (kf->scipher)
		k_sc_finish(kf->scipher);
	if (kf->key)
		free(kf->key);
	if (kf->iobuf)
		free(kf->iobuf);
	if (kf->headerdigest)
		free(kf->headerdigest);
	if (kf->datadigest)
		free(kf->datadigest);
	if (kf->cipherdigest)
		free(kf->cipherdigest);
	free(kf);

	return uuid_close_file(fd);
}

void kfile_write_digests_and_close(kfile_write_fd_t fd)
{
	kfile_t* kf;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	k_hash_final(kf->hash_plaintext, kf->datadigest);

	if (kfile_update(kf->fd, kf->datadigest, kf->digestbytes) < 0)
		pdie("KFILE kfile_update()");

	k_hash_final(kf->hash_ciphertext, kf->cipherdigest);

	if (xwrite(kf->fd, kf->cipherdigest, kf->digestbytes))
		pdie("KFILE unable to write checksum");

	if (lseek(kf->fd, 10, SEEK_SET) < 0)
		pdie("KFILE unable to set file pointer");
	if (xwrite(kf->fd, &kf->ciphersize, sizeof(kf->ciphersize)))
		pdie("KFILE unable to write filesize");

	kfile_close(fd);
}
