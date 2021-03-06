#include "kfile.h"
#include <string.h>
#include <unistd.h>

static inline void _encrypt_io_buf(kfile_t* kf, size_t nbyte)
{
	k_hash_update(kf->hash_plaintext, kf->iobuf, nbyte);
	k_sc_update(kf->scipher, kf->iobuf, kf->iobuf, nbyte);
	k_hash_update(kf->hash_ciphertext, kf->iobuf, nbyte);
}

ssize_t kfile_update(kfile_write_fd_t fd, const void *buf, size_t nbyte)
{
	kfile_t* kf;
	ssize_t nwritten = 0;
	ssize_t total = 0;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	size_t blocks = (nbyte / kf->iobuf_size);
	size_t remaining = (nbyte % kf->iobuf_size);

	for (size_t i = 0; i < blocks; ++i) {
		memmove(kf->iobuf, buf + (i * kf->iobuf_size), kf->iobuf_size);
		_encrypt_io_buf(kf, kf->iobuf_size);
		nwritten = _kf_store_io_buf(kf->fd, kf->iobuf, kf->iobuf_size);
		if (nwritten < 0)
			return -1;
		total += nwritten;
	}
	if (remaining) {
		memmove(kf->iobuf, buf+(blocks*kf->iobuf_size), remaining);
		_encrypt_io_buf(kf, remaining);
		nwritten = _kf_store_io_buf(kf->fd, kf->iobuf, remaining);
		if (nwritten < 0)
			return -1;
		total += nwritten;
	}
	kf->ciphersize += total;
	kf->plainsize += total;

	return total;
}

ssize_t _kfile_update_internal(kfile_write_fd_t fd, const void *buf, size_t nbyte)
{
	kfile_t* kf;
	ssize_t total = 0;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	total = kfile_update(fd, buf, nbyte);
	if (total != nbyte)
		return -1;

	/* ugly solution, fix this */
	kf->plainsize -= total;

	return total;
}
