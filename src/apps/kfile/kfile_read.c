#include "kfile.h"
#include <string.h>

static inline void _decrypt_io_buf(kfile_t* kf, size_t nbyte)
{
	k_sc_update(kf->scipher, kf->iobuf, kf->iobuf, nbyte);
	k_hash_update(kf->hash_plaintext, kf->iobuf, nbyte);
}

ssize_t kfile_read(kfile_read_fd_t fd, void* buf, size_t nbyte)
{
	kfile_t* kf;
	ssize_t nread = 0;
	ssize_t total = 0;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	size_t blocks = (nbyte / kf->iobuf_size);
	size_t remaining = (nbyte % kf->iobuf_size);

	for (size_t i = 0; i < blocks; ++i) {
		nread = _kf_fill_io_buf(kf->fd, kf->iobuf, kf->iobuf_size);
		if (nread <= 0)
			return -1;
		_decrypt_io_buf(kf, kf->iobuf_size);
		memmove(buf+(i*kf->iobuf_size), kf->iobuf, kf->iobuf_size);
		total += nread;
	}
	if (remaining) {
		nread = _kf_fill_io_buf(kf->fd, kf->iobuf, remaining);
		if (nread <= 0)
			return -1;

		_decrypt_io_buf(kf, remaining);
		memmove(buf+(blocks*kf->iobuf_size), kf->iobuf, remaining);
		total += nread;
	}
	return total;
}
