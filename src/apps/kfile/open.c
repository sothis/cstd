#include "kfile.h"
#include "xio.h"
#include "dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>


//#include "cstd.h"





#include <unistd.h>
#include <fcntl.h>



/* bits to bytes with possible padding zero-bits */
#define BITSTOBYTES(x)		(((x + 7) / 8))


static int _kfile_read_and_check_file_header(kfile_t* kf, kfile_open_opts_t* opts)
{
	int		ver;
	char		filename[KFILE_MAX_NAME_LENGTH];
	unsigned char	headerdigest_chk[KFILE_MAX_DIGEST_LENGTH];

	memset(filename ,0, KFILE_MAX_NAME_LENGTH);
	memset(headerdigest_chk, 0, KFILE_MAX_DIGEST_LENGTH);

	if (kf->filesize < sizeof(kfile_header_t)) {
		crit("KFILE filesize lower than expected");
		return -1;
	}

	if (xread(kf->fd, &kf->preamble, sizeof(kfile_preamble_t))
		!= sizeof(kfile_preamble_t))
		pdie("xread()");

	if (strlen(kf->preamble.magic)+1 != sizeof(KFILE_MAGIC))
		return -1;

	if (strlen(kf->preamble.version)+1 != KFILE_VERSION_LENGTH)
		return -1;

	if (memcmp(kf->preamble.magic, KFILE_MAGIC, sizeof(KFILE_MAGIC)))
		return -1;

	ver = kfile_determine_version(kf->preamble.version);
	if (ver < 0)
		{ crit("KFILE unable to determine file version"); return -1; }
#if 0
	if (kf->header.hashfunction >= HASHSUM_MAX)
		{ crit("KFILE unsupported digest algorithm"); return -1; }

	if (kf->header.ciphermode) {
		if (kf->header.ciphermode >= BLK_CIPHER_MODE_MAX) {
			crit("KFILE unsupported block cipher mode");
			return -1;
		}
		if (kf->header.cipher >= BLK_CIPHER_MAX) {
			crit("KFILE unsupported block cipher algorithm");
			return -1;
		}
	} else if (kf->header.cipher >= STREAM_CIPHER_MAX) {
		crit("KFILE unsupported stream cipher algorithm");
		return -1;
	}

	if (opts->uuid != kf->header.uuid)
		{ crit("KFILE UUID doesn't match requested one"); return -1; }

	if (!kf->header.kdf_iterations)
		{ crit("KFILE kdf iterations mustn't be zero"); return -1; }

	_kfile_init_algorithms_with_file(kf, opts);

	if (kf->filesize < (sizeof(kfile_header_t) + (3*kf->digestbytes) + 1)) {
		crit("KFILE filesize lower than expected");
		return -1;
	}

	_kfile_calculate_header_digest(kf);

	if (opts->check_cipherdigest) {
		if (_check_cipherdigest(kf)) {
			crit("KFILE cipher digest doesn't match. source file "
			"was modified.");
			return -1;
		}
	}

	if (kfile_read(kf->fd, headerdigest_chk, kf->digestbytes) < 0) {
		crit("KFILE unable to read header digest from file");
		return -1;
	}

	if (kfile_read(kf->fd, &kf->resourcename_len, 1) < 0) {
		crit("KFILE unable to read resource name size from file");
		return -1;
	}

	if (!kf->resourcename_len) {
		crit("KFILE resource name size mustn't be zero.");
		return -1;
	}

	if (kfile_read(kf->fd, kf->resourcename, kf->resourcename_len) < 0) {
		crit("KFILE unable to read resource name from file");
		return -1;
	}

	if (memcmp(kf->headerdigest, headerdigest_chk, kf->digestbytes)) {
		crit("KFILE header digest doesn't match");
		return -1;
	}
#endif
	return 0;
}

kfile_read_fd_t kfile_open(kfile_open_opts_t* opts)
{
	struct stat st;
	kfile_t* kf;

	if (!opts->iobuf_size)
		die("KFILE I/O buffer size mustn't be zero");

	if (!strlen(opts->low_entropy_pass))
		die("KFILE password empty");

	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf_size = opts->iobuf_size;
	kf->iobuf = xmalloc(opts->iobuf_size);

	xuuid_to_path(opts->uuid, 0, &kf->path, &kf->filename);

	kf->path_ds = opendir(kf->path);
	if (!kf->path_ds)
		die("KFILE opendir()");

	kf->path_fd = dirfd(kf->path_ds);
	if (kf->path_fd < 0)
		die("KFILE dirfd()");

	kf->fd = openat(kf->path_fd, kf->filename, O_RDONLY | O_NOATIME);
	if (kf->fd < 0)
		pdie("KFILE openat()");

	if (fstat(kf->fd, &st))
		pdie("KFILE fstat()");

	if (!S_ISREG(st.st_mode))
		die("KFILE not a regular file");

	kf->filesize = st.st_size;

	file_register_fd(kf->fd, kf->path, kf->filename);

	if (file_set_userdata(kf->fd, kf))
		die("KFILE file_set_userdata()");

	if (_kfile_read_and_check_file_header(kf, opts))
		die("KFILE corrupt or invalid file header");

	return kf->fd;
}

