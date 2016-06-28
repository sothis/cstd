#include "kfile.h"
#include "dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>

static int _check_cipherdigest(kfile_t* kf)
{
	ssize_t nread;
	unsigned char cipherdigest_chk[KFILE_SIZE_MAX];

	size_t blocks = kf->header.dyndata.cipher_data_bytes / kf->iobuf_size;
	size_t rem = kf->header.dyndata.cipher_data_bytes % kf->iobuf_size;

	for (size_t i = 0; i < blocks; ++i) {
		nread = _kf_fill_io_buf(kf->fd, kf->iobuf, kf->iobuf_size);
		if (nread <= 0)
			return -1;
		k_hash_update(kf->hash_ciphertext, kf->iobuf, nread);
	}
	if (rem) {
		nread = _kf_fill_io_buf(kf->fd, kf->iobuf, rem);
		if (nread <= 0)
			return -1;
		k_hash_update(kf->hash_ciphertext, kf->iobuf, nread);
	}

	k_hash_final(kf->hash_ciphertext, cipherdigest_chk);
	if (_kf_read_whole(kf->fd, kf->cipherdigest, kf->digestbytes) < 0)
		return -1;

	/* put read pointer back to cipher start */
	if (lseek(kf->fd, kf->cipherstart, SEEK_SET) < 0) {
		crit("KFILE lseek failed");
		return -1;
	}
	if (memcmp(kf->cipherdigest, cipherdigest_chk, kf->digestbytes)) {
		crit("KFILE cipher digest doesn't match");
		return -1;
	}

	return 0;
}

static void _kfile_init_algorithms_with_file(kfile_t* kf, kfile_open_opts_t* opts)
{
	unsigned char zero_nonce[KFILE_SIZE_MAX];
	uint64_t kdf_iterations = 0;

	memset(zero_nonce, 0, KFILE_SIZE_MAX);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		die("KFILE unable to initialize CSPRNG");

	kf->digestbytes = kf->header.control.digest_bytes + 1;
	kf->headerdigest = xcalloc(1, kf->digestbytes);
	kf->datadigest = xcalloc(1, kf->digestbytes);
	kf->cipherdigest = xcalloc(1, kf->digestbytes);

	kf->hash_plaintext = k_hash_init(kf->header.control.hash_function,
		kf->digestbytes * 8);
	if (!kf->hash_plaintext)
		die("KFILE unable to initialize hash function");

	kf->hash_ciphertext = k_hash_init(kf->header.control.hash_function,
		kf->digestbytes * 8);
	if (!kf->hash_ciphertext)
		die("KFILE unable to initialize hash function");

	if (!kf->header.control.cipher_mode) {
		/* plain streamcipher */
		kf->scipher = k_sc_init(kf->header.control.cipher_function,
			kf->header.control.key_bytes+1);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	if (kf->header.control.cipher_mode) {
		/* blockcipher with a mode that produces a keystream */
		if (k_bcmode_produces_keystream(
		kf->header.control.cipher_mode)	<= 0)
			die("KFILE blockcipher mode doesn't "
				"produce a keystream.");
		kf->scipher = k_sc_init_with_blockcipher(
			kf->header.control.cipher_function,
			kf->header.control.cipher_mode, 0);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);

	/* check iv and kdf_salt here against zero_nonce */

	kdf_iterations = kfile_get_iteration_count(kf->version,
		kf->header.control.kdf_complexity);

	kf->key = _k_key_derive_skein_1024(opts->low_entropy_pass,
		kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1,
		kf->header.control.key_bytes+1,
		kdf_iterations);
	if (!kf->key)
		pdie("KFILE _k_key_derive_skein_1024()");

	if (k_sc_set_key(kf->scipher, kf->header.iv_header.iv,
	kf->key, (kf->header.control.key_bytes + 1) * 8))
		pdie("KFILE k_sc_set_key()");
}

static int _kfile_read_and_check_file_header(kfile_t* kf, kfile_open_opts_t* opts)
{
	int		ver;
	unsigned char	headerdigest_chk[KFILE_SIZE_MAX];

	memset(headerdigest_chk, 0, KFILE_SIZE_MAX);

	if (kf->filesize < sizeof(kfile_header_t)) {
		crit("KFILE filesize lower than expected");
		return -1;
	}

	if (_kf_read_whole(kf->fd, &kf->header.preamble,
	sizeof(kfile_preamble_t)))
		pdie("_kf_read_whole()");

	if (strlen(kf->header.preamble.magic)+1 != sizeof(KFILE_MAGIC))
		return -1;

	if (strlen(kf->header.preamble.version)+1 != KFILE_VERSION_LENGTH)
		return -1;

	if (memcmp(kf->header.preamble.magic, KFILE_MAGIC, sizeof(KFILE_MAGIC)))
		return -1;

	ver = kfile_determine_version(kf->header.preamble.version);
	if (ver < 0)
		{ crit("KFILE unable to determine file version"); return -1; }
	kf->version = ver;

	if (_kf_read_whole(kf->fd, &kf->header.dyndata,
	sizeof(kfile_dynamic_data_header_t)))
		pdie("_kf_read_whole()");

	/* Test here if kf->dyndata.cipher_data_bytes fit into filesize! */
	printf("cipher size: %lu bytes\n", kf->header.dyndata.cipher_data_bytes);
	printf("plain size : %lu bytes\n", kf->header.dyndata.plain_data_bytes);

	if (_kf_read_whole(kf->fd, &kf->header.control,
	sizeof(kfile_control_header_t)))
		pdie("_kf_read_whole()");

	if (_kf_read_whole(kf->fd, &kf->header.kdf_header.kdf_salt_bytes, 1))
		pdie("_kf_read_whole()");

	kf->header.kdf_header.kdf_salt = calloc(1,
		kf->header.kdf_header.kdf_salt_bytes+1);
	if (!kf->header.kdf_header.kdf_salt)
		pdie("calloc");

	if (_kf_read_whole(kf->fd, kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1))
		pdie("_kf_read_whole()");

	if (_kf_read_whole(kf->fd, &kf->header.iv_header.iv_bytes, 1))
		pdie("_kf_read_whole()");

	kf->header.iv_header.iv = calloc(1, kf->header.iv_header.iv_bytes+1);
	if (!kf->header.iv_header.iv)
		pdie("calloc");

	if (_kf_read_whole(kf->fd, kf->header.iv_header.iv,
	kf->header.iv_header.iv_bytes+1))
		pdie("_kf_read_whole()");

	kf->cipherstart = sizeof(kfile_preamble_t) +
		sizeof(kfile_dynamic_data_header_t) +
		sizeof(kfile_control_header_t) +
		1 + (kf->header.kdf_header.kdf_salt_bytes+1) +
		1 + (kf->header.iv_header.iv_bytes+1);

	if (kf->header.control.hash_function >= HASHSUM_MAX)
		{ crit("KFILE unsupported digest algorithm"); return -1; }

	if (kf->header.control.cipher_mode) {
		if (kf->header.control.cipher_mode >= BLK_CIPHER_MODE_MAX) {
			crit("KFILE unsupported block cipher mode");
			return -1;
		}
		if (kf->header.control.cipher_function >= BLK_CIPHER_MAX) {
			crit("KFILE unsupported block cipher algorithm");
			return -1;
		}
	} else if (kf->header.control.cipher_function >= STREAM_CIPHER_MAX) {
		crit("KFILE unsupported stream cipher algorithm");
		return -1;
	}

	if (!kf->header.control.kdf_function)
		{ crit("KFILE kdf_function mustn't be zero"); return -1; }

	_kfile_init_algorithms_with_file(kf, opts);

	_kf_calculate_header_digest(kf);

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

	if (memcmp(kf->headerdigest, headerdigest_chk, kf->digestbytes)) {
		crit("KFILE header digest doesn't match");
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

	return 0;
}

/* TODO: do utf8 validity check on opts->low_entropy_pass */
kfile_read_fd_t kfile_open(kfile_open_opts_t* opts)
{
	struct stat st;
	kfile_t* kf;

	if (!opts)
		return -1;

	/* invalid layout */
	if ((!opts->layout) || (opts->layout >= KFILE_LAYOUT_MAX))
		return -1;

	if (!opts->iobuf_size)
		die("KFILE I/O buffer size mustn't be zero");

	if (!strlen(opts->low_entropy_pass))
		die("KFILE password empty");

	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf_size = opts->iobuf_size;
	kf->iobuf = xmalloc(opts->iobuf_size);
	kf->layout = opts->layout;
	kf->fs_layout = kfile_get_fsl_by_id(kf->layout);
	if (!kf->fs_layout)
		pdie("KFILE filesystem layout implementation not found");

	kf->fd = kf->fs_layout->open_file_ro(opts->uuid);
	if (kf->fd < 0)
		pdie("KFILE uuid_open_file_ro()");

	if (file_set_userdata(kf->fd, kf))
		die("KFILE file_set_userdata()");

	if (fstat(kf->fd, &st))
		pdie("KFILE fstat()");

	if (!S_ISREG(st.st_mode))
		die("KFILE not a regular file");

	kf->filesize = st.st_size;

	if (_kfile_read_and_check_file_header(kf, opts))
		die("KFILE corrupt file header or wrong password");

	return kf->fd;
}

