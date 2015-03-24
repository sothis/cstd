#include "kfile.h"
#include "xio.h"
#include "dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>


/* TODO: this is redundant, see kfile create.c */
static void _kfile_calculate_header_digest(kfile_t* kf)
{
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

static void _kfile_init_algorithms_with_file(kfile_t* kf, kfile_open_opts_t* opts)
{
	unsigned char zero_nonce[KFILE_SIZE_MAX];
	uint64_t kdf_iterations = 0;

	memset(zero_nonce, 0, KFILE_SIZE_MAX);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		die("KFILE unable to initialize CSPRNG");

	kf->digestbytes = kf->control.digest_bytes + 1;
	kf->headerdigest = xcalloc(1, kf->digestbytes);
	kf->datadigest = xcalloc(1, kf->digestbytes);
	kf->cipherdigest = xcalloc(1, kf->digestbytes);

	kf->hash_plaintext = k_hash_init(kf->control.hash_function,
		kf->digestbytes * 8);
	if (!kf->hash_plaintext)
		die("KFILE unable to initialize hash function");

	kf->hash_ciphertext = k_hash_init(kf->control.hash_function,
		kf->digestbytes * 8);
	if (!kf->hash_ciphertext)
		die("KFILE unable to initialize hash function");

	if (!kf->control.cipher_mode) {
		/* plain streamcipher */
		kf->scipher = k_sc_init(kf->control.cipher_function,
			kf->control.key_bytes+1);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	if (kf->control.cipher_mode) {
		/* blockcipher with a mode that produces a keystream */
		if (k_bcmode_produces_keystream(kf->control.cipher_mode) <= 0)
			die("KFILE blockcipher mode doesn't "
				"produce a keystream.");
		kf->scipher = k_sc_init_with_blockcipher(kf->control.cipher_function,
			kf->control.cipher_mode, 0);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);

	/* check iv and kdf_salt here against zero_nonce */

	kdf_iterations = kfile_get_iteration_count(kf->version,
		kf->control.kdf_complexity);

	kf->key = _k_key_derive_skein_1024(opts->low_entropy_pass,
		kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1,
		kf->control.key_bytes+1, kdf_iterations);
	if (!kf->key)
		pdie("KFILE _k_key_derive_skein_1024()");

	if (k_sc_set_key(kf->scipher, kf->iv_header.iv, kf->key, (kf->control.key_bytes + 1) * 8))
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
	kf->version = ver;

	if (xread(kf->fd, &kf->dyndata, sizeof(kfile_dynamic_data_header_t))
		!= sizeof(kfile_dynamic_data_header_t))
		pdie("xread()");

	if (xread(kf->fd, &kf->control, sizeof(kfile_control_header_t))
		!= sizeof(kfile_control_header_t))
		pdie("xread()");

	if (xread(kf->fd, &kf->kdf_header.kdf_salt_bytes, 1) != 1)
		pdie("xread()");

	kf->kdf_header.kdf_salt = calloc(1, kf->kdf_header.kdf_salt_bytes+1);
	if (!kf->kdf_header.kdf_salt)
		pdie("calloc");

	if (xread(kf->fd, kf->kdf_header.kdf_salt,
		kf->kdf_header.kdf_salt_bytes+1) !=
		kf->kdf_header.kdf_salt_bytes+1)
		pdie("xread()");

	if (xread(kf->fd, &kf->iv_header.iv_bytes, 1) != 1)
		pdie("xread()");

	kf->iv_header.iv = calloc(1, kf->iv_header.iv_bytes+1);
	if (!kf->iv_header.iv)
		pdie("calloc");

	if (xread(kf->fd, kf->iv_header.iv,
		kf->iv_header.iv_bytes+1) !=
		kf->iv_header.iv_bytes+1)
		pdie("xread()");

	if (kf->control.hash_function >= HASHSUM_MAX)
		{ crit("KFILE unsupported digest algorithm"); return -1; }

	if (kf->control.cipher_mode) {
		if (kf->control.cipher_mode >= BLK_CIPHER_MODE_MAX) {
			crit("KFILE unsupported block cipher mode");
			return -1;
		}
		if (kf->control.cipher_function >= BLK_CIPHER_MAX) {
			crit("KFILE unsupported block cipher algorithm");
			return -1;
		}
	} else if (kf->control.cipher_function >= STREAM_CIPHER_MAX) {
		crit("KFILE unsupported stream cipher algorithm");
		return -1;
	}

	if (!kf->control.kdf_function)
		{ crit("KFILE kdf_function mustn't be zero"); return -1; }

	_kfile_init_algorithms_with_file(kf, opts);


#if 0
	if (kf->filesize < (sizeof(kfile_header_t) + (3*kf->digestbytes) + 1)) {
		crit("KFILE filesize lower than expected");
		return -1;
	}
#endif

	_kfile_calculate_header_digest(kf);

#if 0
	if (opts->check_cipherdigest) {
		if (_check_cipherdigest(kf)) {
			crit("KFILE cipher digest doesn't match. source file "
			"was modified.");
			return -1;
		}
	}
#endif
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

