#include "kfile.h"
#include "xio.h"
#include "dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>


static int mkdirp(const char* path)
{
	char* p, *tok;
	int e, r = 0;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	if (dir_save_cwd())
		pdie("dir_save_cwd()");

	tok = strtok(p, "/");
	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			r = -1;
			goto out;
		}
		if (chdir(tok)) {
			r = -1;
			goto out;
		}
		tok = strtok(0, "/");
	}
	r = 0;
out:
	if (dir_restore_cwd())
		pdie("dir_restore_cwd()");
	free(p);
	return r;
}

void xuuid_to_path(uint64_t uuid, char** compl, char** fpath, char** fname)
{
	int i, j;
	char uuid_ascii[20];
	char cpath[40];
	char path[20];
	char name[5];

	memset(name, 0, 5);
	memset(path, 0, 20);
	memset(cpath, 0, 40);
	memset(uuid_ascii, 0, 20);
	snprintf(uuid_ascii, 21, "%020" PRIu64, uuid);

	for (j = 0, i = 0; i <= 16; i += 4, j += 5) {
		if (i < 16) {
			path[j] = uuid_ascii[i];
			path[j+1] = uuid_ascii[i+1];
			path[j+2] = uuid_ascii[i+2];
			path[j+3] = uuid_ascii[i+3];
			if (i < 12)
				path[j+4] = '/';
		} else {
			name[0] = uuid_ascii[i];
			name[1] = uuid_ascii[i+1];
			name[2] = uuid_ascii[i+2];
			name[3] = uuid_ascii[i+3];
		}

		cpath[j] = uuid_ascii[i];
		cpath[j+1] = uuid_ascii[i+1];
		cpath[j+2] = uuid_ascii[i+2];
		cpath[j+3] = uuid_ascii[i+3];
		if (i < 16)
			cpath[j+4] = '/';
	}

	if (compl)
		*compl = xstrdup(cpath);
	if (fpath)
		*fpath = xstrdup(path);
	if (fname)
		*fname = xstrdup(name);

	return;
}

static int _kfile_init_algorithms_with_opts
(kfile_t* kf, kfile_create_opts_t* opts)
{
	unsigned char zero_nonce[KFILE_SIZE_MAX];
	uint64_t kdf_iterations = 0;

	memset(zero_nonce, 0, KFILE_SIZE_MAX);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		return -1;

	kf->digestbytes = kf->header.control.digest_bytes + 1;
	kf->headerdigest = xcalloc(1, kf->digestbytes);
	kf->datadigest = xcalloc(1, kf->digestbytes);
	kf->cipherdigest = xcalloc(1, kf->digestbytes);

	kf->hash_plaintext = k_hash_init(opts->hash_function,
		opts->digest_bytes * 8);
	if (!kf->hash_plaintext)
		return -1;

	kf->hash_ciphertext = k_hash_init(opts->hash_function,
		opts->digest_bytes * 8);
	if (!kf->hash_ciphertext)
		return -1;

	if (!opts->cipher_mode) {
		/* plain stream cipher */
		kf->scipher = k_sc_init(opts->cipher_function, opts->key_bytes);
		if (!kf->scipher)
			return -1;
	}
	if (opts->cipher_mode) {
		/* block cipher */
		kf->scipher = k_sc_init_with_blockcipher(opts->cipher_function,
			opts->cipher_mode, 0);
		if (!kf->scipher)
			return -1;
	}

	kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);
	if (!kf->noncebytes || (kf->noncebytes > 256))
		return -1;
	kf->header.iv_header.iv_bytes = kf->noncebytes-1;
	kf->header.kdf_header.kdf_salt_bytes = kf->header.control.digest_bytes;

	kf->header.kdf_header.kdf_salt =
		xcalloc(kf->header.kdf_header.kdf_salt_bytes+1,
			sizeof(unsigned char));

	kf->header.iv_header.iv = xcalloc(kf->header.iv_header.iv_bytes+1,
		sizeof(unsigned char));


	k_prng_update(kf->prng, kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1);

	while (!memcmp(kf->header.kdf_header.kdf_salt, zero_nonce,
	kf->header.kdf_header.kdf_salt_bytes+1)) {
		k_prng_update(kf->prng, kf->header.kdf_header.kdf_salt,
			kf->header.kdf_header.kdf_salt_bytes+1);
	}

	kdf_iterations = kfile_get_iteration_count(opts->version,
		opts->kdf_complexity);

	kf->key = _k_key_derive_skein_1024(opts->low_entropy_pass,
		kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1,
		opts->key_bytes, kdf_iterations);
	if (!kf->key)
		return -1;

	k_prng_update(kf->prng, kf->header.iv_header.iv,
		kf->header.iv_header.iv_bytes+1);
	while (!memcmp(kf->header.iv_header.iv, zero_nonce,
	kf->header.iv_header.iv_bytes+1)) {
		k_prng_update(kf->prng, kf->header.iv_header.iv,
		kf->header.iv_header.iv_bytes+1);
	}

	if (k_sc_set_key(kf->scipher, kf->header.iv_header.iv,
		kf->key, opts->key_bytes * 8))
		return -1;

	return 0;
}

/* TODO: do utf8 validity check on opts->low_entropy_pass and
 * opts->resource_name */
static inline int check_create_opts(kfile_create_opts_t* opts)
{
	size_t len = 0;

	if (!opts)
		return -1;

	/* requested version not supported */
	if (opts->version >= KFILE_VERSION_MAX)
		return -1;

	/* empty password not allowed */
	if (!strlen(opts->low_entropy_pass))
		return -1;

	len = strlen(opts->resource_name);

	/* empty resource name not allowed */
	if (!len)
		return -1;

	/* resource name too long */
	if (len > 255)
		return -1;

	/* I/O buffer size mustn't be zero */
	if (!opts->iobuf_size)
		return -1;

	/* check if several sizes are non-zero and fit
	 * into uint8_t with special encoding */
	if (check_uint8_size(opts->digest_bytes))
		return -1;

	if (check_uint8_size(opts->key_bytes))
		return -1;

	/* hash_function mustn't be zero */
	if (!opts->hash_function)
		return -1;

	/* hash_function not supported */
	if (opts->hash_function >= HASHSUM_MAX)
		return -1;

	/* cipher_function mustn't be zero */
	if (!opts->cipher_function)
		return -1;

	/* plain stream cipher */
	if (!opts->cipher_mode) {
		/* cipher_function not supported */
		if (opts->cipher_function >= STREAM_CIPHER_MAX)
			return -1;
	}

	/* block cipher */
	if (opts->cipher_mode) {
		/* cipher_function not supported */
		if (opts->cipher_function >= BLK_CIPHER_MAX)
			return -1;
		/* cipher_mode not supported */
		if (opts->cipher_mode >= BLK_CIPHER_MODE_MAX)
			return -1;
		/* cipher_mode supported, but doesn't produce a key stream */
		if (k_bcmode_produces_keystream(opts->cipher_mode) <= 0)
			return -1;
	}

	/* kdf_function mustn't be zero */
	if (!opts->kdf_function)
		return -1;

	/* kdf_function not supported */
	if (opts->kdf_function >= KDF_MAX)
		return -1;

	return 0;
}

kfile_write_fd_t kfile_create(kfile_create_opts_t* opts)
{
	kfile_t* kf = 0;

	if (check_create_opts(opts))
		goto err;


	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf_size = opts->iobuf_size;
	kf->iobuf = xmalloc(opts->iobuf_size);

	strcpy(kf->header.preamble.magic, KFILE_MAGIC);
	strcpy(kf->header.preamble.version,
		kfile_version_string(opts->version));

	kf->header.control.hash_function = opts->hash_function;
	kf->header.control.cipher_function = opts->cipher_function;
	kf->header.control.cipher_mode = opts->cipher_mode;
	kf->header.control.kdf_function = opts->kdf_function;
	kf->header.control.kdf_complexity = opts->kdf_complexity;

	assign_uint8_size(&kf->header.control.digest_bytes,
		opts->digest_bytes);
	assign_uint8_size(&kf->header.control.key_bytes, opts->key_bytes);

	kf->resourcename_len = strlen(opts->resource_name);

	_kfile_init_algorithms_with_opts(kf, opts);

	xuuid_to_path(opts->uuid, 0, &kf->path, &kf->filename);
	if (mkdirp(kf->path))
		pdie("KFILE mkdirp() for uuid " PRIu64 "\n", opts->uuid);

	kf->fd = file_create_rw_with_hidden_tmp(kf->filename, kf->path,
		opts->file_mode);
	if (kf->fd < 0)
		pdie("KFILE error creating file '%s' in directory '%s'",
			kf->filename, kf->path);

	if (file_set_userdata(kf->fd, kf))
		die("KFILE file_set_userdata()");

	if (xwrite(kf->fd, &kf->header.preamble, sizeof(kfile_preamble_t)))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->header.dyndata,
		sizeof(kfile_dynamic_data_header_t)))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->header.control, sizeof(kfile_control_header_t)))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->header.kdf_header.kdf_salt_bytes, 1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, kf->header.kdf_header.kdf_salt,
		kf->header.kdf_header.kdf_salt_bytes+1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->header.iv_header.iv_bytes, 1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, kf->header.iv_header.iv,
		kf->header.iv_header.iv_bytes+1))
		pdie("KFILE can't write file header");

	_kf_calculate_header_digest(kf);

	if (kfile_update(kf->fd, kf->headerdigest, kf->digestbytes) < 0)
		pdie("KFILE kfile_update(kf->headerdigest)");

	if (kfile_update(kf->fd, &kf->resourcename_len, 1) < 0)
		pdie("KFILE kfile_update(kf->resourcename_len)");

	if (kfile_update(kf->fd, opts->resource_name, kf->resourcename_len) < 0)
		pdie("KFILE kfile_update(opts->resourcename)");

	return kf->fd;
err:
	if (kf) {
		if (kf->iobuf)
			free(kf->iobuf);
		free(kf);
	}
	return -1;
}
