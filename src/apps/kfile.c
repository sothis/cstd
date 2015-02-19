#include "cstd.h"
#include "kfile.h"
#include "xio.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>

#include "libk/src/utils/dumphx.h"

#define KFILE_MAGIC		("KFILE")

/* index must map exactly to enum kfile_version_t */
static const char* kfile_version_strings[] = {
	"0.1",
	"1.0"
};

/* ugly, currently needed for _k_key_derive_simple1024() */
extern void k_free(void* mem);

int mkdirp(const char* path)
{
	char* p, *tok;
	int e;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	tok = strtok(p, "/");

	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			free(p);
			return -1;
		}
		if (chdir(tok)) {
			free(p);
			return -1;
		}
		tok = strtok(0, "/");
	}
	free(p);
	return 0;
}

int mkpath(uint64_t uuid, char* filename, char* pathname)
{
	int i, j;
	char uuid_ascii[20];
	char cpath[40];
	char path[20];
	char fname[5];
	char* cwd = 0;

	if (!filename || !pathname)
		return -1;

	memset(fname, 0, 5);
	memset(path, 0, 20);
	memset(cpath, 0, 40);
	memset(uuid_ascii, 0, 20);
	snprintf(uuid_ascii, 21, "%020" PRIu64 "", uuid);

	for (j = 0, i = 0; i <= 16; i += 4, j += 5) {
		if (i < 16) {
			path[j] = uuid_ascii[i];
			path[j+1] = uuid_ascii[i+1];
			path[j+2] = uuid_ascii[i+2];
			path[j+3] = uuid_ascii[i+3];
			if (i < 12)
				path[j+4] = '/';
		} else {
			fname[0] = uuid_ascii[i];
			fname[1] = uuid_ascii[i+1];
			fname[2] = uuid_ascii[i+2];
			fname[3] = uuid_ascii[i+3];
		}

		cpath[j] = uuid_ascii[i];
		cpath[j+1] = uuid_ascii[i+1];
		cpath[j+2] = uuid_ascii[i+2];
		cpath[j+3] = uuid_ascii[i+3];
		if (i < 16)
			cpath[j+4] = '/';
	}

	cwd = get_current_dir_name();
	if (!cwd) {
		err("could not get current working directory");
		return -1;
	}

	if (mkdirp(path)) {
		err("could not create whole path '%s'", path);
		chdir(cwd), free(cwd);
		return -1;
	}

	chdir(cwd), free(cwd);
	strcpy(filename, fname);
	strcpy(pathname, path);

	return 0;
}

static void _kfile_init_algorithms(kfile_t* kf, kfile_create_opts_t* opts)
{
	unsigned char zero_nonce[KFILE_MAX_IV_LENGTH];
	memset(zero_nonce, 0, KFILE_MAX_IV_LENGTH);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		die("KFILE unable to initialize CSPRNG");

	if (opts->hashfunction >= HASHSUM_MAX)
		die("KFILE hash function not supported");

	kf->hash = k_hash_init(kf->header.hashfunction, kf->header.hashsize);
	if (!kf->hash)
		die("KFILE unable to initialize hash function");

	if (!opts->cipher)
		die("KFILE no cipher specified");

	if (!opts->ciphermode) {
		/* plain streamcipher */
		if (opts->cipher >= STREAM_CIPHER_MAX)
			die("KFILE streamcipher not supported");
		kf->scipher = k_sc_init(opts->cipher, opts->keysize);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	if (opts->ciphermode) {
		/* blockcipher with a mode that produces a keystream */
		if (opts->cipher >= BLK_CIPHER_MAX)
			die("KFILE blockcipher not supported");
		if (opts->ciphermode >= BLK_CIPHER_MODE_MAX)
			die("KFILE blockcipher mode not supported");
		if (k_bcmode_produces_keystream(opts->ciphermode) <= 0)
			die("KFILE blockcipher mode doesn't "
				"produce a keystream.");
		kf->scipher = k_sc_init_with_blockcipher(opts->cipher,
			opts->ciphermode, 0);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);
	k_prng_update(kf->prng, kf->header.kdf_salt, KFILE_MAX_IV_LENGTH);
	while (!memcmp(kf->header.kdf_salt, zero_nonce, KFILE_MAX_IV_LENGTH)) {
		memset(kf->header.kdf_salt, 0, KFILE_MAX_IV_LENGTH);
		k_prng_update(kf->prng, kf->header.kdf_salt,
			KFILE_MAX_IV_LENGTH);
	}
	kf->key = _k_key_derive_simple1024(opts->low_entropy_pass,
		kf->header.kdf_salt, opts->kdf_iterations);
	if (!kf->key)
		pdie("KFILE _k_key_derive_simple1024()");

	k_prng_update(kf->prng, kf->header.iv, KFILE_MAX_IV_LENGTH);
	while (!memcmp(kf->header.iv, zero_nonce, kf->noncebytes)) {
		memset(kf->header.iv, 0, KFILE_MAX_IV_LENGTH);
		k_prng_update(kf->prng, kf->header.iv, kf->noncebytes);
	}
	k_sc_set_key(kf->scipher, kf->header.iv, kf->key, kf->header.keysize);
}

kfile_write_fd_t kfile_create(kfile_create_opts_t* opts)
{
	kfile_t* kf;

	if ((opts->version < 0) || (opts->version >= KFILE_VERSION_MAX))
		die("KFILE version out of bounds");

	if (!strlen(opts->low_entropy_pass))
		die("KFILE password empty");

	if (!strlen(opts->filename))
		die("KFILE filename empty");

	if (!opts->kdf_iterations)
		die("KFILE kdf iterations mustn't be zero");

	if (!opts->iobuf_size)
		die("KFILE I/O buffer size mustn't be zero");

	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf_size = opts->iobuf_size;
	kf->iobuf = xmalloc(opts->iobuf_size);

	strcpy(kf->header.magic, KFILE_MAGIC);
	strcpy(kf->header.version, kfile_version_strings[opts->version]);
	kf->header.uuid = opts->uuid;
	kf->header.hashfunction = opts->hashfunction;
	kf->header.hashsize = opts->hashsize;
	kf->header.cipher = opts->cipher;
	kf->header.ciphermode = opts->ciphermode;
	kf->header.keysize = opts->keysize;
	kf->header.kdf_iterations = opts->kdf_iterations;

	_kfile_init_algorithms(kf, opts);

	if (mkpath(opts->uuid, kf->filename, kf->path))
		pdie("KFILE mkpath() for uuid " PRIu64 "\n", opts->uuid);

	kf->fd = file_create_rw_with_hidden_tmp(kf->filename, kf->path,
		opts->filemode);
	if (kf->fd < 0)
		pdie("KFILE error creating file '%s' in directory '%s'",
			kf->filename, kf->path);

	if (xwrite(kf->fd, &kf->header, sizeof(kfile_header_t)))
		pdie("KFILE xwrite()");

	k_hash_update(kf->hash, &kf->header, sizeof(kfile_header_t));
	k_hash_final(kf->hash, kf->headerdigest);
//	dumphx("headerdigest", kf->headerdigest, 64);
	k_hash_reset(kf->hash);

	if (file_set_userdata(kf->fd, kf))
		die("KFILE file_set_userdata()");

	if (kfile_update(kf->fd, kf->headerdigest, KFILE_MAX_DIGEST_LENGTH))
		pdie("KFILE kfile_write()");

	if (kfile_update(kf->fd, opts->filename, KFILE_MAX_NAME_LENGTH))
		pdie("KFILE kfile_write()");

	return kf->fd;
}

int kfile_update(kfile_write_fd_t fd, const void *buf, size_t nbyte)
{
	kfile_t* kf;
	size_t filebytes = 0;
	ssize_t nwritten, total = 0;

	kf = file_get_userdata(fd);
	if (!kf)
		pdie("KFILE file_get_userdata()");

	size_t blocks = (nbyte / kf->iobuf_size);
	size_t remaining = (nbyte % kf->iobuf_size);

	for (size_t i = 0; i < blocks; ++i) {
		memmove(kf->iobuf, buf+(i*kf->iobuf_size), kf->iobuf_size);
		k_hash_update(kf->hash, kf->iobuf, kf->iobuf_size);
		k_sc_update(kf->scipher, kf->iobuf, kf->iobuf, kf->iobuf_size);
		while (total != kf->iobuf_size) {
			nwritten = write(kf->fd, kf->iobuf+total,
				kf->iobuf_size-total);
			if (nwritten < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			total += nwritten;
		}
	}
	filebytes += total;
	total = 0;
	if (remaining) {
		memmove(kf->iobuf, buf+(blocks*kf->iobuf_size), remaining);
		k_hash_update(kf->hash, kf->iobuf, remaining);
		k_sc_update(kf->scipher, kf->iobuf, kf->iobuf, remaining);
		while (total != remaining) {
			nwritten = write(kf->fd, kf->iobuf+total,
				remaining-total);
			if (nwritten < 0) {
				if (errno == EINTR)
					continue;
				return -1;
			}
			total += nwritten;
		}
	}
	filebytes += total;

	return 0;
}

void kfile_final(kfile_write_fd_t fd)
{
	kfile_t* kf;

	kf = file_get_userdata(fd);
	if (!kf)
		pdie("file_get_userdata()");

	k_hash_final(kf->hash, kf->datadigest);

	if (kfile_update(kf->fd, kf->datadigest, KFILE_MAX_DIGEST_LENGTH))
		pdie("KFILE kfile_write()");
}

kfile_read_fd_t kfile_open(kfile_open_opts_t* opts)
{
	return -1;
}

int kfile_close(kfile_fd_t fd)
{
	kfile_t* kf;

	if (fd < 0)
		return -1;

	kf = file_get_userdata(fd);
	if (!kf)
		pdie("file_get_userdata()");

	k_hash_finish(kf->hash);
	k_prng_finish(kf->prng);
	k_sc_finish(kf->scipher);
	k_free(kf->key);
	free(kf->iobuf);
	free(kf);

	return file_sync_and_close(fd);
}
