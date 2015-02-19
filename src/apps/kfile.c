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

/* index must map exactly to enum kfile_version_t */
static const char* kfile_version_strings[] = {
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

static void _kfile_init_algortithms(kfile_t* kf, kfile_opts_t* opts)
{
	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng) {
		pdie("KFILE unable to initialize CSPRNG");
	}
	if (opts->hashfunction >= HASHSUM_MAX)
		die("KFILE hash function not supported");
	kf->hash = k_hash_init(kf->header.hashfunction, kf->header.hashsize);
	if (!kf->hash) {
		pdie("KFILE unable to initialize hash function");
	}

	if (opts->cipher >= BLK_CIPHER_MODE_MAX)
		die("KFILE cipher not supported");
	if (opts->cipher && !opts->ciphermode) {
		/* plain streamcipher */
		if (opts->cipher >= STREAM_CIPHER_MAX)
			die("KFILE streamcipher not supported");
		kf->scipher = k_sc_init(opts->cipher, opts->keysize);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}
	if (opts->cipher && opts->ciphermode) {
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

	if (kf->scipher)
		kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);
}

int kfile_create(kfile_opts_t* opts)
{
	kfile_t* kf;

	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf = xmalloc(KFILE_IOBUF_SIZE);

	if ((opts->version < 0) || (opts->version >= KFILE_VERSION_MAX))
		die("KFILE version out of bounds");

	if (!strlen(opts->low_entropy_pass))
		die("KFILE password empty");

	if (!strlen(opts->filename))
		die("KFILE filename empty");

	if (!opts->kdf_iterations)
		die("KFILE kdf iterations mustn't be zero");

	strcpy(kf->header.magic, KFILE_MAGIC);
	strcpy(kf->header.version, kfile_version_strings[opts->version]);
	kf->header.uuid = opts->uuid;
	kf->header.hashfunction = opts->hashfunction;
	kf->header.hashsize = opts->hashsize;
	kf->header.cipher = opts->cipher;
	kf->header.ciphermode = opts->ciphermode;
	kf->header.keysize = opts->keysize;
	kf->header.kdf_iterations = opts->kdf_iterations;

	_kfile_init_algortithms(kf, opts);

	k_prng_update(kf->prng, kf->header.kdf_salt, KFILE_MAX_IV_LENGTH);
	kf->key = _k_key_derive_simple1024(opts->low_entropy_pass,
		kf->header.kdf_salt, opts->kdf_iterations);
	if (!kf->key)
		pdie("_k_key_derive_simple1024()");

	if (mkpath(opts->uuid, kf->filename, kf->path))
		pdie("mkpath() for uuid " PRIu64 "\n", opts->uuid);

	kf->fd = file_create_rw_with_hidden_tmp(kf->filename, kf->path,
		opts->filemode);
	if (kf->fd < 0)
		pdie("error creating file '%s' in directory '%s'",
			kf->filename, kf->path);

	if (xwrite(kf->fd, &kf->header, sizeof(kfile_header_t)))
		pdie("xwrite()");

	if (file_set_userdata(kf->fd, kf))
		pdie("file_set_userdata()");

	return kf->fd;
}

int kfile_close(int fd)
{
	kfile_t* kf;

	kf = file_get_userdata(fd);
	if (!kf) {
		pdie("file_get_userdata()");
	}

	k_hash_finish(kf->hash);
	k_prng_finish(kf->prng);
	k_sc_finish(kf->scipher);
	k_free(kf->key);
	free(kf->iobuf);
	free(kf);

	return file_sync_and_close(fd);
}
