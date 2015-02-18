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

int _kfile_write_header(kfile_t* kf)
{



	return xwrite(kf->fd, &kf->header, sizeof(kfile_header_t));
}

int kfile_create(uint64_t uuid, const char* low_entropy_password)
{
	int fd;
	char path[20];
	char fname[5];
	kfile_t* kf;

	if (mkpath(uuid, fname, path)) {
		err("error creating path for given uuid ('%" PRIu64 "')", uuid);
		return -1;
	}

	fd = file_create_rw_with_hidden_tmp(fname, path, 0400);
	if (fd < 0)
		err("error creating file '%s' in directory '%s'", fname, path);


	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf = xmalloc(KFILE_IOBUF_SIZE);

	kf->fd = fd;
	strcpy(kf->header.magic, KFILE_MAGIC);
	strcpy(kf->header.version, KFILE_VERSION);
	kf->header.uuid = uuid;
	kf->header.hashfunction = HASHSUM_SKEIN_512;
	kf->header.hashsize = 512;
	kf->header.cipher = BLK_CIPHER_AES;
	kf->header.ciphermode = BLK_CIPHER_MODE_CTR;
	kf->header.keysize = 256;

	kf->hash = k_hash_init(kf->header.hashfunction, kf->header.hashsize);
	if (!kf->hash) {
		pdie("k_hash_init()");
	}
	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng) {
		pdie("k_prng_init()");
	}

	k_prng_update(kf->prng, kf->header.kdf_salt, KFILE_MAX_IV_LENGTH);
	kf->key = _k_key_derive_simple1024(low_entropy_password,
		kf->header.kdf_salt, KFILE_KDF_ITERATIONS);
	if (!kf->key) {
		pdie("_k_key_derive_simple1024()");
	}
	kf->scipher = k_sc_init_with_blockcipher(kf->header.cipher,
		kf->header.ciphermode, 0);
	if (!kf->scipher) {
		pdie("k_sc_init_with_blockcipher()");
	}
	kf->nonce_size = k_sc_get_nonce_bytes(kf->scipher);

	printf("nonce size: %u\n", kf->nonce_size);

	_kfile_write_header(kf);

	return fd;
}

int kfile_close(int fd)
{
	return file_sync_and_close(fd);
}
