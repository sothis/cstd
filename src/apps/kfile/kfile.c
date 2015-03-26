#include "cstd.h"
#include "kfile.h"
#include "xio.h"
#include "dir.h"

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

const char* kfile_get_resource_name(kfile_read_fd_t fd)
{
	kfile_t* kf;

	if (fd < 0)
		return 0;

	kf = file_get_userdata(fd);
	if (!kf)
		return 0;

	if (!strlen(kf->resourcename))
		return 0;

	return kf->resourcename;
}

int kfile_close(kfile_fd_t fd)
{
	kfile_t* kf;

	if (fd < 0)
		return -1;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");

	if (kf->kdf_header.kdf_salt)
		free(kf->kdf_header.kdf_salt);
	if (kf->iv_header.iv)
		free(kf->iv_header.iv);
	if (kf->path_ds)
		closedir(kf->path_ds);
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
	if (kf->filename)
		free(kf->filename);
	if (kf->path)
		free(kf->path);
	if (kf->headerdigest)
		free(kf->headerdigest);
	if (kf->datadigest)
		free(kf->datadigest);
	if (kf->cipherdigest)
		free(kf->cipherdigest);
	free(kf);

	return file_sync_and_close(fd);
}
