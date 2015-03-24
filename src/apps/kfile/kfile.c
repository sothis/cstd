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

#include "libk/src/utils/dumphx.h"

/* bits to bytes with possible padding zero-bits */
#define BITSTOBYTES(x)		(((x + 7) / 8))


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
#if 0
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
#endif
#if 0
static void _kfile_calculate_header_digest(kfile_t* kf)
{
	k_hash_update(kf->hash_plaintext, &kf->header, sizeof(kfile_header_t));
	k_hash_final(kf->hash_plaintext, kf->headerdigest);
	k_hash_reset(kf->hash_plaintext);
	/* including the complete header (IV is most important here)
	 * in the cipherdigest, which is appended at the end of the file */
	k_hash_update(kf->hash_ciphertext, &kf->header, sizeof(kfile_header_t));
}
#endif
#if 0
static void _kfile_init_algorithms_with_file(kfile_t* kf, kfile_open_opts_t* opts)
{
	unsigned char zero_nonce[KFILE_MAX_IV_LENGTH];
	memset(zero_nonce, 0, KFILE_MAX_IV_LENGTH);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		die("KFILE unable to initialize CSPRNG");

	if (!kf->header.hashsize || (kf->header.hashsize > 1024))
		die("KFILE invalid hash size specified");

	kf->digestbytes = BITSTOBYTES(kf->header.hashsize);
	kf->headerdigest = xcalloc(1, kf->digestbytes);
	kf->datadigest = xcalloc(1, kf->digestbytes);
	kf->cipherdigest = xcalloc(1, kf->digestbytes);

	kf->hash_plaintext = k_hash_init(kf->header.hashfunction,
		kf->header.hashsize);
	if (!kf->hash_plaintext)
		die("KFILE unable to initialize hash function");

	kf->hash_ciphertext = k_hash_init(kf->header.hashfunction,
		kf->header.hashsize);
	if (!kf->hash_ciphertext)
		die("KFILE unable to initialize hash function");

	if (!kf->header.ciphermode) {
		/* plain streamcipher */
		kf->scipher = k_sc_init(kf->header.cipher, kf->header.keysize);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	if (kf->header.ciphermode) {
		/* blockcipher with a mode that produces a keystream */
		if (k_bcmode_produces_keystream(kf->header.ciphermode) <= 0)
			die("KFILE blockcipher mode doesn't "
				"produce a keystream.");
		kf->scipher = k_sc_init_with_blockcipher(kf->header.cipher,
			kf->header.ciphermode, 0);
		if (!kf->scipher)
			die("KFILE unable to initialize stream cipher");
	}

	kf->noncebytes = k_sc_get_nonce_bytes(kf->scipher);

	/* check iv and kdf_salt here against zero_nonce */

	kf->key = _k_key_derive_simple1024(opts->low_entropy_pass,
		kf->header.kdf_salt, 128, kf->header.kdf_iterations);
	if (!kf->key)
		pdie("KFILE _k_key_derive_simple1024()");

	if (k_sc_set_key(kf->scipher, kf->header.iv, kf->key,
	kf->header.keysize))
		die("KFILE unable to set stream cipher key");
}
#endif

void _encrypt_io_buf(kfile_t* kf, size_t nbyte)
{
	k_hash_update(kf->hash_plaintext, kf->iobuf, nbyte);
	k_sc_update(kf->scipher, kf->iobuf, kf->iobuf, nbyte);
	k_hash_update(kf->hash_ciphertext, kf->iobuf, nbyte);
}

ssize_t _store_io_buf(kfile_t* kf, size_t nbyte)
{
	ssize_t nwritten = 0;
	ssize_t total = 0;

	while (total != nbyte) {
		nwritten = write(kf->fd, kf->iobuf + total, nbyte - total);
		if (nwritten < 0) {
			if (errno == EINTR)
				continue;
			else return nwritten;
		}
		total += nwritten;
	}
	return total;
}

int kfile_update(kfile_write_fd_t fd, const void *buf, size_t nbyte)
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
		nwritten = _store_io_buf(kf, kf->iobuf_size);
		if (nwritten < 0)
			return -1;
		total += nwritten;
	}
	if (remaining) {
		memmove(kf->iobuf, buf+(blocks*kf->iobuf_size), remaining);
		_encrypt_io_buf(kf, remaining);
		nwritten = _store_io_buf(kf, remaining);
		if (nwritten < 0)
			return -1;
		total += nwritten;
	}
	kf->ciphersize += total;

	return total;
}

ssize_t _fill_io_buf(kfile_t* kf, size_t nbyte)
{
	ssize_t nread = 0;
	ssize_t total = 0;

	while (total != nbyte) {
		nread = read(kf->fd, kf->iobuf + total, nbyte - total);
		if (nread < 0) {
			if (errno == EINTR)
				continue;
			else return nread;
		}
		if (nread == 0) {
			/* shall not happen */
			return -1;
		}
		total += nread;
	}
	return total;
}

void _decrypt_io_buf(kfile_t* kf, size_t nbyte)
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
		nread = _fill_io_buf(kf, kf->iobuf_size);
		if (nread <= 0)
			return -1;
		_decrypt_io_buf(kf, kf->iobuf_size);
		memmove(buf+(i*kf->iobuf_size), kf->iobuf, kf->iobuf_size);
		total += nread;
	}
	if (remaining) {
		nread = _fill_io_buf(kf, remaining);
		if (nread <= 0)
			return -1;

		_decrypt_io_buf(kf, remaining);
		memmove(buf+(blocks*kf->iobuf_size), kf->iobuf, remaining);
		total += nread;
	}
	return total;
}

void kfile_write_digests_and_close(kfile_write_fd_t fd)
{
	kfile_t* kf;

	kf = file_get_userdata(fd);
	if (!kf)
		die("KFILE file_get_userdata()");
#if 1
	k_hash_final(kf->hash_plaintext, kf->datadigest);

	if (kfile_update(kf->fd, kf->datadigest, kf->digestbytes) < 0)
		pdie("KFILE kfile_update()");

	k_hash_final(kf->hash_ciphertext, kf->cipherdigest);

	if (xwrite(kf->fd, kf->cipherdigest, kf->digestbytes))
		pdie("KFILE unable to write checksum");
#endif
#if 1
	if (lseek(kf->fd, 10, SEEK_SET) < 0)
		pdie("KFILE unable to set file pointer");
	if (xwrite(kf->fd, &kf->ciphersize, sizeof(kf->ciphersize)))
		pdie("KFILE unable to write filesize");
#endif
	kfile_close(fd);
}

static int _kfile_determine_version(kfile_t* kf)
{
	int ver;

	for(ver = 0; ver < KFILE_VERSION_MAX; ver++) {
//		if (!strcmp(kf->header.version, kfile_version_strings[ver]))
//			return ver;
	}

	return -1;
}

static int _check_cipherdigest(kfile_t* kf)
{
	ssize_t nread;
	unsigned char cipherdigest_chk[KFILE_MAX_DIGEST_LENGTH];
	size_t ciphertextsize = kf->filesize - sizeof(kfile_header_t) -
		kf->digestbytes;
	size_t blocks = ciphertextsize / kf->iobuf_size;
	size_t remaining = ciphertextsize % kf->iobuf_size;

	for (size_t i = 0; i < blocks; ++i) {
		nread = _fill_io_buf(kf, kf->iobuf_size);
		if (nread <= 0)
			return -1;
		k_hash_update(kf->hash_ciphertext, kf->iobuf, nread);
	}
	if (remaining) {
		nread = _fill_io_buf(kf, remaining);
		if (nread <= 0)
			return -1;
		k_hash_update(kf->hash_ciphertext, kf->iobuf, nread);
	}

	k_hash_final(kf->hash_ciphertext, cipherdigest_chk);
	if (xread(kf->fd, kf->cipherdigest, kf->digestbytes) < 0)
		return -1;

	/* put read pointer back to cipher start */
	if (lseek(kf->fd, sizeof(kfile_header_t), SEEK_SET) < 0) {
		crit("KFILE lseek failed");
		return -1;
	}
	if (memcmp(kf->cipherdigest, cipherdigest_chk, kf->digestbytes)) {
		crit("KFILE cipher digest doesn't match");
		return -1;
	}

	return 0;
}
#if 0
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

	if (xread(kf->fd, &kf->header, sizeof(kfile_header_t))
		!= sizeof(kfile_header_t))
		pdie("xread()");

	if (strlen(kf->header.magic)+1 != sizeof(KFILE_MAGIC))
		return -1;

	if (strlen(kf->header.version)+1 != KFILE_VERSION_LENGTH)
		return -1;

	if (memcmp(kf->header.magic, KFILE_MAGIC, sizeof(KFILE_MAGIC)))
		return -1;

	ver = _kfile_determine_version(kf);
	if (ver < 0)
		{ crit("KFILE unable to determine file version"); return -1; }

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
	return 0;
}
#endif
#if 0
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
#endif
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
