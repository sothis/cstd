#include "kfile.h"
#include "xio.h"
#include "dir.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <inttypes.h>

#define KFILE_MAGIC		("KFILE")
#define KFILE_VERSION_LENGTH	(4)

/* index must map exactly to enum kfile_version_t */
static const char* kfile_version_strings[] = {
	"0.1",
	"1.0"
};

static const uint32_t primes_5_digit[256] = {
	10303, 10627, 10937, 11251, 11551, 11887, 12161, 12473,
	12739, 13033, 13337, 13681, 13933, 14323, 14627, 14887,
	15217, 15473, 15773, 16087, 16427, 16747, 17053, 17389,
	17683, 17989, 18289, 18593, 19009, 19373, 19603, 19961,
	20233, 20551, 20903, 21193, 21523, 21821, 22123, 22453,
	22769, 23063, 23417, 23743, 24023, 24359, 24709, 25073,
	25391, 25717, 26029, 26357, 26699, 26987, 27361, 27737,
	28001, 28387, 28649, 28961, 29303, 29633, 30029, 30341,
	30703, 31039, 31321, 31687, 32063, 32363, 32647, 32987,
	33329, 33613, 33923, 34297, 34603, 34939, 35291, 35603,
	35999, 36341, 36677, 36947, 37321, 37607, 37993, 38333,
	38713, 39047, 39367, 39727, 40039, 40433, 40813, 41141,
	41453, 41771, 42073, 42397, 42701, 43013, 43427, 43783,
	44119, 44497, 44797, 45161, 45533, 45869, 46261, 46601,
	46933, 47317, 47653, 47969, 48371, 48679, 49033, 49367,
	49697, 50033, 50359, 50753, 51133, 51439, 51767, 52103,
	52501, 52837, 53161, 53549, 53881, 54269, 54559, 54919,
	55291, 55663, 55949, 56333, 56659, 56951, 57269, 57653,
	57977, 58313, 58679, 59029, 59359, 59669, 60083, 60443,
	60779, 61169, 61553, 61927, 62233, 62633, 62989, 63389,
	63671, 64019, 64439, 64849, 65171, 65539, 65837, 66191,
	66593, 66949, 67273, 67601, 67943, 68371, 68737, 69119,
	69467, 69899, 70223, 70573, 70937, 71263, 71563, 71933,
	72253, 72649, 72973, 73379, 73721, 74131, 74449, 74797,
	75181, 75533, 75853, 76249, 76607, 77003, 77351, 77659,
	78017, 78427, 78791, 79181, 79549, 79867, 80231, 80621,
	80923, 81239, 81637, 81971, 82301, 82651, 83063, 83423,
	83813, 84199, 84521, 84947, 85297, 85643, 86077, 86371,
	86767, 87151, 87523, 87811, 88259, 88721, 89041, 89393,
	89689, 90031, 90397, 90793, 91153, 91499, 91939, 92269,
	92623, 92899, 93257, 93607, 94009, 94399, 94771, 95101,
	95441, 95789, 96167, 96517, 96907, 97303, 97673, 98057
};

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

static void xuuid_to_path(uint64_t uuid, char** compl, char** fpath, char** fname)
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
(kfile_t* kf, kfile_create_opts2_t* opts)
{
	unsigned char zero_nonce[256];
	memset(zero_nonce, 0, 256);

	kf->prng = k_prng_init(PRNG_PLATFORM);
	if (!kf->prng)
		return -1;

	kf->digestbytes = kf->control.digest_bytes + 1;
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
	kf->iv_header.iv_bytes = kf->noncebytes-1;
	kf->kdf_header.kdf_salt_bytes = kf->control.digest_bytes;

	kf->kdf_header.kdf_salt = xcalloc(kf->kdf_header.kdf_salt_bytes+1,
		sizeof(unsigned char));

	kf->iv_header.iv = xcalloc(kf->iv_header.iv_bytes+1,
		sizeof(unsigned char));


	k_prng_update(kf->prng, kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1);
	while (!memcmp(kf->kdf_header.kdf_salt, zero_nonce, kf->kdf_header.kdf_salt_bytes+1)) {
		k_prng_update(kf->prng, kf->header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1);
	}

	kf->key = _k_key_derive_simple1024(opts->low_entropy_pass, kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1, primes_5_digit[opts->kdf_complexity]);
	if (!kf->key)
		pdie("KFILE _k_key_derive_simple1024()");

	k_prng_update(kf->prng, kf->iv_header.iv, kf->iv_header.iv_bytes+1);
	while (!memcmp(kf->header.iv, zero_nonce, kf->iv_header.iv_bytes+1)) {
		k_prng_update(kf->prng, kf->header.iv, kf->iv_header.iv_bytes+1);
	}

	if (k_sc_set_key(kf->scipher, kf->header.iv, kf->key, opts->key_bytes * 8))
		die("KFILE unable to set stream cipher key");

	return 0;
}

static inline int check_create_opts(kfile_create_opts2_t* opts)
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

kfile_write_fd_t kfile_create2(kfile_create_opts2_t* opts)
{
	kfile_t* kf = 0;

	if (check_create_opts(opts))
		goto err;


	kf = xcalloc(1, sizeof(kfile_t));
	kf->iobuf_size = opts->iobuf_size;
	kf->iobuf = xmalloc(opts->iobuf_size);

	strcpy(kf->preamble.magic, KFILE_MAGIC);
	strcpy(kf->preamble.version, kfile_version_strings[opts->version]);

	kf->control.hash_function = opts->hash_function;
	kf->control.cipher_function = opts->cipher_function;
	kf->control.cipher_mode = opts->cipher_mode;
	kf->control.kdf_function = opts->kdf_function;
	kf->control.kdf_complexity = opts->kdf_complexity;

	assign_uint8_size(&kf->control.digest_bytes, opts->digest_bytes);
	assign_uint8_size(&kf->control.key_bytes, opts->key_bytes);


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

	if (xwrite(kf->fd, &kf->preamble, sizeof(kfile_preamble_t)))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->control, sizeof(kfile_control_header_t)))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->kdf_header.kdf_salt_bytes, 1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, kf->kdf_header.kdf_salt, kf->kdf_header.kdf_salt_bytes+1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, &kf->iv_header.iv_bytes, 1))
		pdie("KFILE can't write file header");

	if (xwrite(kf->fd, kf->iv_header.iv, kf->iv_header.iv_bytes+1))
		pdie("KFILE can't write file header");

	_kfile_calculate_header_digest(kf);

	/* header and terminating cipherdigest, kfile_update()'s
	 * increment filesize implicitly */
//	kf->header.filesize = sizeof(kfile_header_t) + kf->digestbytes;

#if 1
	if (kfile_update(kf->fd, kf->headerdigest, kf->digestbytes) < 0)
		pdie("KFILE kfile_update(kf->headerdigest)");

	if (kfile_update(kf->fd, &kf->resourcename_len, 1) < 0)
		pdie("KFILE kfile_update(kf->resourcename_len)");

	if (kfile_update(kf->fd, opts->resource_name, kf->resourcename_len) < 0)
		pdie("KFILE kfile_update(opts->resourcename)");
#endif

	return kf->fd;
err:
	if (kf) {
		if (kf->iobuf)
			free(kf->iobuf);
		free(kf);
	}
	return -1;
}
