#include "cstd.h"
#include "kfile.h"

#include <stdio.h>
#include <string.h>

int cstd_main(int argc, char* argv[], char* envp[])
{
#if 0
	int fd0, fd1, fd2, fd3;

	fd0 = file_create_rw_with_hidden_tmp("testfile0", 0, 00644);
	write(fd0, "hello0\n", 7);

	fd1 = file_create_rw_with_hidden_tmp("testfile1", 0, 00644);
	write(fd1, "hello1\n", 7);

	fd2 = file_create_rw_with_hidden_tmp("testfile2", 0, 00644);
	write(fd2, "hello2\n", 7);

	fd3 = file_create_rw_with_hidden_tmp("testfile3", 0, 00644);
	write(fd3, "hello3\n", 7);


	file_sync_and_close_all();
#endif
#if 1

#if 1
	unsigned char sdata[4096];
	kfile_write_fd_t wfd;
	kfile_create_opts_t kfcopts = {
		.uuid			= 18446744073709551615ul,
		.file_mode		= 0400,
		.layout			= KFILE_LAYOUT_UUID_UINT64,
		.version		= KFILE_VERSION_0_1,
		.hash_function		= HASHSUM_SKEIN_512,
		.digest_bytes		= 64,
		.cipher_function	= BLK_CIPHER_AES,
		.cipher_mode		= BLK_CIPHER_MODE_CTR,
		.key_bytes		= 32,
		.kdf_function		= KDF_SKEIN_1024,
		.kdf_complexity		= 23,
		.iobuf_size		= 65536,
		.resource_name		= { "some_document.pdf" },
		.low_entropy_pass	= { "test1234" }
	};

	memset(sdata, 'z', 4096);
	sdata[4095] = 0;
	wfd = kfile_create(&kfcopts);
	if (wfd < 0)
		pdie("kfile_create()");
	kfile_update(wfd, sdata, sizeof(sdata));
	kfile_write_digests_and_close(wfd);
#endif

#if 1
	unsigned char rdata[4096];
	kfile_read_fd_t rfd;
	kfile_open_opts_t kfoopts = {
		.layout			= KFILE_LAYOUT_UUID_UINT64,
		.uuid			= 18446744073709551615ul,
		.iobuf_size		= 65536,
		.check_cipherdigest	= 1,
		.low_entropy_pass	= { "test1234" }
	};

	rfd = kfile_open(&kfoopts);
	if (rfd < 0)
		pdie("kfile_open()");
	kfile_read(rfd, rdata, 4096);
	printf("resource: '%s'\n" , kfile_get_resource_name(rfd));
	printf("content: '%s'\n", rdata);
	kfile_close(rfd);
#endif
//	printf("s: '%lu'\n", sizeof(kfile_kdf_header_t));
#endif
	return 0;
}
