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
	kfile_write_fd_t wfd;
	kfile_create_opts_t kfcopts = {
		.uuid			= 18446744073709551615ul,
		.filemode		= 0400,
		.version		= KFILE_VERSION_0_1,
		.hashfunction		= HASHSUM_SKEIN_512,
		.hashsize		= 512,
		.cipher			= BLK_CIPHER_AES,
		.ciphermode		= BLK_CIPHER_MODE_CTR,
		.keysize		= 256,
		.kdf_iterations		= 11027,
		.iobuf_size		= 65536,
		.resourcename		= { "some_document.pdf" },
		.low_entropy_pass	= { "test1234" }
	};

	wfd = kfile_create(&kfcopts);
	kfile_update(wfd, "hello ", 6);
	kfile_update(wfd, "world", 6);
	kfile_final(wfd);
	//kfile_close(wfd); /* kfile_final now closes implicitly the fd */

	kfile_read_fd_t rfd;
	char buf[32] = {0};

	kfile_open_opts_t kfoopts = {
		.uuid			= 18446744073709551615ul,
		.iobuf_size		= 65536,
		.low_entropy_pass	= { "test1234" }
	};

#if 1
	rfd = kfile_open(&kfoopts);
	if (rfd < 0)
		pdie("kfile_open()");
	kfile_read(rfd, buf, 13);

	printf("resource: '%s'\n" , kfile_get_resource_name(rfd));
	printf("content: '%s'\n", buf);

	kfile_close(rfd);
#endif
#endif
	return 0;
}
