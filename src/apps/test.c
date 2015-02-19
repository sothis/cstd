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
	int fd;

	kfile_opts_t kfopts = {
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
		.filename		= { "some_document.pdf" },
		.low_entropy_pass	= { "test1234" }
	};

	fd = kfile_create(&kfopts);

	kfile_write(fd, "hello", 5);

	kfile_close(fd);
	return 0;
}
