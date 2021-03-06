#include "cstd.h"
#include "kfile.h"

#include <stdio.h>
#include <string.h>

#include <socket/sio.h>

int main(int argc, char* argv[], char* envp[])
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
	unsigned char sdata[35191];
	kfile_write_fd_t wfd;
	kfile_create_opts_t kfcopts = {
		.uuid			= 18446744073709551615ul,
		.file_mode		= 0400,
		.layout			= KFILE_LAYOUT_UUID_UINT64,
		.version		= KFILE_VERSION_0_1,
		.hash_function		= HASHSUM_SKEIN_1024,
		.digest_bytes		= 128,
		.cipher_function	= BLK_CIPHER_THREEFISH_1024,
		.cipher_mode		= BLK_CIPHER_MODE_CTR,
		.key_bytes		= 128,
		.kdf_function		= KDF_SKEIN_1024,
		.kdf_complexity		= 23,
		.iobuf_size		= 65536,
		.resource_name		= { "some_document.pdf" },
		.low_entropy_pass	= { "test1234" }
	};

	memset(sdata, '-', 35191);
	sdata[35190] = 0;
	wfd = kfile_create(&kfcopts);
	if (wfd < 0)
		pdie("kfile_create()");
	kfile_update(wfd, sdata, sizeof(sdata));
	kfile_write_digests_and_close(wfd);
#endif

#if 1
	unsigned char rdata[35191];
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
	kfile_read(rfd, rdata, 35191);
	printf("resource: '%s'\n" , kfile_get_resource_name(rfd));
	printf("content: '%s'\n", rdata);
	kfile_close(rfd);
#endif
//	printf("s: '%lu'\n", sizeof(kfile_kdf_header_t));
	return 0;
#endif


	int sock;

	if (argc != 2)
		return -1;

	tcp_sock_opt_t sopt = {
		.interface	= argv[1],
		.port		= 1337,
		.non_blocking	= 0,
		.reuse_address	= 1,
		.keep_alive	= 1,
	};

	sock = sio_new_tcp_listening_socket(&sopt);
	printf("sock: %d\n", sock);
	getchar();

	return 0;
}
