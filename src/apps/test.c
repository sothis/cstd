#include "cstd.h"
#include "kfile.h"

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

	uint64_t uuid = 18446744073709551615ul;
	int fd;

	//for(uuid = 0; uuid < 10000; uuid++)
	//	kfile_create(uuid, 0);

	fd = kfile_create(uuid, 0);

	/* do stuff */

	kfile_close(fd);

	return 0;
}
