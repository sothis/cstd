#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>


int main(int argc, char* argv[], char* envp[])
{
	int fd0, fd1, fd2, fd3;

	fd0 = file_create("testfile0", 0, 00644);
	write(fd0, "hello0\n", 7);

	fd1 = file_create("testfile1", 0, 00644);
	write(fd1, "hello1\n", 7);

	fd2 = file_create("testfile2", 0, 00644);
	write(fd2, "hello2\n", 7);

	fd3 = file_create("testfile3", 0, 00644);
	write(fd3, "hello3\n", 7);


	file_sync_and_close(fd2);
	file_sync_and_close(fd0);
	file_sync_and_close(fd3);
	file_sync_and_close(fd1);


	return 0;
}
