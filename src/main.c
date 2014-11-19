#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>


int main(int argc, char* argv[], char* envp[])
{
	int fd = -1;

	fd = file_create("testfile", 0, 00644);
	if (fd < 0)
		pdie("file_create()");
	if (write(fd, "hello\n", 6) != 6)
		pdie("write()");
	if (file_sync_and_close(fd))
		pdie("file_sync_and_close()");

	return 0;
}
