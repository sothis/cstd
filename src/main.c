#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <string.h>


int main(int argc, char* argv[], char* envp[])
{
	file_create("test", 0, 00644);
	return 0;
}
