#include "cstd.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

int main(int argc, char* argv[], char* envp[])
{
	char* s;

	cstd_eprint_version();

	s = xmalloc(2);
	strcpy(s, "s");
	s = path_resolve(s, 0);
	printf("str1: '%s'\n", s);
	free(s);

	if (argc == 2) {
		s = path_resolve_const(argv[1]);
		printf("str2: '%s'\n", s);
		free(s);
	}

	return 0;
}

