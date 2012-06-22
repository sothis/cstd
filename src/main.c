#include "cstd.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[], char* envp[])
{
	int e;
	proc_t p = {
		.argv	= (char*[]){
			"ls",
			"-la",
			NULL,
		},
		.envp	= envp,
		.umask	= 077,
		.wd	= "/",
		.stdin	= STDIN_FILENO,
		.stdout	= STDOUT_FILENO,
		.stderr	= STDERR_FILENO,
	};

	cstd_eprint_version();

	e = proc_fork_and_wait(&p, 1);
	printf("exit code: %d\n", e);
#if 0
	char* s;
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
#endif
	return 0;
}
