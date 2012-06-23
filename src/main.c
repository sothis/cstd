#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[], char* envp[])
{
#if 1
	int fd;
	ssize_t r;
	sdtl_parser_t p;
	unsigned char buf[4096];

	if (argc != 2) {
		die("expected filename as commandline argument\n");
	}

	sdtl_init(&p);
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		pdie("open() '%s'", argv[1]);
	}

	while ((r = read(fd, buf, 4096)) > 0) {
		if (sdtl_add_input_data(&p, buf, r)) {
			die("parser error\n");
		}
	}
	if (r < 0) {
		pdie("read() from '%s'", argv[1]);
	}
	close(fd);

	print_entities(&p);
	sdtl_free(&p);

	return 0;
#endif
#if 0
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
	die("exit code: %d\n", e);
	return 0;
#endif
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
	return 0;
#endif
}
