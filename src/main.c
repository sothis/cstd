#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

sdtl_parser_t p;
sdtl_factory_t f;

int write_sdtl_data(sdtl_factory_t* f, unsigned char* data, size_t len)
{
	size_t i = 0;
	for (i = 0; i < len; ++i)
		printf("%c", data[i]);

	if (sdtl_add_input_data(&p, data, len)) {
		sdtl_free(&p);
		die("parser error\n");
	}
	return 0;
}

int main(int argc, char* argv[], char* envp[])
{
#if 1
	sdtl_init(&p);
	sdtl_factory_init(&f, &write_sdtl_data);

	sdtl_factory_add_string(&f, "value0", "Hello\\, \"world\"!");
	sdtl_factory_add_num(&f, "value1", 0);
	sdtl_factory_add_num(&f, "value2", "35218.1535");
	sdtl_factory_add_string(&f, "value3", "");
	sdtl_factory_start_struct(&f, "section");
	sdtl_factory_add_string(&f, "x", "test");
	sdtl_factory_add_num(&f, "y", "6");
	sdtl_factory_end_struct(&f);

	sdtl_factory_flush(&f);
	printf("\n\nparsed output:\n");
	print_entities(&p, 1);

	sdtl_free(&p);
	return 0;
#endif
#if 0
	int fd;
	ssize_t r;

	unsigned char buf[4096];

	if (argc < 2) {
		die("expected filename as commandline argument\n");
	}

	sdtl_init(&p);
	fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		pdie("open() '%s'", argv[1]);
	}

	while ((r = read(fd, buf, 4096)) > 0) {
		if (sdtl_add_input_data(&p, buf, r)) {
			sdtl_free(&p);
			die("parser error\n");
		}
	}
	if (r < 0) {
		pdie("read() from '%s'", argv[1]);
	}
	close(fd);


#if 0
	print_entities(&p, 1);
#endif
#if 0
	printf("\nvalid SDTL stream without whitespace:\n");
	print_entities(&p, 0);
	printf("\n\n");
#endif

	if (argc == 3) {
		entity_t* e;
		e = sdtl_get_entity_abs(&p, argv[2]);
		if (!e)
			die("component not found.\n");

		switch (e->type) {
			case entity_is_struct:
				printf("%s: is structure\n",
					*e->name ? e->name : "<root>");
				break;
			case entity_is_string:
			case entity_is_null:
			case entity_is_numeric:
				printf("%s: '%s'\n", argv[2], e->data);
				break;
			default:
				die("unknown entity type.\n");
		}
	}


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
