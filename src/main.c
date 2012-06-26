#include "cstd.h"

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>

#if 0
sdtl_parser_t p;
sdtl_factory_t fac;
uint64_t total_bytes = 0;

static int
new_sdtl_stream_data(sdtl_factory_t* f, unsigned char* data, size_t len)
{
#if 0
	size_t i = 0;
	for (i = 0; i < len; ++i)
		printf("%c", data[i]);
#endif
	total_bytes += len;
	if (sdtl_parser_add_data(&p, data, len)) {
		return -1;
	}
	return 0;
}
#endif

#include <string.h>

int main(int argc, char* argv[], char* envp[])
{
#if 1
	sdtl_parser_t p;

	if (argc != 2)
		return -1;

	if (sdtl_parser_init_and_parse_file(&p, argv[1])) {
		printf("malformed sdtl file\n");
		return -1;
	}

	const char* port = sdtl_parser_get_data(&p, ".network.port");
	const char* ifce = sdtl_parser_get_data(&p, ".network.bind-to");
	if (!port || !ifce) {
		printf("invalid configuration file\n");
	} else
		printf("bind to: %s:%s\n", ifce, port);

	sdtl_parser_free(&p);

	return 0;
#endif
#if 0
	int r;

	if (argc != 2)
		return -1;

	r = fs_delete_deep(argv[1]);
	if (r)
		pdie("fs_delete_deep() on %s", argv[1]);

	return 0;
#endif
#if 0
	buffered_string_t s;
	char* m;

	str_buffered_init(&s, 4096);
	str_buffered_append_byte(&s, '1');
	str_buffered_append_byte(&s, '2');
	m = str_buffered_finalize(&s);

	printf("m: '%s' (%lu/%lu)\n", m, strlen(m), s.length);
	return 0;
#endif
#if 0
	sdtl_factory_init(&fac, &new_sdtl_stream_data);

	sdtl_parser_init(&p);

	size_t i;

	for (i = 0; i < 71580; ++i) {
	//while (1) {
		if (sdtl_factory_start_struct(&fac, "main"))
			goto err_out;
		if (sdtl_factory_add_num(&fac, "main", "42"))
			goto err_out;
		if (sdtl_factory_end_struct(&fac))
			goto err_out;
		if (sdtl_factory_add_string(&fac, "value0", "Hello\\, \"world\"!"))
			goto err_out;
		if (sdtl_factory_start_struct(&fac, "empty_struct"))
			goto err_out;
		if (sdtl_factory_end_struct(&fac))
			goto err_out;
		if (sdtl_factory_add_num(&fac, "value1", 0))
			goto err_out;
		if (sdtl_factory_add_num(&fac, "value2", "35218.1535"))
			goto err_out;
		if (sdtl_factory_add_string(&fac, "value3", ""))
			goto err_out;
		if (sdtl_factory_start_struct(&fac, "section"))
			goto err_out;
		if (sdtl_factory_add_string(&fac, "x", "test"))
			goto err_out;
		if (sdtl_factory_start_struct(&fac, "subsection"))
			goto err_out;
		if (sdtl_factory_add_num(&fac, "z", "12"))
			goto err_out;
		if (sdtl_factory_end_struct(&fac))
			goto err_out;
		if (sdtl_factory_add_num(&fac, "y", "6"))
			goto err_out;
		if (sdtl_factory_end_struct(&fac))
			goto err_out;

		if (sdtl_factory_flush(&fac)) {
			goto err_out;
		}

	#if 0
		printf("\nparsed output:\n");
		sdtl_parser_print(&p, 1);
	#endif
		if (sdtl_parser_reset(&p))
			goto err_out;
	}
#if 0
	if (argc == 3) {
		const char* data;
		data = sdtl_parser_get_data(&p, argv[2]);
		if (!data)
			die("component not found, or data not set\n");
		printf("%s: '%s'\n", argv[2], data);
	}
#endif

	printf("processed: %" PRIu64 " bytes\n", total_bytes);
	sdtl_parser_free(&p);
	return 0;

err_out:
	sdtl_parser_free(&p);
	die("parser error");
	return -1;
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
