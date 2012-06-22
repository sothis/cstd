#include "cstd.h"

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

void die(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	veprintf(LOG_CRIT, format, varargs);
	va_end(varargs);
	eprintf(LOG_CRIT, "terminating due to previous error\n");
	_exit(~0);
}

void pdie(char* format, ...)
{
	va_list varargs;
	char buf[64];
	int e;
	char* se;

	e = errno;
	se = 0;

	if (e != 0) {
		sprintf(buf, " (errno %d)\n", e);

		se = str_prepend(se, ": ");
		if (e > 0)
			se = str_append(se, strerror(e));
		se = str_append(se, buf);
	}
	format = str_prepend(se, format);

	va_start(varargs, format);
	veprintf(LOG_CRIT, format, varargs);
	va_end(varargs);
	free(format);
	eprintf(LOG_CRIT, "terminating due to previous error\n");
	_exit(~0);
}

const char* xstrerror(void)
{
	int e = errno;

	if (e < 0) {
		die("strerror(): negative errno given (%d)\n", e);
	}
	return strerror(e);
}

void* xmalloc(size_t size)
{
	void* m;

	if (!size) {
		die("bug: tried to allocate 0 bytes\n");
	}
	m = malloc(size);
	if (!m) {
		errno = ENOMEM;
		pdie("malloc()");
	}
	return m;
}

void* xcalloc(size_t member, size_t size)
{
	void* m;

	if (!member || !size) {
		die("bug: tried to allocate 0 bytes\n");
	}
	m = calloc(member, size);
	if (!m) {
		errno = ENOMEM;
		pdie("calloc()");
	}
	return m;
}

void* xrealloc(void* ptr, size_t size)
{
	void* m;

	if (!ptr && !size) {
		die("bug: tried to allocate 0 bytes\n");
	}
	m = realloc(ptr, size);
	if (!m && size) {
		errno = ENOMEM;
		pdie("realloc()");
	}
	if (m && !size) {
		free(m);
		m = 0;
	}
	return m;
}

char* xstrdup(const char* string)
{
	char* s;
	size_t l;

	if (!string) {
		die("bug: tried to duplicate an unallocated string\n");
	}
	l = strlen(string);
	s = xmalloc(l+1);
	strcpy(s, string);
	return s;
}

char* xrealpath(char* path, int free_path_afterwards)
{
	char* p;

	p = realpath(path, 0);
	if (!p && (errno != ENOENT)) {
		pdie("realpath()");
	}
	if (free_path_afterwards)
		free(path);
	return p;
}
