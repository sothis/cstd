#include "cstd.h"

#include <stdlib.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

void die(char* format, ...)
{
	va_list varargs;

	va_start(varargs, format);
	eprintf(LOG_CRIT, format, varargs);
	va_end(varargs);
	eprintf(LOG_CRIT, "terminating due to previous error\n");
	exit(~0);
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
		die("malloc(): %s\n", strerror(errno));
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
		die("calloc(): %s\n", strerror(errno));
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
		die("realloc(): %s\n", strerror(errno));
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
		die("realpath(): %s (errno %d)\n", strerror(errno), errno);
	}
	if (free_path_afterwards)
		free(path);
	return p;
}
