#include "cstd.h"

#include <string.h>
#include <stdlib.h>

char* str_append(char* string1, const char* string2)
{
	size_t l1;
	size_t l2;
	size_t l;

	if (!string2)
		return string1;

	l1 = (string1) ? strlen(string1) : 0;
	l2 = strlen(string2);
	l = l1 + l2;

	string1 = xrealloc(string1, l+1);
	if (!l1)
		string1[0] = 0;
	strcat(string1, string2);
	return string1;
}

char* str_prepend(char* string1, const char* string2)
{
	size_t l1;
	size_t l2;
	size_t l;

	if (!string2)
		return string1;

	l1 =  string1 ? strlen(string1) : 0;
	l2 = strlen(string2);
	l = l1 + l2;

	string1 = xrealloc(string1, l+1);
	if (!l1)
		string1[0] = 0;
	memmove(string1+l2, string1, l1);
	memcpy(string1, string2, l2);
	string1[l] = 0;
	return string1;
}

static int str_buffered_grow(buffered_string_t* str)
{
	char* t;

	str->allocated += str->threshold;
	t = realloc(str->mem, str->allocated);
	if (!t) {
		free(str->mem);
		return -1;
	}

	memset(t+(str->allocated-str->threshold), 0, str->threshold);
	str->mem = t;
	return 0;
}

int str_buffered_init(buffered_string_t* str, size_t alloc_threshold)
{
	if (!alloc_threshold || !str)
		return -1;

	memset(str, 0, sizeof(buffered_string_t));
	str->threshold = alloc_threshold;

	return str_buffered_grow(str);
}

int str_buffered_append_byte(buffered_string_t* str, char byte)
{
	size_t l;

	if (!byte) {
		free(str->mem);
		return -1;
	}

	l = str->length;
	if (l == (str->allocated-1)) {
		if (str_buffered_grow(str))
			return -1;
	}
	str->mem[l] = byte;
	str->length++;
	return 0;
}

char* str_buffered_finalize(buffered_string_t* str)
{
	str->mem[str->length] = 0;
	return str->mem;
}
