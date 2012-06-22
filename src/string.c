#include "cstd.h"

#include <string.h>

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
