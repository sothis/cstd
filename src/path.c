#include "cstd.h"

/* returns absolute path without symbolic links or NULL if the
 * specified entity doesn't exist */
char* path_resolve(char* path, const char* subtree)
{
	if (subtree) {
		path = str_append(path, subtree);
	}
	return xrealpath(path, 1);
}

char* path_resolve_const(const char* path)
{
	return xrealpath((char*)path, 0);
}
