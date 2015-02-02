#include "cstd.h"
#include "kfile.h"

int mkdirp(const char* path)
{
	char* p, *tok;
	int e;

	if (!path || !strlen(path))
		return -1;

	p = xstrdup(path);

	tok = strtok(p, "/");

	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			free(p);
			return -1;
		}
		if (chdir(tok)) {
			free(p);
			return -1;
		}
		tok = strtok(0, "/");
	}
	free(p);
	return 0;
}

int mkpath(uint64_t uuid)
{
	int i, j;
	char numeric[16];
	char path[20];

	if (uuid > 999999999999999ul)
		return -1;

	snprintf(numeric, 16, "%015" PRIu64 "", uuid);

	for (j = 0, i = 0; i < 14; i += 3, j += 4) {
		path[j] = numeric[i];
		path[j+1] = numeric[i+1];
		path[j+2] = numeric[i+2];
		if (j < 16)
			path[j+3] = '/';
	}

	if (mkdirp(path))
		return -1;

	return 0;
}

int kfile_create(uint64_t uuid, const char* pass)
{

	return 0;
}
