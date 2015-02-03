#include "cstd.h"
#include "kfile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/stat.h>

int mkdirp(const char* path)
{
	char* cwd = 0;
	char* p, *tok;
	int e;

	if (!path || !strlen(path))
		return -1;

	cwd = get_current_dir_name();
	if (!cwd)
		pdie("couldn't get current working directory");

	p = xstrdup(path);

	tok = strtok(p, "/");

	while (tok) {
		e = mkdir(tok, 0755);
		if (e && (errno != EEXIST)) {
			free(p);
			chdir(cwd), free(cwd);
			return -1;
		}
		if (chdir(tok)) {
			free(p);
			chdir(cwd), free(cwd);
			return -1;
		}
		tok = strtok(0, "/");
	}
	free(p);
	chdir(cwd), free(cwd);
	return 0;
}

int mkpath(uint64_t uuid)
{
	int i, j, fd = -1;
	char uuid_ascii[20];
	char cpath[40];
	char path[20];
	char fname[5];

	memset(fname, 0, 5);
	memset(path, 0, 20);
	memset(cpath, 0, 40);
	memset(uuid_ascii, 0, 20);
	snprintf(uuid_ascii, 21, "%020" PRIu64 "", uuid);

	for (j = 0, i = 0; i <= 16; i += 4, j += 5) {
		if (i < 16) {
			path[j] = uuid_ascii[i];
			path[j+1] = uuid_ascii[i+1];
			path[j+2] = uuid_ascii[i+2];
			path[j+3] = uuid_ascii[i+3];
			if (i < 12)
				path[j+4] = '/';
		} else {
			fname[0] = uuid_ascii[i];
			fname[1] = uuid_ascii[i+1];
			fname[2] = uuid_ascii[i+2];
			fname[3] = uuid_ascii[i+3];
		}

		cpath[j] = uuid_ascii[i];
		cpath[j+1] = uuid_ascii[i+1];
		cpath[j+2] = uuid_ascii[i+2];
		cpath[j+3] = uuid_ascii[i+3];
		if (i < 16)
			cpath[j+4] = '/';
	}

	if (mkdirp(path))
		return -1;

	fd = open(fname, O_RDWR | O_CREAT | O_EXCL);

	return fd;
}

int kfile_create(uint64_t uuid, const char* pass)
{
	int fd;

	fd = mkpath(uuid);
	if (fd < 0) {
		pdie("error creating file");
	}
	close(fd);
	return 0;
}
